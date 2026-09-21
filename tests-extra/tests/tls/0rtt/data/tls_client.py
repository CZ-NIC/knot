#!/usr/bin/env python3

# pip install dnspython

import argparse
import asyncio
import os
import struct
import tempfile

import dns.message


READ_TIMEOUT = 10
TICKET_WAIT = 1.0


def make_dns_request(qname, qtype):
    qtype = dns.rdatatype.from_text(qtype)
    query = dns.message.make_query(qname, qtype)
    dns_message = query.to_wire()

    # DNS-over-TLS:
    #   2-byte message length
    #   DNS message
    data = struct.pack("!H", len(dns_message))
    data += dns_message

    return data


async def start_openssl(server, port, sni=None, session_in=None, session_out=None,
                        early_data=None):
    command = ["openssl", "s_client", "-connect", f"{server}:{port}", "-tls1_3",
               "-ign_eof", "-state", "-brief", "-quiet", "-noservername"]

    if sni:
        command += ["-verify_hostname", sni]

    if session_in is not None:
        command += ["-sess_in", session_in]

    if session_out is not None:
        command += ["-sess_out", session_out]

    if early_data is not None:
        command += ["-early_data", early_data]

    print("")
    print("[DEBUG] OpenSSL command:" + " ".join(command))
    print("")

    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    return process


async def read_dns_response(process):
    """
    Read exactly one DNS-over-TLS response.

    DoT keeps the TLS connection open, so we must NOT wait for EOF.
    """

    try:
        header = await asyncio.wait_for(
            process.stdout.readexactly(2),
            timeout=READ_TIMEOUT,
        )
    except asyncio.TimeoutError:
        raise RuntimeError(
            "Timed out waiting for the 2-byte DNS-over-TLS response header"
        )

    length = struct.unpack("!H", header)[0]

    if length == 0:
        raise RuntimeError(
            "Server returned a zero-length DNS-over-TLS message"
        )

    try:
        data = await asyncio.wait_for(
            process.stdout.readexactly(length),
            timeout=READ_TIMEOUT,
        )
    except asyncio.TimeoutError:
        raise RuntimeError(
            f"Timed out waiting for {length} bytes of DNS response"
        )

    try:
        return dns.message.from_wire(data)
    except Exception as exc:
        raise RuntimeError(
            f"Received invalid DNS message: {exc}"
        ) from exc


async def drain_stderr(process):
    """
    Read stderr without blocking the DNS response path.
    """

    try:
        return await asyncio.wait_for(
            process.stderr.read(),
            timeout=2,
        )
    except asyncio.TimeoutError:
        return b""


async def terminate_process(process):
    """
    Terminate s_client cleanly, with a kill fallback.
    """

    if process.returncode is not None:
        return

    process.terminate()

    try:
        await asyncio.wait_for(
            process.wait(),
            timeout=2,
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()


def detect_session_resumption(text):
    if "TLSv1.3 early data" in text:
        return True

    if "SSLv3/TLS read server certificate" in text and \
       "TLSv1.3 read server certificate verify" in text:
        return False

    return None


def detect_early_data(text):
    if "write end of early data" in text and \
       "SSLv3/TLS write finished" in text:
        return True
    else:
        return False


def print_tls_result(session_resumed, early_data_accepted):
    if session_resumed is True:
        print("[+] TLS SESSION RESUMPTION: YES")
    elif session_resumed is False:
        print("[!] TLS SESSION RESUMPTION: NO")
    else:
        print("[!] TLS session resumption status unavailable")

    if early_data_accepted is True:
        print("[+] 0-RTT ACCEPTED")
    elif session_resumed and early_data_accepted is False:
        print("[!] 0-RTT REJECTED")


def session_file_is_valid(filename):
    if not filename:
        return False

    if not os.path.isfile(filename):
        return False

    try:
        return os.path.getsize(filename) > 0
    except OSError:
        return False


async def do_query(server, port, sni, qname, qtype, ticket_file=None):
    print()
    print("=" * 60)
    print("DNS-OVER-TLS CONNECTION")
    print("=" * 60)

    print(f"Server IP   : {server}")
    print(f"Server port : {port}")

    if sni:
        print(f"TLS SNI    : {sni}")
        print("TLS verify  : enabled")
    else:
        print("TLS SNI     : none")
        print("TLS verify  : disabled")

    print(f"DNS query   : {qname} {qtype}")
    print("")

    ticket = None
    if ticket_file:
        ticket = session_file_is_valid(ticket_file)

        if ticket:
            print("[+] Session ticket available")
            print("[+] Will attempt TLS session resumption / 0-RTT")
        else:
            print("[+] No usable session ticket")
            print("[+] Will perform a normal TLS handshake")
    else:
        print("[+] No session ticket specified")
        print("[+] Will perform a normal TLS handshake")

    if ticket:
        print()
        print("[+] Starting resumed TLS connection...")
        print("[+] 0-RTT may be used")
    else:
        print()
        print("[+] Starting normal TLS connection...")

    request = make_dns_request(qname, qtype)

    early_data_file = None
    if ticket:
        fd, early_data_file = tempfile.mkstemp(
            prefix="tls13-0rtt-",
            suffix=".data",
        )
        os.close(fd)

        try:
            with open(early_data_file, "wb") as f:
                f.write(request)
        except Exception:
            try:
                os.unlink(early_data_file)
            except OSError:
                pass
            raise

    session_in = ticket_file if ticket else None
    session_out = ticket_file
    process = await start_openssl(
        server=server,
        port=port,
        sni=sni,
        session_in=session_in,
        session_out=session_out,
        early_data=early_data_file,
    )

    if ticket:
        print("[+] Sending DNS query as early as possible...")

    response = None
    stderr = b""

    try:
        if not ticket:
            # Normal TLS application data.
            process.stdin.write(request)
            await process.stdin.drain()

        # With -early_data, OpenSSL itself sends the DNS request.
        #
        # In both cases, read exactly one DNS-over-TLS response.
        response = await read_dns_response(process)

        if ticket_file:
            # TLS 1.3 NewSessionTicket messages are post-handshake.
            #
            # Give OpenSSL/server a short opportunity to deliver the
            # session before terminating s_client.
            await asyncio.sleep(TICKET_WAIT)

    finally:
        stderr_task = asyncio.create_task(
            drain_stderr(process)
        )

        await terminate_process(process)

        stderr = await stderr_task

    tls_text = stderr.decode(
        errors="replace"
    )

    session_resumed = detect_session_resumption(tls_text)

    if ticket:
        early_data_accepted = detect_early_data(tls_text)
    else:
        early_data_accepted = None

    # ------------------------------------------------------------
    # Print handshake progress messages
    # ------------------------------------------------------------

    print()
    print("[+] TLS handshake completed")
    print(f"[+] Session resumed: {session_resumed is True}")


    # ------------------------------------------------------------
    # TLS session ticket
    # ------------------------------------------------------------

    if session_out is not None:
        if not os.path.exists(session_out):
            raise RuntimeError(
                "OpenSSL did not create the TLS session file."
            )

        size = os.path.getsize(session_out)

        if size == 0:
            raise RuntimeError(
                "OpenSSL created an empty TLS session file."
            )

        print()
        print("[+] Received TLS session ticket")
        print(f"[+] Saved TLS session ticket to {session_out}")

    # ------------------------------------------------------------
    # Canonical TLS output
    # ------------------------------------------------------------

    print_tls_result(
        session_resumed=session_resumed,
        early_data_accepted=early_data_accepted,
    )

    if early_data_file is not None:
        try:
            os.unlink(early_data_file)
        except OSError:
            pass

    # ------------------------------------------------------------
    # DNS response
    # ------------------------------------------------------------

    if response is None:
        raise RuntimeError(
            "No DNS response was received."
        )

    print()
    print("DNS RESPONSE")
    print("-" * 60)
    print(response)

    print()
    print("[+] Connection closed")


async def main(args):
    await do_query(
        server=args.server,
        port=args.port,
        sni=args.sni,
        qname=args.qname,
        qtype=args.qtype,
        ticket_file=args.ticket,
    )


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "Universal DNS-over-TLS client with optional "
            "TLS session resumption and 0-RTT."
        )
    )

    parser.add_argument(
        "server",
        help="IP address or hostname of the DNS-over-TLS server",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=853,
        help="DNS-over-TLS port (default: 853)",
    )

    parser.add_argument(
        "--sni",
        help=(
            "TLS SNI / certificate hostname. "
            "If specified, TLS certificate verification is enabled."
        ),
    )

    parser.add_argument(
        "--qname",
        default="example.com",
        help="DNS name to query (default: example.com)",
    )

    parser.add_argument(
        "--qtype",
        default="A",
        help=(
            "DNS query type, e.g. A, AAAA, MX, TXT "
            "(default: A)"
        ),
    )

    parser.add_argument(
        "--ticket",
        metavar="FILE",
        help=(
            "TLS session ticket file. If it exists, attempt session reumption "
            "and 0-RTT. A newly received ticket is saved to this file."
        ),
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    try:
        asyncio.run(main(args))

    except KeyboardInterrupt:
        print()
        print("[!] Interrupted")

    except Exception as exc:
        print()
        print(f"[!] ERROR: {exc}")
        raise
