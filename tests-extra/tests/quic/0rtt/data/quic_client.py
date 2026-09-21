#!/usr/bin/env python3

# python3 -m venv venv
# source venv/bin/activate
# pip install aioquic dnspython

import argparse
import asyncio
import os
import pickle
import struct

import dns.message
import dns.rdatatype

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, QuicEvent, StreamDataReceived


class DoQClientProtocol(QuicConnectionProtocol):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.responses = {}
        self.handshake_completed = asyncio.Event()

        self.early_data_accepted = None
        self.session_resumed = None

    async def wait_for_handshake(self):
        await self.handshake_completed.wait()

    async def query(self, qname, qtype):
        qtype = dns.rdatatype.from_text(qtype)
        query = dns.message.make_query(qname, qtype)
        dns_message = query.to_wire()

        # DNS-over-QUIC:
        #   2-byte message length
        #   DNS message
        data = struct.pack("!H", len(dns_message))
        data += dns_message

        stream_id = self._quic.get_next_available_stream_id()

        loop = asyncio.get_running_loop()
        future = loop.create_future()

        self.responses[stream_id] = {
            "future": future,
            "data": bytearray(),
        }

        print(f"[+] Sending query on QUIC stream {stream_id}")

        self._quic.send_stream_data(stream_id, data, end_stream=True)

        self.transmit()

        return await future

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, HandshakeCompleted):
            self.early_data_accepted = event.early_data_accepted
            self.session_resumed = event.session_resumed

            print()
            print("[+] TLS handshake completed")
            print(f"[+] Session resumed: {event.session_resumed}")

            self.handshake_completed.set()
            return

        if not isinstance(event, StreamDataReceived):
            return

        state = self.responses.get(event.stream_id)

        if state is None:
            return

        state["data"].extend(event.data)
        data = state["data"]

        # Need the 2-byte DNS message length.
        if len(data) < 2:
            return

        message_length = struct.unpack("!H", data[:2])[0]

        # Wait for the complete DNS message.
        if len(data) < 2 + message_length:
            return

        dns_message = bytes(data[2:2 + message_length])

        try:
            response = dns.message.from_wire(dns_message)

            if not state["future"].done():
                state["future"].set_result(response)

        except Exception as exc:
            if not state["future"].done():
                state["future"].set_exception(exc)

        finally:
            del self.responses[event.stream_id]


def save_session_ticket(ticket, filename):
    print()
    print("[+] Received TLS session ticket")

    try:
        parent = os.path.dirname(os.path.abspath(filename))

        if parent:
            os.makedirs(parent, exist_ok=True)

        with open(filename, "wb") as f:
            pickle.dump(ticket, f)

        print(f"[+] Saved TLS session ticket to {filename}")

    except Exception as exc:
        print(f"[!] Failed to save session ticket: {exc}")


def load_session_ticket(filename):
    if not filename:
        return None

    if not os.path.exists(filename):
        return None

    try:
        with open(filename, "rb") as f:
            ticket = pickle.load(f)

        return ticket

    except Exception as exc:
        print(f"[!] Failed to load session ticket: {exc}")
        return None


def create_configuration(sni, ticket=None):
    configuration = QuicConfiguration(is_client=True, alpn_protocols=["doq"])

    if sni:
        # When SNI is specified:
        # - use it as TLS server name
        # - enable normal certificate verification
        configuration.server_name = sni
    else:
        # No SNI means certificate verification is disabled.
        configuration.verify_mode = 0

    if ticket is not None:
        # Enable TLS session resumption.
        configuration.session_ticket = ticket

    return configuration


async def do_query(server, port, sni, qname, qtype, ticket_file=None):
    print()
    print("=" * 60)
    print("DNS-OVER-QUIC CONNECTION")
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

    # ------------------------------------------------------------
    # Load an optional session ticket.
    # ------------------------------------------------------------

    ticket = None

    if ticket_file:
        ticket = load_session_ticket(ticket_file)

        if ticket is not None:
            print("[+] Session ticket available")
            print("[+] Will attempt TLS session resumption / 0-RTT")
        else:
            print("[+] No usable session ticket")
            print("[+] Will perform a normal TLS handshake")
    else:
        print("[+] No session ticket specified")
        print("[+] Will perform a normal TLS handshake")

    # ------------------------------------------------------------
    # Configure QUIC.
    # ------------------------------------------------------------

    configuration = create_configuration(sni=sni, ticket=ticket)

    # ------------------------------------------------------------
    # Save newly received tickets when a ticket file was supplied.
    # ------------------------------------------------------------

    session_ticket_handler = None

    if ticket_file:
        session_ticket_handler = (
            lambda new_ticket: save_session_ticket(new_ticket, ticket_file)
        )

    # ------------------------------------------------------------
    # With a session ticket, don't wait for the handshake.
    #
    # This allows query() to send the DNS request as TLS early data.
    #
    # Without a ticket, wait for the normal handshake first.
    # ------------------------------------------------------------

    wait_connected = ticket is None

    if ticket is not None:
        print()
        print("[+] Starting resumed QUIC connection...")
        print("[+] 0-RTT may be used")
    else:
        print()
        print("[+] Starting normal QUIC connection...")

    async with connect(
        server,
        port,
        configuration=configuration,
        create_protocol=DoQClientProtocol,
        session_ticket_handler=session_ticket_handler,
        wait_connected=wait_connected,
    ) as client:
        if ticket is not None:
            print("[+] Sending DNS query as early as possible...")

        response = await client.query(qname, qtype)

        # For a resumed connection, wait until the handshake completes
        # so we know whether resumption and 0-RTT were accepted.
        await client.wait_for_handshake()

        if client.session_resumed is True:
            print("[+] TLS SESSION RESUMPTION: YES")
        elif client.session_resumed is False:
            print("[!] TLS SESSION RESUMPTION: NO")
        else:
            print("[!] TLS session resumption status unavailable")

        if client.early_data_accepted is True:
            print("[+] 0-RTT ACCEPTED")
        elif client.session_resumed and client.early_data_accepted is False:
            print("[!] 0-RTT REJECTED")

        print()
        print("DNS RESPONSE")
        print("-" * 60)
        print(response)

        # Give aioquic/TLS time to deliver a NewSessionTicket.
        if ticket_file:
            await asyncio.sleep(0.5)

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
            "Universal DNS-over-QUIC client with optional "
            "TLS session resumption and 0-RTT."
        )
    )

    parser.add_argument(
        "server",
        help="IP address or hostname of the DNS-over-QUIC server",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=853,
        help="DNS-over-QUIC port (default: 853)",
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
