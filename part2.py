#!/usr/bin/env python3

"""
##### PART 2: DNS OVER HTTPS (DOH) WRAPPER #####

Extend your proxy to support DNS over HTTPS. Convert incoming DNS-over-UDP
queries into HTTPS requests and return DNS responses.

Requirements:
- Use the requests library. Optionally use dnslib or dnspython for packet
  parsing/building.
- Support at least A and CNAME queries.
- Return valid DNS UDP responses (preserve IDs, flags, and questions).
- Default to Google’s JSON DoH API (https://dns.google/resolve). RFC 8484
  binary DoH is optional extra credit.
"""

import argparse
import asyncio
import json
import signal
import socket
import struct
from typing import cast, override

import dns.message
import requests
from dns.rrset import RRset

type Address = tuple[str, int]

HOST_ADDR = ("127.0.0.1", 1053)
UPSTREAM_SERVER = "8.8.8.8"
UPSTREAM_SERVER_DOH = "https://dns.google/resolve?"

DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    38: "A6",
    39: "DNAME",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    255: "ANY",
}


class BasicDNSProxy(asyncio.DatagramProtocol):
    transport: asyncio.DatagramTransport | None
    upstream_server: Address
    debug: bool
    doh: bool

    def __init__(self, debug_flag: bool, upstream_server: str, doh_flag: bool):
        self.transport = None
        self.upstream_server = (upstream_server, 80 if doh_flag else 53)

        self.debug = debug_flag
        self.doh = doh_flag

    @override
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        print(f"Listening on {HOST_ADDR[0]}:{HOST_ADDR[1]}")

    @override
    def datagram_received(self, data: bytes, addr: Address) -> None:
        if self.doh:
            _ = asyncio.create_task(self.handle_doh_query(data, addr))
        else:
            _ = asyncio.create_task(self.handle_query(data, addr))

    async def handle_doh_query(self, data: bytes, addr: Address) -> None:
        if self.debug:
            print("Task sleeping...")
            await asyncio.sleep(3)

        params_lst = self.make_query_params(data)

        for attempt in range(3):
            try:
                responses = await asyncio.gather(
                    *[
                        asyncio.to_thread(requests.get, self.upstream_server[0], params)
                        for params in params_lst
                    ]
                )

                transport_ = cast(asyncio.DatagramTransport, self.transport)
                for r in responses:
                    parsed = self.DNSQueryParser(r.content)
                    print(parsed)

                    query_msg = dns.message.from_wire(data)
                    upstream_msg = dns.message.from_wire(r.content)
                    reply_msg = dns.message.make_response(
                        query_msg,
                        recursion_available=True,
                    )
                    reply_msg.answer.extend(upstream_msg.answer)
                    reply_msg.authority.extend(upstream_msg.authority)
                    reply_msg.additional.extend(upstream_msg.additional)
                    reply_msg.use_edns(
                        edns=upstream_msg.edns,
                        ednsflags=upstream_msg.ednsflags,
                        payload=upstream_msg.payload,
                    )
                    transport_.sendto(reply_msg.to_wire(), addr)

                break
            except asyncio.TimeoutError:
                print(f"Upstream timeout for {addr}, attempt {attempt + 1}")
                print(f"Retries remaining: {2 - attempt}")

    def make_query_params(self, data: bytes):
        params_lst: list[dict[str, str]] = []
        questions = dns.message.from_wire(data).question
        for q in questions:
            name = q.name.to_unicode()
            type = DNS_TYPES[q.rdtype]
            params_lst.append(
                {"name": name, "type": type, "ct": "application/dns-message"}
            )

        return params_lst

    def preserve_header(self, data: bytes):
        message = dns.message.from_wire(data)
        return (message.id, message.flags)

    async def handle_query(self, data: bytes, addr: Address) -> None:
        if self.debug:
            print("Task sleeping...")
            await asyncio.sleep(3)

        transport: asyncio.DatagramTransport | None = None

        loop = asyncio.get_running_loop()

        for attempt in range(3):
            try:
                on_response = loop.create_future()

                def on_response_factory():
                    class Upstream(asyncio.DatagramProtocol):
                        @override
                        def datagram_received(self, data: bytes, addr: Address) -> None:
                            if not on_response.done():
                                on_response.set_result(data)

                    return Upstream()

                transport, _ = await loop.create_datagram_endpoint(
                    on_response_factory,
                    remote_addr=self.upstream_server,
                    family=socket.AF_INET,
                )

                transport.sendto(data)

                response: bytes = await asyncio.wait_for(on_response, timeout=3)

                parsed = self.DNSQueryParser(response)
                print(parsed)

                transport_ = cast(asyncio.DatagramTransport, self.transport)
                transport_.sendto(response, addr)
                break
            except asyncio.TimeoutError:
                print(f"Upstream timeout for {addr}, attempt {attempt + 1}")
                print(f"Retries remaining: {2 - attempt}")
            finally:
                if transport:
                    transport.close()

    class DNSQueryParser:
        query: dns.message.Message

        def __init__(self, query: bytes) -> None:
            self.query = dns.message.from_wire(query)

            self.write_to_file()

        @override
        def __str__(self) -> str:
            sections = [
                ("Questions", self.query.question),
                ("Answer RRs", self.query.answer),
                ("Authority RRs", self.query.authority),
                ("Additional RRs", self.query.additional),
            ]

            lines = ["\n=START==============="]

            for section, rrsets in sections:
                section_count = self.query.section_count(rrsets)
                lines.append(f"{section} ({section_count}):")

                if not section_count:
                    lines.append("  (none)")
                else:
                    records = self.parse_rrset_lst(rrsets)
                    if not records and self.query.opt:
                        records = self.parse_rrset_lst([self.query.opt])

                    [
                        lines.append(
                            f"  - Name: {name}, Type: {type}{f" ({rlength} bytes)" if rlength else ""}"
                        )
                        for name, type, rlength in records
                    ]

            lines.append("==============END=\n")
            return "\n".join(lines)

        def parse_rrset_lst(
            self, rrsets: list[RRset]
        ) -> list[tuple[str, str, int | None]]:
            records: list[tuple[str, str, int | None]] = []
            for rrset in rrsets:
                name = rrset.name.to_unicode()
                type = DNS_TYPES[rrset.rdtype]

                if not rrset.processing_order():
                    records.append((name, type, None))
                else:
                    for rdata in rrset.processing_order():
                        rlength = 0
                        bytes = rdata.to_wire()
                        if bytes:
                            rlength = len(bytes)
                        records.append((name, type, rlength))

            return records

        def write_to_file(self) -> None:
            with open("output.json", "w") as output:
                data = {
                    "question": [
                        {"name": name, "type": type}
                        for name, type, _ in self.parse_rrset_lst(self.query.question)
                    ],
                    "answer": [
                        {"name": name, "type": type, "resource_size": size}
                        for name, type, size in self.parse_rrset_lst(self.query.answer)
                    ],
                    "authority": [
                        {"name": name, "type": type, "resource_size": size}
                        for name, type, size in self.parse_rrset_lst(
                            self.query.authority
                        )
                    ],
                    "additional": [
                        {"name": name, "type": type, "resource_size": size}
                        for name, type, size in self.parse_rrset_lst(
                            self.query.additional + [self.query.opt]
                            if self.query.opt
                            else self.query.additional
                        )
                    ],
                }

                json.dump(
                    data,
                    output,
                    indent=4,
                )


async def main():
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--upstream", type=str, default=UPSTREAM_SERVER)
    _ = parser.add_argument("--debug", action="store_true")
    _ = parser.add_argument("--doh", action="store_true")
    args = parser.parse_args()

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    loop.add_signal_handler(signal.SIGINT, stop_event.set)

    transport, _ = await loop.create_datagram_endpoint(
        lambda: BasicDNSProxy(
            args.debug,
            (
                UPSTREAM_SERVER_DOH
                if args.doh and args.upstream == UPSTREAM_SERVER
                else args.upstream
            ),
            args.doh,
        ),
        local_addr=HOST_ADDR,
    )

    try:
        _ = await stop_event.wait()
    finally:
        transport.close()

    pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in pending:
        _ = task.cancel()
    _ = await asyncio.gather(*pending, return_exceptions=True)
    print("\nShutting down...")


if __name__ == "__main__":
    asyncio.run(main())
