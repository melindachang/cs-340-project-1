#!/usr/bin/env python3

"""
##### PART 1: DNS PROXY #####

Implement a UDP DNS proxy that listens on 127.0.0.1:1053 (a non-privileged
port), forwards DNS queries to an upstream resolver (default 8.8.8.8), and
relays responses. No caching is required.

Requirements:
- Use only Python standard libraries (socket, select/asyncio, etc.).
- Handle multiple concurrent clients (e.g., non-blocking I/O).
- Preserve DNS transaction IDs and payloads (no parsing required).
- Implement basic timeouts and retries to the upstream server.
- Bind only to 127.0.0.1 (do not expose publicly).
- Log query names/types and response sizes.
"""

import argparse
import asyncio
import json
import signal
import socket
import struct
from typing import cast, override

type Address = tuple[str, int]

HOST_ADDR = ("127.0.0.1", 1053)
UPSTREAM_SERVER = "8.8.8.8"

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

    def __init__(self, debug_flag: bool, upstream_server: str):
        self.transport = None
        self.upstream_server = (upstream_server, 53)
        self.debug = debug_flag

    @override
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        print(f"Listening on {HOST_ADDR[0]}:{HOST_ADDR[1]}")

    @override
    def datagram_received(self, data: bytes, addr: Address) -> None:
        _ = asyncio.create_task(self.handle_query(data, addr))

    async def handle_query(self, data: bytes, addr: Address):
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
        query_head: bytes
        query_body: bytes

        qd_records: list[tuple[str, str]]
        an_records: list[tuple[str, str, int]]
        ns_records: list[tuple[str, str, int]]
        ar_records: list[tuple[str, str, int]]

        def __init__(self, query: bytes) -> None:
            self.query_head = query[:12]
            self.query_body = query[12:]
            qd, an, ns, ar = self.parse()

            self.qd_records = qd
            self.an_records = an
            self.ns_records = ns
            self.ar_records = ar

            self.write_to_file()

        @override
        def __str__(self) -> str:
            sections = [
                (
                    "Questions",
                    self.qd_records,
                ),
                (
                    "Answer RRs",
                    self.an_records,
                ),
                (
                    "Authority RRs",
                    self.ns_records,
                ),
                (
                    "Additional RRs",
                    self.ar_records,
                ),
            ]

            lines = ["\n=START==============="]

            for section, records in sections:
                lines.append(f"{section} ({len(records)}):")

                if not len(records):
                    lines.append("  (none)")

                for record in records:
                    line = f"  - Name: {record[0]}, Type: {record[1]}"
                    if len(record) == 3:
                        line += f" ({record[2]} bytes)"
                    lines.append(line)

            lines.append("==============END=\n")
            return "\n".join(lines)

        def parse(self):
            counts: tuple[int, int, int, int] = struct.unpack(
                "!4H", self.query_head[4:]
            )
            QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = counts
            posn, qd = self.parse_questions(QDCOUNT, 0)
            posn, an = self.parse_records(ANCOUNT, posn)
            posn, ns = self.parse_records(NSCOUNT, posn)
            posn, ar = self.parse_records(ARCOUNT, posn)

            return (qd, an, ns, ar)

        def parse_questions(
            self, num_qns: int, posn: int
        ) -> tuple[int, list[tuple[str, str]]]:
            questions: list[tuple[str, str]] = []
            for _ in range(num_qns):
                posn, record_name = self.parse_name(posn)
                posn, record_type = self.parse_type(posn)
                questions.append((record_name, record_type))
                posn += 2

            return posn, questions

        def parse_records(self, num_records: int, posn: int):
            records: list[tuple[str, str, int]] = []
            for _ in range(num_records):
                posn, record_name = self.parse_name(posn)
                posn, record_type = self.parse_type(posn)
                posn += 6
                rdlength: int = struct.unpack("!H", self.query_body[posn : posn + 2])[0]
                records.append((record_name, record_type, rdlength))
                posn += 2 + rdlength

            return posn, records

        def parse_name(self, posn: int) -> tuple[int, str]:
            name: list[str] = []
            label_len = self.query_body[posn]

            while label_len != 0:
                if not self.is_pointer(label_len):
                    label_val: bytes = struct.unpack(
                        f"{label_len}s",
                        self.query_body[1 + posn : 1 + posn + label_len],
                    )[0]
                    name.append(label_val.decode())
                    posn += 1 + label_len
                    label_len = self.query_body[posn]
                else:
                    ptr_offset: int = (
                        struct.unpack("!H", self.query_body[posn : posn + 2])[0]
                        & 0x3FFF
                    ) - 12
                    _, ref = self.parse_name(ptr_offset)
                    name.append(ref)
                    break

            if label_len == 0:
                return (posn + 1, ".".join(name))
            else:
                return (posn + 2, ".".join(name))

        def parse_type(self, posn: int) -> tuple[int, str]:
            record_type: int = struct.unpack("!H", self.query_body[posn : posn + 2])[0]
            posn += 2
            return (posn, DNS_TYPES[record_type])

        def is_pointer(self, bytes: int) -> bool:
            return True if (bytes >> 6) & 0b11 == 0b11 else False

        def write_to_file(self) -> None:
            with open("output.json", "w") as output:
                data = {
                    "question": [
                        {"name": name, "type": type} for name, type in self.qd_records
                    ],
                    "answer": [
                        {"name": name, "type": type, "resource_size": size}
                        for name, type, size in self.an_records
                    ],
                    "authority": [
                        {"name": name, "type": type, "resource_size": size}
                        for name, type, size in self.ns_records
                    ],
                    "additional": [
                        {"name": name, "type": type, "resource_size": size}
                        for name, type, size in self.ar_records
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
    args = parser.parse_args()

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    loop.add_signal_handler(signal.SIGINT, stop_event.set)

    transport, _ = await loop.create_datagram_endpoint(
        lambda: BasicDNSProxy(args.debug, args.upstream), local_addr=HOST_ADDR
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
