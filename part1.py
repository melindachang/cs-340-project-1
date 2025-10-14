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

import asyncio
import json
import socket
import struct

HOST_ADDR = ("127.0.0.1", 1053)
UPSTREAM_SERVER = ("8.8.8.8", 53)

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


def send(
    data: bytes,
    sock: socket.SocketType,
    addr: tuple[str, int] = UPSTREAM_SERVER,
    retries: int = 3,
    timeout: int = 3,
):
    sock.settimeout(timeout)
    while retries > 0:
        retries -= 1
        try:
            _ = sock.sendto(data, addr)
            sock.settimeout(None)
            return
        except socket.timeout:
            print(f"Upstream server {addr} timed out")
            print(f"Retries remaining: {retries}")
            continue


def parse_section(count: int, query_body: bytes, posn: int, is_question: bool = False):
    rrs: list[tuple[str, str]] = []
    for _ in range(count):
        posn, name = parse_name(query_body, posn)
        rtype: int = struct.unpack("!H", query_body[posn : posn + 2])[0]
        rrs.append((name, DNS_TYPES[rtype]))
        posn += 2
        if is_question:
            posn += 2
        else:
            posn += 6
            data_len: int = struct.unpack("!H", query_body[posn : posn + 2])[0]
            posn += 2 + data_len

    return (posn, rrs)


def is_pointer(bytes: int):
    return True if (bytes >> 6) & 0b11 == 0b11 else False


def parse_name(query_body: bytes, posn: int):
    name: list[str] = []
    label_len = query_body[posn]

    while label_len != 0:
        if not is_pointer(label_len):
            label_val: bytes = struct.unpack(
                f"{label_len}s", query_body[1 + posn : 1 + posn + label_len]
            )[0]
            name.append(label_val.decode())
            posn += 1 + label_len
            label_len = query_body[posn]
        else:
            ptr_offset: int = (
                struct.unpack("!H", query_body[posn : posn + 2])[0] & 0x3FFF
            ) - 12
            _, ref = parse_name(query_body, ptr_offset)
            name.append(ref)
            break

    if label_len == 0:
        return (posn + 1, ".".join(name))
    else:
        return (posn + 2, ".".join(name))


def log_reply(raw: bytes):
    counts: tuple[int, int, int, int] = struct.unpack("!4H", raw[4:12])
    QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = counts

    query_body = raw[12:]

    posn, qd = parse_section(QDCOUNT, query_body, 0, True)
    posn, an = parse_section(ANCOUNT, query_body, posn)
    posn, ns = parse_section(NSCOUNT, query_body, posn)
    posn, ar = parse_section(ARCOUNT, query_body, posn)

    with open("output.json", "w") as output:
        data = {
            "question": [{"name": name, "type": type} for name, type in qd],
            "answer": [{"name": name, "type": type} for name, type in an],
            "authority": [{"name": name, "type": type} for name, type in ns],
            "additional": [{"name": name, "type": type} for name, type in ar],
        }

        print(json.dumps(data))

        json.dump(
            data,
            output,
            indent=4,
        )


async def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as recv_sock:
        recv_sock.bind(HOST_ADDR)
        recv_sock.setblocking(False)

        try:
            while True:
                print("lol")
        except KeyboardInterrupt:
            recv_sock.close


# with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as recv_sock:
#     recv_sock.bind(HOST_ADDR)
#     recv_sock.setblocking(False)
#
#     try:
#         while True:
#             readable, _, _ = select.select(
#                 [recv_sock],
#                 [],
#                 [],
#             )
#             if recv_sock in readable:
#                 try:
#                     (data, addr) = recv_sock.recvfrom(1024)
#
#                     with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as send_sock:
#                         send(data, send_sock)
#                         response, _ = send_sock.recvfrom(1024)
#                         if not response:
#                             break
#
#                         log_reply(response)
#                         send(response, recv_sock, addr)
#                 except BlockingIOError:
#                     pass
#     except KeyboardInterrupt:
#         recv_sock.close
