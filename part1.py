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

import json
import select
import socket
import struct
import time

HOST = "127.0.0.1"
PORT = 1053
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


def send(data, sock, addr=UPSTREAM_SERVER, retries=3, timeout=3):
    sock.settimeout(timeout)
    while retries > 0:
        retries -= 1
        try:
            sock.sendto(data, addr)
            sock.settimeout(None)
            return
        except socket.timeout:
            print(f"Upstream server {addr} timed out")
            print(f"Retries remaining: {retries}")
            continue


def parse_section(count, query_body, posn, is_question=False):
    rrs = []
    for _ in range(count):
        posn, name = parse_name(query_body, posn)
        rtype = struct.unpack("!H", query_body[posn : posn + 2])[0]
        rrs.append((name, DNS_TYPES[rtype]))
        posn += 2
        if is_question:
            posn += 2
        else:
            posn += 6
            data_len = struct.unpack("!H", query_body[posn : posn + 2])[0]
            posn += 2 + data_len

    return (posn, rrs)


def is_pointer(bytes):
    return True if (bytes >> 6) & 0b11 == 0b11 else False


def parse_name(query_body, posn):
    name = []
    label_len = query_body[posn]

    while label_len != 0:
        if not is_pointer(label_len):
            label_val = struct.unpack(
                f"{label_len}s", query_body[1 + posn : 1 + posn + label_len]
            )[0]
            name.append(label_val.decode())
            posn += 1 + label_len
            label_len = query_body[posn]
        else:
            ptr_offset = (
                struct.unpack("!H", query_body[posn : posn + 2])[0] & 0x3FFF
            ) - 12
            _, ref = parse_name(query_body, ptr_offset)
            name.append(ref)
            break

    if label_len == 0:
        return (posn + 1, ".".join(name))
    else:
        return (posn + 2, ".".join(name))


def log_reply(raw):
    QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = struct.unpack("!4H", raw[4:12])

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


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as recv_sock:
    recv_sock.bind((HOST, PORT))
    recv_sock.setblocking(0)

    try:
        while True:
            readable, _, _ = select.select(
                [recv_sock],
                [],
                [],
            )
            if recv_sock in readable:
                try:
                    (data, addr) = recv_sock.recvfrom(1024)

                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as send_sock:
                        send(data, send_sock)
                        response, _ = send_sock.recvfrom(1024)
                        if not response:
                            break

                        log_reply(response)
                        send(response, recv_sock, addr)
                except BlockingIOError:
                    pass
    except KeyboardInterrupt:
        recv_sock.close
