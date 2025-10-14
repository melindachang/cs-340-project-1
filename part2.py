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
