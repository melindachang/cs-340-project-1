# cs-340-project-1

Melinda Chang (yus8813)

## Instructions

Clone repository:

```
git clone https://github.com/melindachang/cs-340-project-1.git
cd cs340-project-1
```

Activate your virtual environment and install dependencies:

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Part 1

### Usage

Run the following:

```
python part1.py [--upstream=address] [--debug]
```

Example output:
```
$ python part1.py --upstream=1.1.1.1
Listening on 127.0.0.1:1053

=START===============
Questions (1):
  - Name: example.com, Type: A
  Answer RRs (6):
  - Name: example.com, Type: A (4 bytes)
  - Name: example.com, Type: A (4 bytes)
  - Name: example.com, Type: A (4 bytes)
  - Name: example.com, Type: A (4 bytes)
  - Name: example.com, Type: A (4 bytes)
  - Name: example.com, Type: A (4 bytes)
Authority RRs (0):
  (none)
Additional RRs (1):
  - Name: , Type: OPT (0 bytes)
==============END=
```

See `output.json` for dump.

#### Options
- `--upstream`: Change upstream address to which DNS requests will be forwarded
  (default: `8.8.8.8`)
- `--debug`: Test async I/O unblocking; stalls every `handle_query()` call by 3
  seconds

### Design Description

The class `BasicDNSProxy` extends `asyncio.DatagramProtocol`, meaning each
instance is associated with an instance of an `asyncio` transport (abstraction
of socket API). The transport performs callbacks to pass the data it receives
to the protocol object, i.e., our proxy.

Stepping through the program:
1. `asyncio.run` starts an event loop using `main()` as its entrypoint
2. Event loop binds a new transport to localhost port and associates it with a
   new instance of `BasicDNSProxy`
3. When socket is successfully bound, transport triggers `connection_made`
   callback and passes the proxy a reference to itself
4. When the transport receives a new incoming datagram, it triggers the
   `datagram_received` callback - this schedules a run of the `handle_query`
   coroutine that is passed the datagram
5. `handle_query` creates a new transport to communicate with the upstream
   server and an awaitable `Future` placeholder that will eventually contain
   its reply
6. New transport forwards the passed-in query, awaits response (timeout and
   retry logic is here, handled with `asyncio.wait_for()`)
7. Result of fulfilled future is passed into an instance of the nested class
   `DNSQueryParser`, which dumps a JSON-serialized version to `output.json`
8. Unparsed datagram is passed back through the original transport to the
   source port of the original query

Other notes:
- `asyncio` enables non-blocking I/O because the logic to handle each client is
  encapsulated in the `handle_query` method, each call to which the event loop
  can pause midway (during a few specific asynchronous operations: `await`,
  `asycio.sleep()`...) to execute other tasks concurrently
- In `main()`, a try...finally statement with a `stop_event` listener prevents
  errors from being thrown by `SIGINT` (CTRL+C).

## Part 2

### Usage

Run the following:

```
python part2.py [--upstream=address] [--debug] [--doh]
```

#### Options
- `--doh`: Transmit upstream over HTTPS instead of UDP
- `--upstream`: Change upstream address to which DNS requests will be forwarded
  (default: `8.8.8.8`; if `--doh`, default: `https://dns.google/resolve?`)
- `--debug`: Test async I/O unblocking; stalls every new task by 3 seconds

### Design Description

All functionality from part 1 remains, but parsing is now handled by
`dnspython`. Tracing where the new proxy diverges from the old one:

1. Upon `datagram_received` callback: if `--doh` argument was provided, passes
   data into the coroutine `handle_doh_query`.
2. `requests` library functions are all synchronous, so control is handed to
   the event loop by making a new `asyncio` thread for it. Proxy extracts the
   question entry from the received data and supplies it as a parameter for an
   HTTPS GET request to the upstream endpoint.
3. The HTTPS response that eventuates is parsed into a DNS message, and the
   contents of its answer, authority, and additional RR sections are embedded
   in a new `Message` object that copies over most of the header of the initial
   query. This message is then sent off to the original host.

## Part 2(b)

### Design Description

The same program as in part 2, except:
- `handle_doh_query` now encodes the entire contents of the received datagram
  in Base64URL and appends it to the URI of the request
- Forwarded request has an ID of 0 for caching considerations (actual ID is
  restored upon relaying reply back to requestee).

## Part 3

### Usage

See `part3.log` for logging info from the most recent script run.

### Design Description

The same program as in part 2(b), except:
- `BasicDNSProxy` now stores its own persistent `requests.Session` object,
  which is instantiated upon the first call to `datagram_received` along with a
  persistent `Accept:` header.
- `handle_doh_query` now uses `logging.Logger` to broadcast how much time
  elapses between the start and end of each task

### Measurements

Measurements were taken as follows. I start the proxy:

```
python part3.py --doh
```

From a different terminal I fire off DNS lookups in the following order:

```
dig @127.0.0.1 -p 1053 example.com A
dig @127.0.0.1 -p 1053 www.example.com CNAME
dig @127.0.0.1 -p 1053 example.com A
dig @127.0.0.1 -p 1053 example.com A
dig @127.0.0.1 -p 1053 www.example.com CNAME
dig @127.0.0.1 -p 1053 www.example.com CNAME
```

The file `part3.log` now contains the following:

```
INFO:__main__:(ID57077) QUERY [ Name: example.com., Type: A ]
INFO:__main__:(ID57077) START Timer
INFO:__main__:(ID57077) END Time elapsed: 51.199977ms
INFO:__main__:(ID37033) QUERY [ Name: www.example.com., Type: CNAME ]
INFO:__main__:(ID37033) START Timer
INFO:__main__:(ID37033) END Time elapsed: 30.814066ms
INFO:__main__:(ID31113) QUERY [ Name: example.com., Type: A ]
INFO:__main__:(ID31113) START Timer
INFO:__main__:(ID31113) END Time elapsed: 21.826936ms
INFO:__main__:(ID63478) QUERY [ Name: example.com., Type: A ]
INFO:__main__:(ID63478) START Timer
INFO:__main__:(ID63478) END Time elapsed: 11.626827ms
INFO:__main__:(ID27770) QUERY [ Name: www.example.com., Type: CNAME ]
INFO:__main__:(ID27770) START Timer
INFO:__main__:(ID27770) END Time elapsed: 20.792699ms
INFO:__main__:(ID10328) QUERY [ Name: www.example.com., Type: CNAME ]
INFO:__main__:(ID10328) START Timer
INFO:__main__:(ID10328) END Time elapsed: 17.565559ms
```

The ID displayed in parentheses is the DNS query ID and tells us which
coroutine each log belongs to.

Let's do the same operations, this time using the near-identical script from
part 2(b):

```
python part2b.py --doh
```

These are the contents of `part2b.log`:

```
INFO:__main__:(ID31606) QUERY [ Name: example.com., Type: A ]
INFO:__main__:(ID31606) START Timer
INFO:__main__:(ID31606) END Time elapsed: 63.378534ms
INFO:__main__:(ID6955) QUERY [ Name: www.example.com., Type: CNAME ]
INFO:__main__:(ID6955) START Timer
INFO:__main__:(ID6955) END Time elapsed: 46.238061ms
INFO:__main__:(ID53270) QUERY [ Name: example.com., Type: A ]
INFO:__main__:(ID53270) START Timer
INFO:__main__:(ID53270) END Time elapsed: 51.014552ms
INFO:__main__:(ID6978) QUERY [ Name: example.com., Type: A ]
INFO:__main__:(ID6978) START Timer
INFO:__main__:(ID6978) END Time elapsed: 33.406025ms
INFO:__main__:(ID44349) QUERY [ Name: www.example.com., Type: CNAME ]
INFO:__main__:(ID44349) START Timer
INFO:__main__:(ID44349) END Time elapsed: 61.347146ms
INFO:__main__:(ID58037) QUERY [ Name: www.example.com., Type: CNAME ]
INFO:__main__:(ID58037) START Timer
INFO:__main__:(ID58037) END Time elapsed: 45.424713ms
```

Every request in part 2(b) takes substantially longer, presumably because the
proxy had to establish a new connection to service every query. Later requests
in part 3 are consistently fulfilled faster than the first request.
