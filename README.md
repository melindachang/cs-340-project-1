# cs-340-project-1

Melinda Chang (yus8813)

## Usage

### Part 1

Run the following:

``` python part1.py [--upstream=address] [--debug] ```

Use `dig` to perform a DNS lookup via `localhost:1053`:

``` dig @127.0.0.1 -p 1053 example.com A ```

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

**Options**
- `--upstream`: Change upstream address to which DNS requests will be forwarded
  (default: `8.8.8.8`)
- `--debug`: Test async I/O unblocking; stalls every `handle_query()` call by 3
  seconds
