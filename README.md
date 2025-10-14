# cs-340-project-1

Melinda Chang (yus8813)

## Usage

### Part 1

Run the following:

``` python part1.py [--upstream=address] [--debug] ```

**Options**
- `--upstream`: Set address to which DNS requests will be forwarded (default:
  `8.8.8.8`)
- `--debug`: Test async I/O unblocking; stalls every `handle_query()` call by 3 seconds
