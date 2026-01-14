# DNSDump

Dump all DNS records by requesting every record type.

# Usage

It can be use both as library and as a CLI tool.

## CLI

```
usage: dnsdump [-h] -d DOMAIN [-v] [-s] [-r RESOLV] [--nocolor] [--nosource]

Dump all DNS records by requesting every RRType.

options:
  -h, --help           show this help message and exit
  -d, --domain DOMAIN  Domain name to query
  -v, --verbose        Show failed attempts
  -s, --silent         Show failed attempts
  -r, --resolv RESOLV  Path to the resolver configuration file
  --nocolor            Disable colors on stdout
  --nosource           Disable source tags in OAM
  ```

## Library

```python
from graphrecon_lib import Context
from dnsdump import (
    DNSDump,
    DNSDumpAnswer,
    DNSDumpNoAnswer,
    DNSDumpQueryFail
)

with Context("dnsdump") as ctx:
    dnsdump = DNSDump(ctx)

    dump = dnsdump.dump_domain("exemple.com")

    for answer in dump:
        match answer:
            case DNSDumpAnswer():
                print(answer.rdtype, answer.data)
            case DNSDumpNoAnswer():
                print(answer.rdtype, "No such entry")
            case DNSDumpQueryFail():
                print(answer.rdtype, "Query fail")
```