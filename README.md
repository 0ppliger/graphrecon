```
┏━╸┏━┓┏━┓┏━┓╻ ╻┏━┓┏━╸┏━╸┏━┓┏┓╻
┃╺┓┣┳┛┣━┫┣━┛┣━┫┣┳┛┣╸ ┃  ┃ ┃┃┗┫
┗━┛╹┗╸╹ ╹╹  ╹ ╹╹┗╸┗━╸┗━╸┗━┛╹ ╹
        ATTACK SURFACE MAPPING
```

# About

GraphRecon is a set of python tools dedicated to model the attack
surface of a target in the form of a graph using the [Open Asset
Model](https://owasp-amass.github.io/docs/open_asset_model/).

# Tools

- **[dnsdump](https://github.com/0ppliger/graphrecon/tree/master/packages/dnsdump)**  
  Extract data from DNS records
- **[dnsfuzz](https://github.com/0ppliger/graphrecon/tree/master/packages/dnsfuzz)**  
  Enumerate subdomain by querying A and AAAA record based on a wordlist 
- **[txtminer](https://github.com/0ppliger/graphrecon/tree/master/packages/txtminer)**  
  Extract products based on TXT domain verification tokens
- **[certdump](https://github.com/0ppliger/graphrecon/tree/master/packages/certdump)**  
  Extract data from x509 certificate
- **[apex](https://github.com/0ppliger/graphrecon/tree/master/packages/apex)**  
  Return the apex of a given domain
  
# Consistent Coding Practices

All tools are developed using the same coding standards to ensure uniformity.

* [x] **Available as both a library and a script**  
  Supports manual use as well as automation
* [x] **Data stored in an [asset store](https://github.com/0ppliger/open-asset-store.py)**  
  Enables structured exploration of the attack surface as an asset graph
* [x] **Command pattern**  
  Makes tasks easy to queue, schedule, and run in parallel
* [x] `--nocolor` flag  
* [x] `--verbose` flag  
* [x] `--silent` flag  
* [x] `--nostore` flag  
* [x] `--nosource` flag  
* [x] `LOGLEVEL=DEBUG` support  
  Allows detailed process tracing
* [x] **Nice docstrings**  
* [x] **SIGINT handling**  
* [x] **Precise error messages**  
* [x] **Rate limiting** (*if applicable*)  
* [x] **Configurable DNS resolver** (*if applicable*)  
  
# Architecture Overview
  
`__main__.py` handles CLI arguments, displays output, and invokes commands.

`service.py` implements the commands. It is responsible for translating user input into domain-level primitives and for handling everything needed to ensure that `run()` executes without errors. It also handles storage, rate limiting, and other concerns surrounding the core logic.

`core.py` contains the tool’s core logic.
  
-----

© Oppliger J
