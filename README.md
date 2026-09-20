# NETRA v0.1.0

### Network Reconnaissance Toolkit

NETRA is a lightweight Python-based TCP reconnaissance tool built to understand what is actually happening during a network scan --- from
opening a TCP connection to identifying the service running behind an
open port.

It is intentionally small, terminal-based, and dependency-free.

> **Scan ports. Find services. Read the response.**

------------------------------------------------------------------------


## Requirements

-   Python 3.9+
-   Windows, Linux, or another platform with standard Python socket
    support
-   No third-party Python packages required for the core scanner

Check your Python version:

``` bash
python --version
```

or on some Linux systems:

``` bash
python3 --version
```

------------------------------------------------------------------------

## Installation

Clone the repository:

``` bash
git clone https://github.com/Kishore-Code-Hub/Network-Reconnaissance-Toolkit.git
cd Network-Reconnaissance-Toolkit
```

Run NETRA:

### Windows

``` powershell
python netra.py
```

### Linux

``` bash
python3 netra.py
```

------------------------------------------------------------------------

## What NETRA does

NETRA takes a hostname or IP address, scans the selected ports,
identifies which ones accept TCP connections, and optionally performs
basic service/banner detection on the ports that are open.

A typical run looks like:

``` text
Target
  ↓
Resolve hostname
  ↓
Select ports
  ↓
TCP scan
  ↓
OPEN / CLOSED / NO RESPONSE
  ↓
Service detection
  ↓
Banner / protocol information
  ↓
Final report
```

The goal of v0.1.0 is simple: **do network reconnaissance well before
adding anything else.**

------------------------------------------------------------------------

## Features

-   **Quick Scan**
    -   Scans a predefined set of common service ports.
-   **Custom Port Range**
    -   Scan any range from `1` to `65535`.
    -   Example: `1-10000`
-   **Custom Port List**
    -   Scan individual ports and ranges.

    -   Example:

        ``` text
        22,80,443,3306,8000-8010
        ```
-   **Threaded scanning**
    -   Uses concurrent workers for faster scans.
-   **Sequential scanning**
    -   Useful for understanding and comparing the basic scanning
        process without concurrency.
-   **Service / banner detection**
    -   Runs after an open TCP port is found.
    -   Includes protocol-aware identification for supported services.
-   **Latency measurement**
    -   Shows how long the TCP connection took.
-   **Live results**
    -   Open ports are displayed while the scan is running.
-   **Graceful Ctrl+C**
    -   Large scans can be interrupted without killing the whole
        program.
-   **Clear TCP states**
    -   `OPEN`
    -   `CLOSED`
    -   `NO RESPONSE`
    -   `ERROR`
-   **Reusable Python API**
    -   The scanner is designed to be imported and used by other Python
        security tools.
-   **Single-file design**
    -   The current module stays compact and easy to understand.

------------------------------------------------------------------------

## Example

![NETRA terminal demo](/assets/netra-demo.png)

------------------------------------------------------------------------

## Scan modes

### Fast --- Threaded

The default mode.

Multiple ports are scanned concurrently, making it suitable for larger
ranges.

``` text
[1] Fast (Threaded)
```

### Sequential

Ports are scanned one after another.

``` text
[2] Sequential
```

This mode is slower, but it is useful for learning how the scanner
behaves without concurrent workers.

------------------------------------------------------------------------

## Service detection

Service detection is performed on ports that are actually found to be
open.

For example:

``` text
80    → HTTP
443   → HTTPS
22    → SSH
53    → DNS
3306  → MySQL
```

NETRA also attempts protocol-aware banner detection where supported.

The important distinction is that a port number alone is only a
convention. A service label should be treated as an identification
result, not absolute proof of what software is running.

------------------------------------------------------------------------

## Using NETRA as a Python module

NETRA is not limited to its interactive terminal interface.

The core scanner can be imported into another Python project.

Example:

``` python
from netra import PortScanner

scanner = PortScanner("192.168.1.10")

results = scanner.scan(
    ports=[22, 80, 443],
    threaded=True
)

for result in results:
    if result.state == "OPEN":
        print(result)
```

This makes NETRA useful as a building block for larger security
automation projects.

------------------------------------------------------------------------

## Port range examples

### Quick scan

Choose:

``` text
[1] Quick Scan
```

### Scan ports 1--1000

``` text
Start port: 1
End port: 1000
```

### Scan ports 1--10000

``` text
Start port: 1
End port: 10000
```

### Custom list

``` text
22,80,443,3306,8000-8010
```

------------------------------------------------------------------------

## Project structure

The current version intentionally stays small:

``` text
NETRA/
│
├── netra.py
├── README.md
└── assets/
    └── netra-demo.png
```

The single-file approach makes the first version easy to read, test, and
understand.

As the project grows, functionality can be separated into modules
without changing the core idea.

------------------------------------------------------------------------

## What this project is for

NETRA is primarily a learning and security-engineering project.

It demonstrates practical understanding of:

-   TCP connections
-   sockets
-   port states
-   timeouts
-   concurrency
-   hostname resolution
-   service identification
-   banner grabbing
-   structured results
-   command-line interfaces
-   reusable Python components

It is also a foundation for future reconnaissance modules.

------------------------------------------------------------------------

## Roadmap

The first milestone is deliberately focused.

### v0.1.0 --- TCP Reconnaissance

-   [x] TCP port scanning
-   [x] Quick scan
-   [x] Custom ranges
-   [x] Custom port lists
-   [x] Threaded scanning
-   [x] Sequential scanning
-   [x] Service detection
-   [x] Banner detection
-   [x] Latency
-   [x] Ctrl+C handling
-   [x] Reusable scanner API

### Future

Possible future modules:

``` text
NETRA
├── TCP Reconnaissance
├── Service Intelligence
├── DNS Reconnaissance
├── HTTP Reconnaissance
└── Reporting / Automation
```

Future features should be added when they are useful and reliable ---
not simply to make the feature list longer.

------------------------------------------------------------------------

## Responsible use

Only scan systems and networks that you own or have explicit permission
to test.

NETRA is intended for learning, authorized security testing, lab
environments, CTFs, and defensive network reconnaissance.

------------------------------------------------------------------------

## Version

**NETRA v0.1.0 --- TCP Network Reconnaissance**

Built with Python and the standard library.

