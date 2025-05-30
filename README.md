# Cybersec Tools

**Multithreaded Port Scanner & Packet Sniffer** in Python 3.

## Features

- **Port Scanner**: TCP connect scan across a port range, multithreaded.
- **Packet Sniffer**: Raw-socket capture of Ethernet & IPv4 headers.
- **CLI Interface**: `scan` and `sniff` subcommands.

## Installation

```bash
git clone https://github.com/<your-username>/cybersec-tools.git
cd cybersec-tools
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
