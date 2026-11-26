# netmapper

Scan your own network, list every device (IP, MAC, hostname) and see which common ports are open. Risky ports are flagged.

**Status:** work in progress. Scanning and the Streamlit web app work. AI risk explanations are next.

> Only scan networks you own or have permission to scan. The tool refuses public IP ranges and anything bigger than 1024 addresses.

## Run it (Mac)

```bash
git clone https://github.com/itsjoshareh1/netmapper.git
cd netmapper
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m streamlit run app.py
```

Your browser opens at `localhost:8501`. The subnet is auto-detected (usually a `192.168.x.0/24`). Press **Scan**.

Command line and tests:

```bash
python netmapper.py                  # scan auto-detected subnet
python netmapper.py 192.168.1.0/24   # or choose one
pytest
```

## How it works

1. Detect your local IP and build the /24 subnet around it.
2. For every address, try a TCP connection to 17 common ports. An open port or an active refusal means a device is there.
3. Read the ARP table (`arp -a`) to catch devices that ignore connections and to get MAC addresses.
4. Look up hostnames, label each open port by risk, show a table.

No admin rights and no extra tools needed. It is slower than `nmap` and can miss devices that block everything.

## Roadmap

- [x] Ping-free host discovery and port check
- [x] Streamlit table with risk flags
- [ ] MAC vendor lookup (who made this device?)
- [ ] Banner grabbing and service/version guesses
- [ ] Claude explains each device's risk in plain language
- [ ] Scan history and "what changed since last time"

## Limits

TCP connect scanning only. It checks 17 common ports, not all 65535. A device that drops all traffic and is not in the ARP table will not show up.

## License

MIT
