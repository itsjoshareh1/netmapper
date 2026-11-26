# netmapper

Scan your own network, list every device (IP, MAC, hostname) and see which common ports are open. Risky ports are flagged.

**Status:** work in progress. Scanning and the Streamlit web app work. AI risk explanations are next.

> Only scan networks you own or have permission to scan. The tool refuses public IP ranges and anything bigger than 1024 addresses.

## Run it (Mac, no Terminal needed)

1. On this page click **Code > Download ZIP**.
2. Double-click the ZIP to unzip it.
3. Open the folder and double-click **Start Netmapper.command**.
   - First time only: if macOS says it cannot verify the file, right-click it, choose **Open**, then **Open** again.
   - First launch takes about a minute while it sets itself up.
4. Your browser opens the app. Your network is prefilled. Press **Scan**.
5. When macOS asks to allow access to devices on your local network, click **Allow**. Without it the scan finds nothing.

Close the Terminal window that opened to stop the app.

If you have no Python, the launcher opens python.org. Install it and double-click the file again.

### For developers

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m streamlit run app.py      # web app
python netmapper.py                 # command line, auto-detects subnet
python netmapper.py 192.168.1.0/24  # or choose one
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
