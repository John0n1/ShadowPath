# ShadowPath

ShadowPath is a **smart internal network pivoting toolkit** designed for offensive security professionals. It automates post-exploitation tasks—such as SMB share enumeration, remote command execution, NTLM/DNS relaying, and Active Directory mapping—to help you "live off the land" in enterprise environments.



---

## Features

- **Credential Harvesting**  
  Enumerate SMB shares on a target using impacket's SMBConnection (supports anonymous and authenticated logins) to gather useful share information.

- **Remote Execution**  
  Execute commands on remote Windows hosts via WMI/SMB. ShadowPath wraps impacket’s `wmiexec.py` tool to deliver commands and capture output.

- **NTLM/DNS Relay**  
  Leverage NTLM relaying by wrapping impacket’s `ntlmrelayx.py` to pivot further into internal networks (future enhancements planned).

- **Active Directory Mapping**  
  Query Active Directory via LDAP (using the ldap3 library) to retrieve and map computer objects, thereby providing an up-to-date network inventory.

- **Robust Logging & Error Handling**  
  All operations are logged with timestamps, and errors are handled gracefully to ensure you get actionable feedback during engagements.

- **Modular & Extensible**  
  ShadowPath is organized into subcommands (`harvest`, `exec`, `relay`, `admap`) for easy extension and integration with other red team tools.

- **Debian/PEP 668 Compliant**  
  The tool is packaged as a Debian package and uses a local Python virtual environment for its dependencies, ensuring smooth deployment on Debian 12 and similar systems.

---

## Installation

### Installing as a Debian Package

ShadowPath is also available as a `.deb` package. To install:

   ```bash
   sudo dpkg -i shadowpath_0.1_all.deb
   ```

   The executable will be installed to `/usr/local/bin/shadowpath`.
### Prerequisites

ShadowPath requires an apt-based Linux distribution (e.g., Debian, Ubuntu). It installs its required system packages via apt. Ensure you have the following installed (the deb package will install missing ones automatically):

- `tcpdump`
- `tshark`
- `nmap`
- `arp-scan`
- `avahi-utils`
- `ffmpeg`
- `curl`
- `jq`
- `cutycapt`
- `python3`
- `python3-venv`
- `python3-pip`

It also relies on the [impacket](https://github.com/SecureAuthCorp/impacket) suite (specifically `wmiexec.py` and `ntlmrelayx.py`) and [ldap3](https://ldap3.readthedocs.io/).

### Installing from Source

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/John0n1/ShadowPath.git
   cd ShadowPath
   ```

2. **Make the Script Executable:**
   ```bash
   chmod +x shadowpath.py
   mv shadowpath.py shadowpath
   ```

3. **Run the Tool:**

   ShadowPath requires root privileges. Run it using sudo:

   ```bash
   sudo ./shadowpath <subcommand> [options]
   ```

   On first run, ShadowPath will automatically create a local Python virtual environment (`./watchtower_venv`) and install its Python dependencies (`wsdiscovery`, `scapy`, `onvif-zeep`).



---

## Usage

ShadowPath is organized into four main subcommands. Below are some examples:

### 1. Harvest SMB Shares

Attempt to enumerate SMB shares (and possibly harvest credentials) from a target.

```bash
sudo shadowpath harvest 10.0.0.5 -u DOMAIN\\user -p password
```

If credentials are not provided, an anonymous login is attempted.

### 2. Remote Command Execution

Execute a remote command on a Windows host via WMI/SMB.

```bash
sudo shadowpath exec 10.0.0.10 -u DOMAIN\\user -p password -c "ipconfig /all"
```

This command wraps impacket's `wmiexec.py` to run the command on the target.

### 3. NTLM/DNS Relay

Set up an NTLM relay to pivot into the network.

```bash
sudo shadowpath relay http://10.0.0.5 --listen-port 80
```

*Note:* This module currently wraps ntlmrelayx.py. Make sure impacket is installed and configured.

### 4. Active Directory Mapping

Query an Active Directory domain controller for computer objects.

```bash
sudo shadowpath admap ldap://dc.example.com -u DOMAIN\\user -p password -b "DC=example,DC=com"
```

This will output a list of computer objects retrieved via LDAP.

---

## Contributing

Contributions are welcome! If you have ideas, improvements, or bug fixes, please open an issue or submit a pull request.

---

## License

ShadowPath is licensed under the [MIT License](./LICENSE). See the LICENSE file for details.

---

## References

- [Impacket GitHub Repository](https://github.com/SecureAuthCorp/impacket)
- [ldap3 Documentation](https://ldap3.readthedocs.io/)
- [Nmap Network Scanning Guide](https://nmap.org/book/)
- [WS-Discovery for Python](https://python-ws-discovery.readthedocs.io/en/latest/)
- [PEP 668: Externally Managed Environments](https://peps.python.org/pep-0668/)

---
> **Disclaimer:** Use ShadowPath only on networks and systems for which you have explicit authorization. Unauthorized use is illegal and unethical.

**Happy Pivoting!**
