# modules/scanner.py
# Job: Scan targets with Nmap and check IPs on VirusTotal

import subprocess
import xml.etree.ElementTree as ET
import requests
import os

# Folder to save Nmap results
SCAN_DIR = 'scan_results'
os.makedirs(SCAN_DIR, exist_ok=True)


def run_nmap_scan(target: str) -> str:
    """Run Nmap on a target. Returns path to XML result file."""
    xml_file = os.path.join(SCAN_DIR, f'{target}.xml')
    subprocess.run(
        ['nmap', '-Pn', '-sV', '-oX', xml_file, target],
        capture_output=True
    )
    return xml_file


def parse_nmap_xml(xml_file: str) -> list:
    """Read the Nmap XML file and return a list of open ports."""
    if not os.path.exists(xml_file):
        return []
    try:
        root = ET.parse(xml_file).getroot()
    except ET.ParseError:
        return []

    results = []
    for host in root.findall('host'):
        # Get IP address
        addr = host.find('address')
        if addr is None:
            continue
        ip = addr.get('addr', 'unknown')

        # Get each open port
        for port in host.findall('.//port'):
            state_el = port.find('state')
            state    = state_el.get('state', 'unknown') if state_el is not None else 'unknown'

            # Skip closed ports
            if state not in ('open', 'filtered'):
                continue

            svc = port.find('service')
            results.append({
                'ip':       ip,
                'port':     port.get('portid', '0'),
                'protocol': port.get('protocol', 'tcp'),
                'state':    state,
                'service':  svc.get('name',    'unknown') if svc else 'unknown',
                'product':  svc.get('product', '')        if svc else '',
                'version':  svc.get('version', '')        if svc else '',
            })
    return results


def check_virustotal(ip: str, api_key: str) -> dict:
    """Ask VirusTotal about an IP. Returns safety info."""
    # Safe default values if anything goes wrong
    default = {
        'malicious_reports': 0,
        'suspicious_count':  0,
        'harmless_count':    0,
        'community_score':   0,
        'country':           'Unknown',
        'network':           'Unknown',
        'categories':        '',
    }

    if not api_key:
        return default

    try:
        response = requests.get(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
            headers={'x-apikey': api_key},
            timeout=10
        )
        if response.status_code != 200:
            return default

        data  = response.json()['data']['attributes']
        stats = data.get('last_analysis_stats', {})
        votes = data.get('total_votes', {})
        cats  = data.get('categories', {})

        return {
            'malicious_reports': int(stats.get('malicious',  0)),
            'suspicious_count':  int(stats.get('suspicious', 0)),
            'harmless_count':    int(stats.get('harmless',   0)),
            'community_score':   int(votes.get('harmless', 0)) - int(votes.get('malicious', 0)),
            'country':           data.get('country', 'Unknown'),
            'network':           data.get('network', 'Unknown'),
            'categories':        ', '.join(set(cats.values())) if cats else '',
        }
    except Exception:
        return default