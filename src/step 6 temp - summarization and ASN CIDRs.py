import socket
import geoip2.database
import logging
import requests
import ipaddress
import time
import os
import subprocess
import json
from collections import defaultdict
from idna import encode as idna_encode

# Paths to input files
IP_LST_PATH = 'sum/input/ips_all.lst'
DOMAINS_LST_PATH = 'sum/output/domains_all.lst'
OUTPUT_FILE = 'sum/output/ipsum.lst'

# Path to the GeoLite2 ASN database
GEOIP_DB_PATH = 'sum/GeoLite2-ASN.mmdb'
GEOIP_DB_URLS = [
    'https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb'
]

# Cloudflare official IP ranges endpoint (public, no auth required)
CLOUDFLARE_IPS_URL = 'https://api.cloudflare.com/client/v4/ips'

# Static fallback Cloudflare ranges (kept in sync with the public list).
# Used only if the live API cannot be reached.
CLOUDFLARE_FALLBACK_CIDRS = [
    # IPv4
    '173.245.48.0/20',
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '190.93.240.0/20',
    '188.114.96.0/20',
    '197.234.240.0/22',
    '198.41.128.0/17',
    '162.158.0.0/15',
    '104.16.0.0/13',
    '104.24.0.0/14',
    '172.64.0.0/13',
    '131.0.72.0/22',
    # IPv6
    '2400:cb00::/32',
    '2606:4700::/32',
    '2803:f800::/32',
    '2405:b500::/32',
    '2405:8100::/32',
    '2a06:98c0::/29',
    '2c0f:f248::/29',
]

# Function to fetch Cloudflare's official IP ranges, falling back to a
# hard-coded list if the API is unreachable.
def fetch_cloudflare_cidrs():
    try:
        response = requests.get(CLOUDFLARE_IPS_URL, timeout=30)
        response.raise_for_status()
        data = response.json().get('result', {})
        cidrs = list(data.get('ipv4_cidrs', [])) + list(data.get('ipv6_cidrs', []))
        if cidrs:
            logging.info(f'Fetched {len(cidrs)} Cloudflare CIDRs from the live API.')
            return cidrs
        logging.warning('Cloudflare API returned an empty list; using fallback.')
    except Exception as e:
        logging.warning(f'Failed to fetch Cloudflare IPs from API: {e}; using fallback.')
    return list(CLOUDFLARE_FALLBACK_CIDRS)

# Function to download the GeoLite2 ASN database
def download_geolite2_asn_db():
    if not os.path.exists(GEOIP_DB_PATH):
        for url in GEOIP_DB_URLS:
            try:
                response = requests.get(url)
                response.raise_for_status()
                with open(GEOIP_DB_PATH, 'wb') as f:
                    f.write(response.content)
                logging.info(f'Downloaded GeoLite2 ASN database to {GEOIP_DB_PATH} from {url}')
                return
            except requests.RequestException as e:
                logging.warning(f'Failed to download GeoLite2 ASN database from {url}: {e}')
        logging.error('All attempts to download the GeoLite2 ASN database have failed.')
        raise Exception('Unable to download GeoLite2 ASN database')

# Initialize the GeoIP2 reader
def initialize_geoip_reader():
    download_geolite2_asn_db()
    return geoip2.database.Reader(GEOIP_DB_PATH)

# Set up logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler('summary.log', mode='a'),
                        logging.StreamHandler()
                    ])

# Trusted ASNs for company domains
COMPANY_DOMAINS = {
    'google.com': [15169],
    'youtube.com': [15169],
    'ggpht.com': [15169],
    'facebook.com': [32934],
    'instagram.com': [32934],
    'whatsapp.com': [32934],
    'microsoft.com': [8075],
    'linkedin.com': [14492],
    'netflix.com': [2906],
    'akamai.com': [20940],
    'twitter.com': [13414],
    'x.com': [13414],
    'dropbox.com': [19679],
    'tesla.com': [394161]
}

# Local IP CIDRs to exclude
LOCAL_IP_CIDRS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10')
]

# Function to summarize IPs into the smallest possible subnets, with /28 as the maximum

def summarize_ips(ips):
    try:
        # Parse input into IP networks
        networks = []
        for ip in set(ips):
            try:
                networks.append(ipaddress.ip_network(ip, strict=False))
            except ValueError as e:
                logging.warning(f"Skipping invalid IP or CIDR: {ip} ({e})")

        # Collapse adjacent or overlapping networks
        collapsed_networks = ipaddress.collapse_addresses(networks)
        summarized_networks = []

        for network in collapsed_networks:
            # Preserve existing CIDRs like /25, /24, etc., as-is
            if network.prefixlen < 28:
                summarized_networks.append(network)
            else:
                # Split /32 into smallest possible subnets without exceeding /28
                summarized_networks.extend(network.subnets(new_prefix=max(28, network.prefixlen)))

        logging.info(f"Summarized networks: {summarized_networks}")
        return summarized_networks
    except Exception as e:
        logging.error(f"Error summarizing IPs: {e}")
        return []

# Function to handle rate-limiting errors (429) and retry after waiting
def handle_rate_limit():
    wait_time = 60
    logging.warning(f"Rate limit hit. Waiting for {wait_time} seconds.")
    time.sleep(wait_time)

# Function to get CIDRs for a domain from ASN using ip.guide
def get_cidr_for_asn(asn):
    try:
        command = f'curl -sL https://ip.guide/as{asn}'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return data.get('routes', {}).get('v4', [])
        else:
            logging.error(f"Error executing curl command: {result.stderr}")
            return []
    except Exception as e:
        logging.error(f"Error retrieving CIDRs for ASN {asn}: {e}")
        return []

# Function to resolve a domain with retries and punycode support
def resolve_domain(domain):
    try:
        domain_punycode = idna_encode(domain).decode('utf-8')
        return socket.gethostbyname_ex(domain_punycode)[2]
    except Exception as e:
        logging.error(f"Could not resolve domain {domain}: {e}")
        return []

# Function to check if a domain matches COMPANY_DOMAINS and fetch CIDRs
def process_domain_for_asn(domain, processed_asns):
    asns = COMPANY_DOMAINS.get(domain, [])
    cidrs = set()
    for asn in asns:
        if asn not in processed_asns:
            processed_asns.add(asn)
            cidrs.update(get_cidr_for_asn(asn))
    return cidrs

# Function to read IPs from ip.lst
def read_ips_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return []

# Function to check if an IP is local
def is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_network(ip, strict=False)
        if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or
                ip_obj.is_reserved or ip_obj.is_unspecified or ip_obj.is_link_local):
            return True
        for cidr in LOCAL_IP_CIDRS:
            if ip_obj.version == cidr.version and ip_obj.subnet_of(cidr):
                return True
    except ValueError as e:
        logging.error(f"Invalid IP or CIDR: {ip}: {e}")
    return False

# Function to write summarized CIDRs to ipsum.lst
def write_summarized_ips(ips, filename):
    try:
        with open(filename, 'w') as f:
            for cidr in ips:
                f.write(f"{cidr}\n")
        logging.info(f"Written summarized IPs to {filename}")
    except Exception as e:
        logging.error(f"Error writing summarized IPs to file: {e}")

# Main function to process ip.lst, summarize, and add CIDRs for company domains
def main():
    reader = initialize_geoip_reader()
    ips = read_ips_from_file(IP_LST_PATH)
    ips = [ip for ip in ips if not is_local_ip(ip)]
    summarized_ips = summarize_ips(ips)

    domains = read_ips_from_file(DOMAINS_LST_PATH)
    company_cidrs = set()
    processed_asns = set()

    for domain in domains:
        company_cidrs.update(process_domain_for_asn(domain, processed_asns))

    # Merge Cloudflare's official ranges (IPv4 + IPv6) into the final list.
    cloudflare_cidrs = fetch_cloudflare_cidrs()

    final_cidrs = set(summarized_ips) | company_cidrs | set(cloudflare_cidrs)
    write_summarized_ips(final_cidrs, OUTPUT_FILE)

if __name__ == '__main__':
    main()
