#!/usr/bin/env python3

import os
import csv
import json
import time
import logging
import argparse
import requests
from requests.exceptions import RequestException, Timeout, HTTPError, ConnectionError


# Store discovered subdomains to prevent duplicates
discovered_subdomains = set()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def parse_args():
    """Parse command-line arguments using argparse."""
    parser = argparse.ArgumentParser(description="VirusTotal Subdomain Enumerator")

    parser.add_argument(
        "domain", 
        help="Domain to enumerate subdomains for"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file to save subdomains (default: subdomains.json)",
        default="subdomains.json"
    )
    parser.add_argument(
        "-f", "--format",
        help="Output format (json, csv, txt). Default: json",
        choices=["json", "csv", "txt"],
        default="csv"
    )
    parser.add_argument(
        "-s", "--sleep",
        help="Time delay (in seconds) between API requests. Default: 15s",
        type=int,
        default=15
    )

    return parser.parse_args()

def get_api_keys() -> list:
    api_keys = os.getenv("VT_API_KEYS", "")
    return api_keys.split(",") if api_keys else []

def build_url(domain: str) -> str:
    return f'https://www.virustotal.com/api/v3/domains/{domain}/relationships/subdomains'

def save_results(filename, output_format):
    """Save discovered subdomains to a specified file format."""
    if not discovered_subdomains:
        print("No subdomains found to save.")
        return

    if output_format == "json":
        with open(filename, "w") as f:
            json.dump(list(discovered_subdomains), f, indent=4)
    elif output_format == "csv":
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Subdomain"])
            writer.writerows([[subdomain] for subdomain in discovered_subdomains])
    elif output_format == "txt":
        with open(filename, "w") as f:
            f.write("\n".join(discovered_subdomains))

    print(f"\n✅ Results saved to {filename}")


def fetch_subdomains(api_url: str, api_keys: list) -> None:
    try:
        if api_keys:
            response = requests.get(api_url, headers={"x-apikey": api_keys[0]}, params={"limit": 40}, timeout=10)

            if response.status_code == 200:
                data = response.json()
                for domain in data.get("data", []):
                    subdomain = domain.get("id")
                    if subdomain:
                        discovered_subdomains.add(subdomain)
                        print(subdomain)
                        fetch_subdomains(build_url(subdomain), api_keys)
                        time.sleep(15)

                next_url = data.get("links", {}).get("next")
                if next_url:
                    fetch_subdomains(next_url, api_keys)

            if response.status_code == 401:
                print(f"API key is invalid or expired, Removing and switching to the next key.")
                api_keys.pop(0)
                fetch_subdomains(api_url, api_keys)
                return
            
            if response.status_code == 429:
                print(f"API key is rate-limited, Removing and switching to the next key.")
                api_keys.pop(0)
                fetch_subdomains(api_url, api_keys)
                return
                
            response.raise_for_status()
        else:
            print("No API keys available to make requests.")

    except Timeout:
        logger.error("Request timed out")
    except HTTPError as e:
        logger.error(f"HTTP error occurred: {e}")
    except ConnectionError:
        logger.error("Connection error occurred")
    except RequestException as e:
        logger.error(f"Request error: {e}")
    except ValueError as e:
        logger.error(f"Invalid JSON response: {e}")
        
    return None


def main():
    args = parse_args()
    if not args.domain:
        print("Please provide a domain to enumerate subdomains for.")
        return
    
    print(f"Starting subdomain discovery for: {args.domain}")
    fetch_subdomains(build_url(args.domain), get_api_keys())
    save_results(args.output, args.format)


if __name__ == "__main__":
    main()
