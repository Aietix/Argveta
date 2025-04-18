#!/usr/bin/env python3

import os
import csv
import json
import time
import logging
import argparse
import requests
from requests.exceptions import RequestException, Timeout, HTTPError, ConnectionError

# Global set to store discovered records
discovered_subdomains = set()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(description="VirusTotal Subdomain Enumerator")

    parser.add_argument(
        "domain", 
        help="Domain to enumerate subdomains for"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file to save subdomains (default: <domain>.<format>)",
        default=None
    )
    parser.add_argument(
        "-f", "--format",
        help="Output format (csv, json, txt). Default: json",
        choices=["csv", "json", "txt"],
        default="csv"
    )
    parser.add_argument(
        "-s", "--sleep",
        help="Time delay (in seconds) between API requests. Default: 15s",
        type=int,
        default=15
    )

    args = parser.parse_args()

    if args.output is None:
        args.output = f"{args.domain}.{args.format}"

    return args


def get_api_key() -> str:
    key = os.getenv("VT_API_KEY")
    if not key:
        logger.error("No API key found. Please set the VT_API_KEY environment variable.")
        exit(1)
    return key


def build_url(domain: str) -> str:
    return f'https://www.virustotal.com/api/v3/domains/{domain}/relationships/subdomains'


def save_results(filename, output_format):
    if not discovered_subdomains:
        print("No subdomains found to save.")
        return

    if output_format == "json":
        with open(filename, "w") as f:
            json.dump(sorted(discovered_subdomains), f, indent=4)
    elif output_format == "csv":
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Subdomain"])
            for sub in sorted(discovered_subdomains):
                writer.writerow([sub])
    elif output_format == "txt":
        with open(filename, "w") as f:
            f.write("\n".join(sorted(discovered_subdomains)))

    print(f"\nResults saved to {filename}")


def filter_subdomains(data):
    global discovered_subdomains

    # Extract subdomains from API data
    data_subdomains = {entry["id"] for entry in data.get("data", [])}
    new_subs = list(data_subdomains - discovered_subdomains)
    # Record all seen
    discovered_subdomains.update(new_subs)

    # Next page link if present
    next_url = data.get("links", {}).get("next")
    return new_subs, next_url


def fetch_subdomains(domain: str, api_url: str, api_key: str, sleep_delay: int) -> None:
    try:
        headers = {"x-apikey": api_key}
        response = requests.get(api_url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            subs, next_url = filter_subdomains(data)

            for sub in subs:
                print(sub)
                time.sleep(sleep_delay)
                fetch_subdomains(sub, build_url(sub), api_key, sleep_delay)

            if next_url:
                fetch_subdomains(domain, next_url, api_key, sleep_delay)

        elif response.status_code == 401:
            logger.error("API key is invalid or expired. Please check your VT_API_KEY.")
            return
        elif response.status_code == 429:
            logger.error("Rate limit exceeded. Try increasing the --sleep value or retry later.")
            return
        else:
            response.raise_for_status()

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


def main():
    args = parse_args()
    api_key = get_api_key()

    print(f"Starting subdomain discovery for: {args.domain}")
    print(f"Output file: {args.output}")

    fetch_subdomains(args.domain, build_url(args.domain), api_key, args.sleep)
    save_results(args.output, args.format)


if __name__ == "__main__":
    main()
