#!/usr/bin/env python3

import os
import sys
import time
import requests

# Constants for Virustotal API limits
DEFAULT_SLEEP = 15
PREMIUM_SLEEP = 0

def get_api_key() -> str:
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        sys.exit("Error: Virustotal API key not set. Set it using the 'VT_API_KEY' environment variable.")
    return api_key

def get_sleep_interval() -> int:
    premium = bool(os.getenv("VT_PREMIUM", "False").lower() == "true")
    return PREMIUM_SLEEP if premium else DEFAULT_SLEEP

def build_url(domain: str) -> str:
    return f'https://www.virustotal.com/api/v3/domains/{domain}/relationships/subdomains'

def fetch_subdomains(api_url: str, api_key: str, sleep: int) -> None:
    # Recursively fetch subdomains from the Virustotal API.
    try:
        response = requests.get(api_url, headers={"x-apikey": api_key}, params={"limit": 40})
        response.raise_for_status()
        data = response.json()

        for domain in data.get("data", []):
            subdomain = domain.get("id")
            if subdomain:
                print(subdomain)
                fetch_subdomains(build_url(subdomain), api_key, sleep)
                time.sleep(sleep)

        next_url = data.get("links", {}).get("next")
        if next_url:
            fetch_subdomains(next_url, api_key, sleep)

    except requests.exceptions.RequestException as e:
        print(f"HTTP Error: {e}")
    except KeyError as e:
        print(f"Unexpected response format: Missing key {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 argveta.py <domain>")

    domain = sys.argv[1]
    api_key = get_api_key()
    sleep = get_sleep_interval()

    print(f"Starting subdomain discovery for: {domain}")
    fetch_subdomains(build_url(domain), api_key, sleep)

if __name__ == "__main__":
    main()