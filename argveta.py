#!/usr/bin/env python3
import sys
import time
import json
import requests


# Argveta - Discovering subdomains recursively using Virustotal API
# Virustotal Public API is limited to 500 requests per day and a rate of 4 requests per minute.
# The Premium API does not have request rate or daily allowance limitations
# If you have a premium account change vt_premium = False as vt_premium = True


# API key
api_key = ''
premium = False
sleep = 20 if not premium else 0


if api_key == '':
    sys.exit(print('Please add Virusttotal API key'))

if len(sys.argv) == 1:
    sys.exit(print('Usage: python3 argveta.py example.com'))


def url(domain: str) -> str:
    return f'https://www.virustotal.com/api/v3/domains/{domain}/relationships/subdomains'
    

def get_domains(api_url: str) -> None:

    try:
        response = requests.get(api_url, headers = {'x-apikey': api_key}, params = {'limit': 40})
        json_data = response.json()
        
        for domain in json_data['data']:
            print(domain['id'])
            get_domains(url(domain['id']))
            time.sleep(sleep)
        
        if 'next' in json_data['links']:
            get_domains(json_data['links']['next'])   

    except Exception as e:
      print(f'Error: {e}')


get_domains(url(sys.argv[1]))
