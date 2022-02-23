# Argveta
**Argveta - Discovering subdomains recursively using  Virustotal API**  

Add Virustotal API key: **api_key = 'XXXXXXXXXXXX'** \
If you have a premium account change **vt_premium = False** as **vt_premium = True** 

Virustotal Public API is limited to 500 requests per day and a rate of 4 requests per minute. \
The Premium API does not have request rate or daily allowance limitations 

**Usage:**  python3 argveta.py google.com

**Result:**
1 | 2 | 3  | 4 | 5
------------ | ------------- | ------------- | ------------- | -------------
google.com | play.google.com | c.play.google.com | redirector.c.play.google.com | ***

\
This script was written in 20 minutes, I hope I will make changes in the future ...
