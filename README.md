# Argveta: VirusTotal Subdomain Finder

This Python script uses the VirusTotal API to recursively fetch subdomains of a given domain. It is designed to help security researchers discover subdomains.

## ⚙️ Requirements

- Python 3.x
- `requests` Python library
- VirusTotal API Key

## 🚀 Installation

1. Clone this repository:

    ```bash
    git clone https://github.com/yourusername/argveta.git
    cd argveta
    ```

2. Install the required dependencies:

    ```bash
    pip install requests
    ```

## 🔑 Setup

1. Obtain an API key from [VirusTotal](https://www.virustotal.com/).
2. Set the API key as an environment variable:

    ```bash
    export VT_API_KEYS='api_key1,api_key2'
    ```

### **CLI Options**
| Option        | Description                                   | Default          |
|--------------|-----------------------------------------------|------------------|
| `domain`     | The target domain to find subdomains for     | **Required**     |
| `-o, --output` | Output file to save results                 | `subdomains.json` |
| `-f, --format` | Output format (`json`, `csv`, `txt`)        | `csv`            |
| `-s, --sleep`  | Time delay (in seconds) between API requests | `15`             |

## 🛠️ Usage

Run the script with the target domain:

```bash
python3 argveta.py <domain>
```


## 🧪 Example

To discover subdomains for example.com, run:

  ```
  python3 argveta.py example.com
  ```

The script will output the discovered subdomains directly in the terminal:

  ```
  Starting subdomain discovery for: example.com
  sub1.example.com
  sub2.example.com
  sub3.sub2.example.com
  ...
  ```

## ⚠️ Notes
```
**Free users** have a limited request quota (**4 lookups per minute, 500 per day**).  
**Premium users** have higher rate limits but still need to avoid excessive requests.
** VirusTotal suggests avoiding the use of multiple API keys. However, if you do, the script will automatically switch keys when rate limits are reached. 🤷‍♂️

```

