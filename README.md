# Argveta: VirusTotal Subdomain Finder

This Python script uses the VirusTotal API to recursively fetch subdomains of a given domain. It is designed to help security researchers discover subdomains.

## ⚙️ Requirements

- Python 3.x
- `requests` Python library

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
    export VT_API_KEY='your_api_key'
    ```

3. If you are using a VirusTotal Premium account, set the `VT_PREMIUM` environment variable:

    ```bash
    export VT_PREMIUM=true
    ```

## 🛠️ Usage

Run the script with the target domain as a command-line argument:

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
Free users: 4 lookups / min, with a daily limit of 500 requests.
```

