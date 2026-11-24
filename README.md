# OSINT Investigation Toolkit

A beginner-friendly Python desktop application for lawful Open Source Intelligence (OSINT) learning and authorized research. It performs limited lookups using publicly available DNS, RDAP, HTTP response, reverse-DNS, and IP-registration information.

## Features

- Domain and URL analysis
- Public DNS records (A, AAAA, MX, NS, TXT, CNAME)
- Domain RDAP information
- Website HTTP response metadata
- Public IP classification and reverse DNS
- Approximate public IP geolocation / ISP information
- Email syntax and public MX-record checks
- JSON and TXT report export
- Tkinter desktop GUI

## Requirements

- Kali Linux, Debian, Ubuntu, or Windows
- Python 3.10+
- Internet connection for online lookups
- Tkinter (usually included with system Python)

## Install on Kali Linux

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip python3-tk git unzip
```

Extract the ZIP, then enter the project directory:

```bash
cd ~/Downloads
unzip osint_investigation_toolkit.zip
cd osint_investigation_toolkit
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Start the application:

```bash
python main.py
```

## Windows setup

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

## Example targets

- Domain: `example.com`
- Public IP: `8.8.8.8`
- Email format/domain check: `name@example.com`

## Project structure

```text
osint_investigation_toolkit/
├── main.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── osint_toolkit/
│   ├── __init__.py
│   ├── analyzer.py
│   └── gui.py
├── logs/
└── reports/
```

## GitHub

Suggested repository name: `osint-investigation-toolkit`

```bash
git init
git add .
git commit -m "Initial OSINT Investigation Toolkit"
git branch -M main
git remote add origin https://github.com/cyber370/osint-investigation-toolkit.git
git push -u origin main
```

## Privacy and safety

This tool is designed for public-source research and education. It does not access private accounts, verify mailbox ownership, scrape private data, exploit systems, or perform password attacks. IP geolocation is approximate and may show an ISP or hosting provider rather than an individual's location. Use only against targets and data you are authorized to investigate, and follow applicable laws and service terms.
