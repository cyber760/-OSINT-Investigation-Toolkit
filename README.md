## OSINT Investigation Toolkit

A Python-based Open Source Intelligence (OSINT) toolkit designed for cybersecurity research, public information gathering, and digital footprint analysis.

### Features
- Domain information lookup
- DNS record analysis
- IP address intelligence
- WHOIS information lookup
- Email domain analysis
- Public website metadata extraction
- Social media public-profile research
- Investigation report generation
- Export results to JSON and TXT

### Technology Stack
- Python 3
- Kali Linux
- Requests
- BeautifulSoup
- DNSPython
- WHOIS
- Git

### Installation (Kali Linux)

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git whois dnsutils
```

### Setup

```bash
git clone https://github.com/cyber370/osint-investigation-toolkit.git
cd osint-investigation-toolkit

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

### Run

```bash
python3 main.py
```

### Developer
Jatin Kumar

GitHub: https://github.com/cyber370

### Disclaimer
For educational purposes, authorized security research, and analysis of publicly available information. Respect privacy, applicable laws, and website terms of service.
unzip osint_investigation_toolkit.zip
cd osint_investigation_toolkit
Create and activate a virtual environment:

Bash
python3 -m venv .venv
source .venv/bin/activate
Install dependencies:

Bash
python -m pip install --upgrade pip
pip install -r requirements.txt
Start the application:

Bash
python main.py
Windows setup
PowerShell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
Example targets
Domain: example.com

Public IP: 8.8.8.8

Email format/domain check: name@example.com

Project structure
Plaintext
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
GitHub
Suggested repository name: osint-investigation-toolkit

Bash
git init
git add .
git commit -m "Initial OSINT Investigation Toolkit"
git branch -M main
git remote add origin [https://github.com/cyber370/osint-investigation-toolkit.git](https://github.com/cyber370/osint-investigation-toolkit.git)
git push -u origin main
Privacy and safety
This tool is designed for public-source research and education. It does not access private accounts, verify mailbox ownership, scrape private data, exploit systems, or perform password attacks. IP geolocation is approximate and may show an ISP or hosting provider rather than an individual's location. Use only against targets and data you are authorized to investigate, and follow applicable laws and service terms.
''',
"LICENSE": r'''
MIT License

Copyright (c) 2026 Jatin Kumar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
''',
".gitignore": r'''
.venv/
venv/
pycache/
.py[cod]
.env
reports/
!reports/.gitkeep
logs/*
!logs/.gitkeep
.DS_Store
''',
"reports/.gitkeep": "",
"logs/.gitkeep": "",
}
for rel, content in files.items():
p = base / rel
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")

zip_path = pathlib.Path("osint_investigation_toolkit.zip")
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
for p in base.rglob("*"):
if p.is_file():
z.write(p, p.relative_to(base.parent))
print(f"Created: {zip_path} ({zip_path.stat().st_size:,} bytes)")


```text?code_stdout&code_event_index=1
Created: osint_investigation_toolkit.zip (7,932 bytes)

Your ZIP file is ready:


osint_investigation_toolkit
 ZIP 
Included Project Structure
main.py — Entry point to launch the GUI application

requirements.txt — Dependencies (requests, dnspython)

osint_toolkit/ — Core package containing __init__.py, analyzer.py, and gui.py

README.md & LICENSE — Documentation and MIT license

.gitignore, reports/, and logs/ — Project folders and Git configuration

Quick Start
Extract osint_investigation_toolkit.zip and open the folder in your terminal.

Install dependencies:

Bash
pip install -r requirements.txt
Run the toolkit:

Bash
python main.py
