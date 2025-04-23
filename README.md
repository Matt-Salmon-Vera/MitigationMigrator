## Summary

This repository contains **MitigationMigrator**, a Python CLI tool that parses Veracode XML detail reports, extracts mitigation history, and applies consolidated annotations back into a Veracode application via the Veracode REST API. It supports fuzzy line-matching, single-shot annotation per flaw, and graceful handling of locked or already-approved issues.

---

## Table of Contents

- [Features](#features)
    
- [Use Cases](#use-cases)
    
- [Prerequisites](#prerequisites)
    
- Installation
    
- [API Authentication Options](#API)
    
- [Usage](#usage)
    
- [Troubleshooting](#troubleshooting)
    
- [Inspiration & Credits](#inspiration--credits)
    
- [Publishing with GitHub CLI](#publishing-with-github-cli)
    

---

## Features

- **XML parsing** of Veracode detail reports, including namespace awareness [GitHub](https://github.com/veracode/veracode-api-py?utm_source=chatgpt.com).
    
- **Layered matching** on CWE, file name, path, and line number (strict or fuzzy).
    
- **Single annotation per flaw**, preserving original submitter and timestamp.
    
- **Credential rotation** via uppercase `VERACODE_API_KEY_ID`/`SECRET` env vars.
    
- **Graceful skip** on HTTP 409 (locked issues) and on already-approved flaws.
    

---

## Use Cases

1. **Migration of historical mitigations** from legacy XML exports into modern Veracode apps.
    
2. **Automated annotation** in CI/CD pipelines to reduce manual annotation tasks.
    
3. **Audit trail consolidation**, providing one clear annotation summarising the original mitigation context.
    

---

## Prerequisites

- **Python 3.8+** installed on Linux/macOS/Windows.
    
- A **Veracode API key pair** with sufficient permissions to list findings and add annotations.
    
- **GitHub CLI** (`gh`) installed and authenticated if you plan to publish the repo [GitHub CLI](https://cli.github.com/manual/gh_repo_create?utm_source=chatgpt.com).
    

---

## Installation

1. Clone this repository (or use your own fork):
    
    bash
    
    CopyEdit
    
    `git clone https://github.com/YOUR_USER/MitigationMigrator.git cd MitigationMigrator`
    
2. Create and activate a virtual environment:
    
    bash
    
    CopyEdit
    
    `python3 -m venv venv source venv/bin/activate`
    
3. Install the required packages:
    
    bash
    
    CopyEdit
    
    `pip install -r requirements.txt`
    

---

## API 
	
Your Veracode credentials can be provided to MitigationMigrator in any of these ways:

API Credentials File
Create a file at ~/.veracode/credentials with a [default] profile:

``` ini
[default]
veracode_api_key_id     = YOUR_API_ID
veracode_api_key_secret = YOUR_API_SECRET
```

The Veracode signing library (used by veracode_api_py and veracode_api_signing) will automatically pick this up when you call get_credentials() 
Home | Veracode Docs
Home | Veracode Docs
.

Environment Variables
Export your keys as uppercase vars (Linux/macOS/UNIX):

bash
CopyEdit
export VERACODE_API_KEY_ID="YOUR_API_ID"
export VERACODE_API_KEY_SECRET="YOUR_API_SECRET"
These are also read by the signing library in preference to any file 
Home | Veracode Docs
.

Command-Line Arguments
Pass them directly to the script for one-off runs:

bash
Copy
Edit
python MitigationMigrator.py \
  -x detailedreport.xml \
  -tn "MyApp" \
  -vid YOUR_API_ID \
  -vkey YOUR_API_SECRET
These override both env vars and the credentials file.

Interactive Prompt
If you run with --prompt, the script will ask you for an application name at runtime. Credentials still come from whichever of the above methods you’ve configured first 
All Posts
.


    

---

## Usage

bash

CopyEdit

`python MitigationMigrator.py \   -x PATH/TO/detailedreport.xml \   -tn "YourAppName" \   -fm \   --debug \   [-d] \   [-po] \   [-p]`

- `-x, --xml_report` – path to the XML detail report (required).
    
- `-t, --toapp` – target application GUID (mutually exclusive with `-tn`).
    
- `-tn, --toappname` – target application name (direct lookup, non-interactive).
    
- `-p, --prompt` – interactive app selection by name.
    
- `-tsn, --tosandboxname` – optional sandbox name within the app.
    
- `-fm, --fuzzy_match` – allow ±5 line-number variance.
    
- `-d, --dry_run` – simulate without applying annotations.
    
- `-po, --propose_only` – only propose mitigation comments, no approvals.
    
- `--debug` – verbose step-by-step logging.
    

---

## Troubleshooting

- **No matches found** – enable `--debug` to see per-flaw matching decisions.
    
- **401 Unauthorized** – ensure you’ve exported uppercase `VERACODE_API_KEY_ID`/`SECRET` and that the key has correct permissions [PyPI](https://pypi.org/project/veracode-api-py/0.9.29/?utm_source=chatgpt.com).
    
- **409 Conflict (locked flaw)** – the script now skips locked issues and proceeds without error.
    

---

## Inspiration & Credits

- Built atop **veracode-api-py**, Veracode’s official Python helper library for REST APIs [GitHub](https://github.com/veracode/veracode-api-py?utm_source=chatgpt.com).
    
- Signing logic guided by the **Veracode Python HMAC Example** from Veracode’s docs [GitHub](https://github.com/veracode/veracode-python-hmac-example?utm_source=chatgpt.com).
    
- Original “Mitigation Copier” concept adapted for **single-shot annotations**.
