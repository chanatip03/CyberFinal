# 🛡️ Operation Ghost Logs

> **A Blue Team CTF challenge — Incident Response, Log Analysis & Threat Attribution**
> Developed by KMUTT Cybersecurity Agency (KMUTT-CSA)

---

## Overview

**Operation Ghost Logs** is a realistic Blue Team cybersecurity challenge designed for students and security enthusiasts. Players take the role of a SOC analyst responding to a live incident — verifying SIEM log integrity, identifying a threat actor buried among decoy traffic, and decrypting an encrypted attribution profile.

| Property | Detail |
|---|---|
| **Difficulty** | Intermediate |
| **Estimated Time** | 25–40 minutes |
| **Max Points** | 25 |
| **Skills Required** | HMAC-SHA256, log analysis, AES-256-CBC decryption |
| **Technology** | Python Flask, Docker |

---

## Quick Start (Deploy with Docker)

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- Port `5000` available on your machine

### 1. Clone / Download the Project

```bash
# If using git
git clone <repository-url>
cd CyberFinal_1

# Or extract the zip and open a terminal in the folder
```

### 2. Build and Start

```bash
docker compose up -d --build
```

### 3. Access the Challenge

Open your browser and navigate to:

```
http://localhost:5000
```

### 4. Stop the Challenge

```bash
docker compose down
```

### Other Useful Commands

```bash
# View live logs
docker logs ghost-logs-app -f

# Restart without rebuilding
docker compose restart

# Rebuild after code changes
docker compose up -d --build
```

---

## Project Structure

```
CyberFinal_1/
├── app.py                          # Flask application
├── requirements.txt                # Python dependencies
├── Dockerfile                      # Container build instructions
├── docker-compose.yml              # Container orchestration
├── .dockerignore
│
├── templates/
│   ├── index.html                  # Stage 1 — Evidence portal
│   ├── threat_intel.html           # Decoy store page (disguised)
│   ├── threat_intel_archive.html   # Hidden archive (found via robots.txt)
│   ├── threat_intel_submit.html    # Hidden flag submission page
│   └── 404.html                    # 404 page
│
├── static/
│   ├── style.css                   # Main stylesheet
│   ├── leaflet.js                  # Map library (bundled locally)
│   └── leaflet.css
│
├── challenge/
│   ├── audit.log                   # SIEM log export (evidence)
│   ├── audit.log.sig               # HMAC-SHA256 signature
│   ├── wordlist.txt                # Candidate HMAC secret keys
│   └── encrypted_profile.txt      # AES-256-CBC encrypted attacker profile
│
├── operation_ghost_logs_spec.md    # Full technical specification
└── README.md                       # This file
```

---

## Challenge Walkthrough (Full Solution)

> ⚠️ **Instructor / Marker Reference Only** — Do not share with students before they attempt the challenge.

---

### Step 1 — Read the Briefing

When you open `http://localhost:5000`, a briefing modal appears from the SOC Team Lead:

> *"Earlier today, our SIEM flagged suspicious activity. Someone broke into the admin account and went straight for the financial database. A significant amount of data was sent to an unknown external address. Go through those logs carefully and track them down."*

Click **"Understood — Begin Investigation"** to proceed.

---

### Step 2 — Download the Evidence Files

On the Evidence Portal, download all three files:

| File | Purpose |
|---|---|
| `audit.log` | SIEM export — 59 events, 5 IPs, 2-hour window |
| `audit.log.sig` | HMAC-SHA256 hex digest to verify log integrity |
| `wordlist.txt` | 5 candidate secret keys |

---

### Step 3 — Verify the Log (HMAC-SHA256 Brute-Force)

The log must be verified before it can be trusted as evidence.

**Goal:** Find which key in `wordlist.txt` produces a digest matching `audit.log.sig`.

Run this Python script:

```python
import hmac, hashlib

sig = open("audit.log.sig").read().strip()
data = open("audit.log", "rb").read()

with open("wordlist.txt") as f:
    for line in f:
        key = line.strip()
        digest = hmac.new(key.encode(), data, hashlib.sha256).hexdigest()
        print(f"{key}: {digest}")
        if digest == sig:
            print(f"\n✅ MATCH FOUND! Secret key = '{key}'")
            break
```

**Result:**

```
company2026: <no match>
letmein:     <no match>
admin123:    <no match>
forensics!:  f8dd6d048d1308c95a757f700b5ffaae418e93dd736be98612e5cf2774001960  ✅ MATCH
```

> **✅ Secret Key = `forensics!`** (10 points)

---

### Step 4 — Analyze the Log

Open `audit.log` and look for the attacker. The log has 5 unique IPs:

| IP | Role |
|---|---|
| `10.0.1.45` | Internal employee (sarah.m) — normal HR, document downloads |
| `172.16.4.12` | IT sysadmin — legitimate admin tasks, scheduled maintenance |
| `203.0.113.5` | External customer (jsmith) — orders, profile, 1 expired session |
| `198.51.100.23` | Automated scanner/bot — probing common paths, all 404/403 |
| `185.77.23.91` | **THE ATTACKER** |

**The attacker sequence (look for these tags):**

```
[21:00:14] WARN   AUTH  185.77.23.91  login attempt 1 → 401
[21:00:28] WARN   AUTH  185.77.23.91  login attempt 2 → 401
[21:00:47] WARN   AUTH  185.77.23.91  login attempt 3 → 401
[21:01:03] CRIT   AUTH  185.77.23.91  login attempt 4 → 200  [BRUTE_FORCE_SUCCESS]
[21:01:44] INFO   ACCESS 185.77.23.91 /admin/dashboard
[21:02:55] WARN   ACCESS 185.77.23.91 /admin/users         [SENSITIVE_ENDPOINT]
[21:03:42] WARN   ACCESS 185.77.23.91 /admin/audit-trail   [RECON]
[21:05:01] CRIT   ACCESS 185.77.23.91 /finance/payroll.xlsx [SENSITIVE_FILE_ACCESS]
[21:07:33] CRIT   PRIVESC 185.77.23.91 token_reuse → superadmin [PRIVILEGE_ESCALATION]
[21:09:00] CRIT   ACCESS 185.77.23.91 /admin/db/export     [DATA_EXPORT]
[21:10:27] CRIT   EXFIL  185.77.23.91 bytes_out=638976     [EXFILTRATION_DETECTED]
[21:12:44] INFO   AUTH   185.77.23.91 DELETE /session      [SESSION_REVOKED]
```

> **✅ Attacker IP = `185.77.23.91`**

---

### Step 5 — Navigate to the Threat Intel Page

In your browser address bar, type:

```
http://localhost:5000/threat-intel/185.77.23.91
```

> ⚠️ This page looks like a **fake online store** ("GhostFox Supplies Co."). This is intentional — it is a disguise. Do not be fooled.

---

### Step 6 — Find the Hidden Archive (via robots.txt)

Look at the page source (`Ctrl+U`) or check `robots.txt`:

```
http://localhost:5000/robots.txt
```

You will see:

```
Disallow: /threat-intel/185.77.23.91/archive
Disallow: /threat-intel/185.77.23.91/submit
```

Navigate to the **archive page**:

```
http://localhost:5000/threat-intel/185.77.23.91/archive
```

This reveals the **encrypted attribution profile** (AES-256-CBC, OpenSSL salted format).

> **✅ IP identified + archive found** (5 points)

---

### Step 7 — Decrypt the Attribution Profile

Copy the ciphertext from the archive page.

**Method A — OpenSSL (recommended):**

```bash
# Paste the ciphertext into a text file, then:
echo "<paste ciphertext here>" | base64 -d > enc.bin
openssl enc -d -aes-256-cbc -pbkdf2 -in enc.bin -pass pass:forensics!
```

**Method B — Python:**

```python
import base64, hashlib
from Crypto.Cipher import AES

password = b"forensics!"
ct = base64.b64decode(open("enc.bin", "rb").read())

# Strip OpenSSL header: "Salted__" (8 bytes) + salt (8 bytes)
salt = ct[8:16]
data = ct[16:]

# PBKDF2 key derivation
key_iv = hashlib.pbkdf2_hmac("sha256", password, salt, 10000, 48)
key, iv = key_iv[:32], key_iv[32:]

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(data)
# Remove PKCS7 padding
print(plaintext[:-plaintext[-1]].decode())
```

**Decrypted result:**

```json
{
  "attacker_handle": "ghostfox",
  "email": "ghostfox@protonmail.com",
  "country": "Romania",
  "city": "Bucharest",
  "last_known_lat": 44.4268,
  "last_known_lon": 26.1025,
  "final_flag": "flag{ghost_logs_led_to_threat_attribution}"
}
```

> **✅ Profile decrypted** (5 points)

---

### Step 8 — Submit the Final Flag

Navigate to the submission page (also found in `robots.txt`):

```
http://localhost:5000/threat-intel/185.77.23.91/submit
```

Enter the flag:

```
flag{ghost_logs_led_to_threat_attribution}
```

A success message appears, along with the revealed attacker profile and a Leaflet map pinpointing **Bucharest, Romania** — the attacker's last known location.

> **✅ Flag submitted — Case closed!** (5 points)

---

## Answer Sheet (Quick Reference)

| Step | Answer |
|---|---|
| HMAC Secret Key | `forensics!` |
| Attacker IP | `185.77.23.91` |
| Hidden archive path | `/threat-intel/185.77.23.91/archive` |
| Decryption password | `forensics!` (same as HMAC key) |
| Attacker handle | `ghostfox` |
| Attacker location | Bucharest, Romania |
| Final Flag | `flag{ghost_logs_led_to_threat_attribution}` |

---

## Scoring

| Objective | Points |
|---|---:|
| Recover HMAC secret key via brute-force | 10 |
| Identify attacker IP and access threat intel | 5 |
| Decrypt the attribution profile | 5 |
| Submit the correct final flag | 5 |
| **Total** | **25** |

---

## Concepts Covered

- **HMAC-SHA256** — log integrity verification, MAC brute-force
- **SIEM log analysis** — distinguishing malicious vs. benign traffic
- **Web reconnaissance** — reading `robots.txt`, inspecting page source, hidden routes
- **AES-256-CBC + PBKDF2** — symmetric decryption of OpenSSL-encrypted data
- **Incident response** — threat attribution and case closure

---

## Instructor Notes

- The challenge is fully **self-contained** — no external API calls required for core functionality
- Leaflet.js is bundled locally (`/static/leaflet.js`) — works in air-gapped networks
- The only external dependency is **Google Fonts** (cosmetic — challenge works without it)
- To reset, simply run `docker compose down && docker compose up -d --build`
- The HMAC signature in `audit.log.sig` must match the content of `audit.log` exactly — do not edit the log without regenerating the signature

**Regenerate HMAC signature after editing `audit.log`:**

```python
import hmac, hashlib
secret = b"forensics!"
data = open("challenge/audit.log", "rb").read()
sig = hmac.new(secret, data, hashlib.sha256).hexdigest()
open("challenge/audit.log.sig", "w").write(sig)
print(sig)
```

---

*KMUTT Cybersecurity Agency — Operation Ghost Logs — Blue Team Challenge*
