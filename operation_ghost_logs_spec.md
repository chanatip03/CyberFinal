# Operation Ghost Logs: HMAC-Based Audit Verification & Threat Attribution

## Overview

This document specifies the two-stage Blue Team cryptography challenge and corresponding web application.

The challenge simulates a real-world SOC incident response investigation where analysts:

1. Receive a SIEM log export containing web server and authentication events from a 2-hour window.
2. Verify the log has not been tampered with using HMAC-SHA256 (brute-force the secret key from a wordlist).
3. Analyze the verified log to identify the attacker IP among multiple decoy IPs.
4. Navigate to the Threat Intelligence Portal by typing the attacker IP directly into the browser URL.
5. Decrypt an AES-256-CBC encrypted attribution profile to reveal the attacker's identity.
6. Submit the final flag.

---

# Educational Objectives

Participants will learn:
- HMAC-SHA256 — data integrity verification
- Weak secret key management — brute-forcing with a wordlist
- SIEM log analysis — identifying attacker behavior among noise
- AES-256-CBC / PBKDF2 — symmetric decryption
- Blue Team incident response and threat attribution

---

# Storyline

The KMUTT Cybersecurity Agency receives an incident report from an organization.
Their SIEM triggered alerts suggesting:

- Audit logs may have been tampered with prior to export.
- A threat actor brute-forced admin credentials on their web server.
- Sensitive financial data (`/finance/payroll.xlsx`) was accessed and downloaded.
- The attacker escalated privileges using token reuse.
- Data was exfiltrated to an external IP address.

The analyst must verify the log integrity and identify the attacker.

---

# Challenge Flow

```text
Download evidence files
    ↓
Brute-force HMAC secret → verify log integrity
    ↓
Analyze log → identify attacker IP among decoys
    ↓
Type /threat-intel/<IP> in browser URL bar
    ↓
View encrypted attribution profile
    ↓
Decrypt with recovered HMAC secret
    ↓
Submit final flag
```

---

# Stage 1: Audit Log Verification

## Files Provided

### audit.log

SIEM-style centralized log export — 2-hour window, 5 unique IPs, 40 entries.

Format:
```
[TIMESTAMP] [SEVERITY] [MODULE] SRC_IP "METHOD PATH PROTO" STATUS BYTES [NOTES]
```

**Decoy IPs in the log:**

| IP | Role |
|----|------|
| `10.0.1.45` | Internal employee — normal browsing |
| `172.16.4.12` | IT sysadmin — legitimate admin access |
| `203.0.113.5` | External user — 1 failed login then normal activity |
| `198.51.100.23` | Automated bot — port/path scanner (gets 404s) |
| `185.77.23.91` | **ATTACKER** — brute-force, data theft, exfiltration |

**Attack sequence visible in log (attacker IP: `185.77.23.91`):**
```
21:00:14  WARN  AUTH  185.77.23.91  login attempt 1 → 401
21:00:28  WARN  AUTH  185.77.23.91  login attempt 2 → 401
21:00:47  WARN  AUTH  185.77.23.91  login attempt 3 → 401
21:01:03  CRIT  AUTH  185.77.23.91  login attempt 4 → 200  [BRUTE_FORCE_SUCCESS]
21:02:18  INFO  ACCESS  185.77.23.91  /admin/dashboard → 200
21:05:01  CRIT  ACCESS  185.77.23.91  /finance/payroll.xlsx → 200 (524288 bytes)
21:07:33  CRIT  PRIVESC  185.77.23.91  token_reuse → superadmin
21:10:27  CRIT  EXFIL  185.77.23.91  bytes_out=638976  [EXFILTRATION_DETECTED]
```

### audit.log.sig

Hex-encoded HMAC-SHA256 of `audit.log`:

```
853adad62ee354b5d73ae159d6d64981df0fb844c8bc533c71c5ece61efd9187
```

### wordlist.txt

```
company2026
letmein
admin123
forensics!
SOCteam
```

Correct secret key: `forensics!`

---

## Player Objective

1. For each key in `wordlist.txt`, compute: `HMAC-SHA256(key, audit.log)`
2. Compare to `audit.log.sig` — when they match, the key is found.
3. Analyze the log — `185.77.23.91` is the only IP with brute-force + privilege escalation + exfiltration.
4. Navigate to: `http://<server>/threat-intel/185.77.23.91`

> **No form submission.** Players type the IP into the browser URL bar directly.
> Wrong IPs return a 404 page.

---

# Stage 2: Threat Intelligence Portal

## URL

```
/threat-intel/185.77.23.91
```

Visited directly by the player after identifying the attacker IP.
Any other IP returns HTTP 404.

## Displayed Content

### Threat Metadata

| Field | Value |
|-------|-------|
| IP Address | 185.77.23.91 |
| First Seen | 2026-05-16 21:00 UTC |
| ASN | AS64512 |
| Country | Unknown |
| Reputation | Critical |
| Notes | Encrypted attribution record found in threat feed |

### Encrypted Profile (AES-256-CBC, PBKDF2, OpenSSL salted)

```
U2FsdGVkX1+9j4LzJfm3vwuJ42I0dCB+R1JfOPsIFDoSXTbbZLkO/FZKAMAoijt
aSbZP7Llm+8Evi6FxS78lYpEpt6e4M4x71jLDFLPwvNOrEVRQ85PXmOZu/PK5Rqo
OjwgWJDdJJf8442rHT7G9ItoYddB9T0IRvfu8Hwi/vkJgzUY9xFwj1qTOrvlZw1S
oxQ6GapsPS6UpcYQ6r+oFt1DnTTBg4IbTEvot9odrLPV6HKXUzHJjjQk4WP27fsz
S2R5HyQMGKkLJyENTOgZBxD6SsC7q1FXf1Gc20GNZ6qphWGq87qF7yvM9Nl+r4iq
+ppYmaJh6UaS/JZt4LsuHHH4m9fu/cDZWHGQzVZhn0BA=
```

### Hint

```
Password = HMAC secret key recovered from Stage 1 (forensics!)
```

---

# Stage 2 Cryptography

- Algorithm: AES-256-CBC
- Key derivation: PBKDF2-SHA256, 10000 iterations
- Salt: embedded in ciphertext (`Salted__` header, OpenSSL format)
- Input password: `forensics!`

**OpenSSL decrypt command:**
```bash
echo "<ciphertext>" | base64 -d > enc.bin
openssl enc -d -aes-256-cbc -pbkdf2 -in enc.bin -pass pass:forensics!
```

---

# Decrypted Threat Profile

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

---

# Final Flag

```
flag{ghost_logs_led_to_threat_attribution}
```

---

# Web Application Architecture

## Website 1: Evidence Portal (`/`)

- Incident summary with threat timeline
- SIEM log context — 5 IPs described (4 known, 1 unknown/attacker)
- Downloadable evidence files: `audit.log`, `audit.log.sig`, `wordlist.txt`
- HMAC-SHA256 objectives and Python hint
- Instruction: *"Type the attacker IP into your browser: `/threat-intel/<IP>`"*
- Scoring table

## Website 2: Threat Intelligence Portal (`/threat-intel/<ip>`)

- Shows threat metadata for `185.77.23.91` only
- Displays encrypted blob with copy button
- Decryption instructions (OpenSSL + Python)
- Flag submission field
- On correct flag: reveals attacker profile JSON + Leaflet.js map of Bucharest

---

# Flask Route Specification

| Method | Route | Action |
|--------|-------|--------|
| GET | `/` | Render Evidence Portal |
| GET | `/threat-intel/<ip>` | Render threat profile if IP matches; else 404 |
| POST | `/submit-flag` | Validate flag → JSON response |
| GET | `/download/<file>` | Serve challenge files |

> No `/submit-ip` route. IP navigation is done via browser URL bar.

---

# Folder Structure

```
operation-ghost-logs/
├── app.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── templates/
│   ├── index.html
│   ├── threat_intel.html
│   └── 404.html
├── static/
│   ├── style.css
│   ├── leaflet.js       ← bundled locally (no CDN)
│   └── leaflet.css      ← bundled locally (no CDN)
└── challenge/
    ├── audit.log
    ├── audit.log.sig
    ├── wordlist.txt
    └── encrypted_profile.txt
```

---

# Docker Deployment

```bash
# Build and start
docker compose up -d --build

# Access
http://localhost:5000

# Stop
docker compose down
```

The application is fully self-contained — no external API calls required for core challenge functionality.
Leaflet.js is bundled locally. Only Google Fonts loads from CDN (cosmetic, not required).

---

# Step-by-Step Player Walkthrough

## Step 1
Download `audit.log`, `audit.log.sig`, `wordlist.txt`.

## Step 2
For each key in `wordlist.txt`, compute HMAC-SHA256:
```python
import hmac, hashlib
key = "forensics!"
data = open("audit.log","rb").read()
print(hmac.new(key.encode(), data, hashlib.sha256).hexdigest())
```

## Step 3
Compare to `audit.log.sig`. Matching key = `forensics!`

## Step 4
Analyze the log. `185.77.23.91` is the only IP with:
- 3 failed logins → successful brute-force
- Access to `/finance/payroll.xlsx`
- PRIVESC via token_reuse
- EXFIL with 638976 bytes out

## Step 5
Type in browser: `http://<server>/threat-intel/185.77.23.91`

## Step 6
Decrypt the encrypted profile using password `forensics!`.

## Step 7
Submit: `flag{ghost_logs_led_to_threat_attribution}`

---

# Concepts Covered

- HMAC-SHA256 — data integrity, MAC brute-force
- SIEM log analysis — signal vs. noise, decoy IPs
- AES-256-CBC + PBKDF2 — symmetric decryption
- Incident response — attacker attribution

---

# Difficulty Level

Intermediate.

Suitable for students with basic knowledge of Python, HMAC, and command-line tools.

---

# Estimated Completion Time

- Stage 1: 15–20 minutes
- Stage 2: 10–15 minutes
- Total: 25–35 minutes

---

# Scoring

| Task | Points |
|------|-------:|
| Recover HMAC secret key | 10 |
| Identify attacker IP | 5 |
| Decrypt attribution profile | 5 |
| Submit correct final flag | 5 |
| **Total** | **25** |

---

# Recommended Title

## Operation Ghost Logs: From Log Integrity to Threat Attribution
