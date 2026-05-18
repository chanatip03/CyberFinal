from flask import Flask, render_template, send_from_directory, request, jsonify, Response
import os

app = Flask(__name__)

CORRECT_IP = "185.77.23.91"
CORRECT_FLAG = "flag{ghost_logs_led_to_threat_attribution}"
CHALLENGE_DIR = os.path.join(os.path.dirname(__file__), "challenge")

ENCRYPTED_PROFILE = open(os.path.join(CHALLENGE_DIR, "encrypted_profile.txt")).read().strip()

THREAT_META = {
    "first_seen": "2026-05-16 21:00 UTC",
    "asn": "AS64512",
    "country": "Unknown",
    "reputation": "Critical",
    "notes": "Encrypted attribution record found in threat feed"
}


@app.route("/")
def index():
    return render_template("index.html")


# /robots.txt — standard crawler policy file; first recon step for players
@app.route("/robots.txt")
def robots_txt():
    content = """User-agent: *
Disallow: /

# Security policy: /.well-known/security.txt
"""
    return Response(content, mimetype="text/plain")


# /.well-known/security.txt — RFC 9116 standard, security researchers always check this
@app.route("/.well-known/security.txt")
def security_txt():
    content = """Contact: soc@kmutt-csa.internal
Expires: 2027-01-01T00:00:00.000Z
Preferred-Languages: th, en
Canonical: https://cyberfinal-5myd.onrender.com/.well-known/security.txt

# Internal audit note (do not publish externally):
# Case document archive: /threat-intel/185.77.23.91/archive
# Analyst submission endpoint: /threat-intel/185.77.23.91/submit
# Access restricted to authorised SOC personnel only.
"""
    return Response(content, mimetype="text/plain")


# /site-policy — backup alias linked from the store footer
@app.route("/site-policy")
def site_policy():
    content = """GhostFox Supplies Co. — Site Policy
=====================================
This site complies with standard web crawler policies.
For security disclosures, see: /.well-known/security.txt

Restricted sections (internal use only):
  /threat-intel/185.77.23.91/archive
  /threat-intel/185.77.23.91/submit

Unauthorised access to restricted sections is prohibited.
"""
    return Response(content, mimetype="text/plain")


# Main threat intel page — disguised as a normal store
@app.route("/threat-intel/<ip>")
def threat_intel(ip):
    if ip != CORRECT_IP:
        return render_template("404.html"), 404
    return render_template("threat_intel.html", ip=ip)


# Hidden archive page — contains the encrypted profile
@app.route("/threat-intel/<ip>/archive")
def threat_intel_archive(ip):
    if ip != CORRECT_IP:
        return render_template("404.html"), 404
    return render_template(
        "threat_intel_archive.html",
        ip=ip,
        encrypted_profile=ENCRYPTED_PROFILE,
    )


# Hidden submit page — flag submission form
@app.route("/threat-intel/<ip>/submit")
def threat_intel_submit(ip):
    if ip != CORRECT_IP:
        return render_template("404.html"), 404
    return render_template("threat_intel_submit.html", ip=ip)


# Flag validation endpoint
@app.route("/submit-flag", methods=["POST"])
def submit_flag():
    flag = request.form.get("flag", "").strip()
    if flag == CORRECT_FLAG:
        return jsonify({"success": True, "message": "Operation complete. Attacker attributed: ghostfox / Bucharest, Romania."})
    return jsonify({"success": False, "message": "Incorrect. Keep investigating."})


# Evidence file downloads
@app.route("/download/<filename>")
def download(filename):
    allowed = {"audit.log", "audit.log.sig", "wordlist.txt"}
    if filename not in allowed:
        return "Not found", 404
    return send_from_directory(CHALLENGE_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
