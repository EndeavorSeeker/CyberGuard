def img_analyse(file):
    if file:
        return True
    else:
        return False
# ============================================================
# CYBERGUARD AI — FINAL VERSION 🔥
# ============================================================

from PIL import Image
from pyzbar.pyzbar import decode
import hashlib
import requests
import os

# ============================================================
# CONFIG
# ============================================================

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


# ============================================================
# SHA256
# ============================================================

def generate_sha256(filepath):

    sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:
        for block in iter(lambda: f.read(4096), b''):
            sha256.update(block)

    return sha256.hexdigest()


# ============================================================
# IMAGE VALIDATION
# ============================================================

def check_real_image(filepath):

    score = 0
    details = []

    try:
        img = Image.open(filepath)
        img.verify()
        details.append("Valid image format")

    except Exception:
        score += 80
        details.append("Fake or corrupted image")

    return score, details


# ============================================================
# PAYLOAD DETECTION
# ============================================================

def check_embedded_payload(filepath):

    score = 0
    details = []

    with open(filepath, 'rb') as f:
        data = f.read()

    if data.startswith(b'MZ'):
        score += 90
        details.append("Executable disguised as image")

    if b'<script' in data.lower():
        score += 30
        details.append("Script pattern detected")

    return score, details


# ============================================================
# STEGANOGRAPHY
# ============================================================

def detect_steganography(filepath):

    score = 0
    details = []

    try:
        size = os.path.getsize(filepath)
        img = Image.open(filepath)

        width, height = img.size
        estimated = width * height * 3

        if size > estimated * 2:
            score += 25
            details.append("Possible hidden data")

    except Exception as e:
        details.append(f"Stego error: {e}")

    return score, details


# ============================================================
# VIRUSTOTAL UPLOAD
# ============================================================

def upload_to_virustotal(filepath):

    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        with open(filepath, "rb") as f:
            files = {"file": f}
            response = requests.post(url, files=files, headers=headers)

        if response.status_code == 200:
            return "Uploaded for analysis"
        else:
            return f"Upload failed: {response.status_code}"

    except Exception as e:
        return f"Upload error: {e}"


# ============================================================
# VIRUSTOTAL CHECK
# ============================================================

def check_virustotal(filepath):

    score = 0
    details = []

    if not VIRUSTOTAL_API_KEY:
        details.append("VirusTotal: API key not set")
        return score, details

    try:

        file_hash = generate_sha256(filepath)
        details.append(f"SHA256: {file_hash}")

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        response = requests.get(url, headers=headers)

        if response.status_code == 200:

            stats = response.json()["data"]["attributes"]["last_analysis_stats"]

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            details.append(
                f"VirusTotal: {malicious} malicious / {suspicious} suspicious"
            )

            if malicious > 0:
                score += 80
                details.append("MALWARE DETECTED")

            elif suspicious > 0:
                score += 40
                details.append("Suspicious file")

            else:
                details.append("VirusTotal clean")

        elif response.status_code == 404:

            details.append("VirusTotal: File unknown")
            details.append(upload_to_virustotal(filepath))

        elif response.status_code == 401:
            details.append("VirusTotal: Invalid API key")

        else:
            details.append(f"VirusTotal error: {response.status_code}")

    except Exception as e:
        details.append(f"VirusTotal error: {e}")

    return score, details


# ============================================================
# QR ANALYSIS
# ============================================================

def analyse_url(url):

    score = 0
    details = []

    suspicious = ["bit.ly", "tinyurl", "grabify", "ngrok"]

    for d in suspicious:
        if d in url.lower():
            score += 40
            details.append(f"Suspicious domain: {d}")

    if not url.startswith("https://"):
        score += 20
        details.append("Non-HTTPS URL")

    return score, details


def check_qr_codes(filepath):

    score = 0
    details = []

    try:
        img = Image.open(filepath)
        qr_codes = decode(img)

        if qr_codes:

            details.append("QR code detected")

            for qr in qr_codes:

                data = qr.data.decode('utf-8')
                details.append(f"QR Content: {data}")

                if "http" in data.lower():
                    s, d = analyse_url(data)
                    score += s
                    details.extend(d)

        else:
            details.append("No QR codes found")

    except Exception as e:
        details.append(f"QR error: {e}")

    return score, details


# ============================================================
# MAIN ENGINE
# ============================================================

def analyze_image(filepath):

    score = 0
    details = []

    try:

        details.append(f"File: {os.path.basename(filepath)}")

        for func in [
            check_real_image,
            check_embedded_payload,
            detect_steganography,
            check_qr_codes,
            check_virustotal
        ]:
            s, d = func(filepath)
            score += s
            details.extend(d)

        if score >= 80:
            status = "MALICIOUS"
        elif score >= 40:
            status = "SUSPICIOUS"
        else:
            status = "CLEAN"

        return {
            "status": status,
            "score": score,
            "details": details
        }

    except Exception as e:
        return {
            "status": "ERROR",
            "score": 0,
            "details": [str(e)]
        }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    result = analyze_image("test.png")

    print("\n========== RESULT ==========\n")
    print("STATUS :", result["status"])
    print("SCORE  :", result["score"])

    print("\nDETAILS:\n")
    for d in result["details"]:
        print("-", d)