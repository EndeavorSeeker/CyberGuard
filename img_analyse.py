
from PIL import Image
from pyzbar.pyzbar import decode
import hashlib
import requests
import os

'''# 🔗 URL SHIELD IMPORT
from url_shield import check_url
# 🔗 TEXT CHECK IMPORT
from url_shield import check_text'''


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

    data_lower = data.lower()

    # 🧨 Script / JS injection
    if b'<script' in data_lower:
        score += 30
        details.append("Script tag detected")

    # ⚠️ HTML injection
    if b'<iframe' in data_lower or b'<img' in data_lower:
        score += 20
        details.append("Suspicious HTML tag detected")

    # 🐍 Python / code injection
    if b'import os' in data_lower or b'exec(' in data_lower:
        score += 40
        details.append("Code execution pattern detected")

    # 💻 Command injection
    if b'cmd.exe' in data_lower or b'powershell' in data_lower:
        score += 50
        details.append("Command execution detected")

    # 📂 Path traversal
    if b'../' in data_lower or b'..\\' in data_lower:
        score += 25
        details.append("Path traversal pattern detected")

    # 🔐 Credential stealing
    if b'password=' in data_lower or b'login=' in data_lower:
        score += 30
        details.append("Credential pattern detected")

    # 🌐 Suspicious links
    if b'http://' in data_lower or b'https://' in data_lower:
        score += 10
        details.append("Embedded URL found")

    # 🧬 Encoded / obfuscated
    if b'base64' in data_lower or b'eval(' in data_lower:
        score += 35
        details.append("Obfuscated code detected")

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
# VIRUSTOTAL
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
'''
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

                # 🔥 unified analysis
                s, d = check_url(data)

                details.append("Content analysis:")
                score += s
                details.extend(d)

        else:
            details.append("No QR codes found")

    except Exception as e:
        details.append(f"QR error: {e}")

    return score, details'''


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
            #check_qr_codes,
            check_virustotal
        ]:
            s, d = func(filepath)
            score += s
            details.extend(d)

        # ✅ STATUS SYSTEM
        if score >= 80:
            status = "THREAT"
        elif score >= 40:
            status = "WARNING"
        else:
            status = "SAFE"

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

    file_path = "test.png"  # 🔁 photo de test

    result = analyze_image(file_path)

    print("\n","=="*10 ,"RESULT", "=="*10,"\n")
    print("STATUS :", result["status"])
    print("SCORE  :", result["score"])

    print("\nDETAILS:\n")
    for d in result["details"]:
        print("-", d)