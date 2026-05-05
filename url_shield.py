import re
from urllib.parse import urlparse

# ----------------------------
# Feature Extraction
# ----------------------------
def extract_features(url):
    features = {}

    parsed = urlparse(url)

    features["length"] = len(url)
    features["has_https"] = 1 if parsed.scheme == "https" else 0
    features["num_dots"] = url.count(".")
    features["num_slashes"] = url.count("/")
    features["has_at"] = 1 if "@" in url else 0
    features["has_ip"] = 1 if re.match(r"^\d+\.\d+\.\d+\.\d+", parsed.netloc) else 0

    suspicious_words = ["login", "verify", "update", "bank", "secure", "account"]
    features["suspicious_words"] = 1 if any(word in url.lower() for word in suspicious_words) else 0

    return features


# ----------------------------
# Detection Logic
# ----------------------------
def rule_based_detector(features):
    score = 0

    if features["length"] > 75:
        score += 1
    if features["has_https"] == 0:
        score += 1
    if features["num_dots"] > 3:
        score += 1
    if features["num_slashes"] > 5:
        score += 1
    if features["has_at"] == 1:
        score += 2
    if features["has_ip"] == 1:
        score += 2
    if features["suspicious_words"] == 1:
        score += 2

    # Normalize score (max ~10)
    confidence = min(score / 10, 1.0)

    if score >= 4:
        prediction = "phishing"
        risk_level = "HIGH"
    elif score >= 2:
        prediction = "suspicious"
        risk_level = "MEDIUM"
    else:
        prediction = "safe"
        risk_level = "LOW"

    return prediction, confidence, risk_level


# ----------------------------
# Main Function
# ----------------------------
def analyze_url(url):
    try:
        features = extract_features(url)
        prediction, confidence, risk_level = rule_based_detector(features)

        return {
            "url": url,
            "prediction": prediction,
            "confidence": round(confidence, 2),
            "risk_level": risk_level
        }

    except Exception as e:
        return {
            "error": str(e),
            "prediction": "error"
        }


# ----------------------------
# Test (run this file directly)
# ----------------------------
if __name__ == "__main__":
    test_urls = [
        "https://google.com",
        "http://192.168.0.1/login",
        "http://secure-bank-login.com/verify/account",
        "https://github.com"
    ]

    for url in test_urls:
        print(analyze_url(url))