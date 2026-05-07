# url_shield.py - Simple URL analyzer for CyberGuard
# Returns: True = SAFE, False = THREAT

import requests
import re
from urllib.parse import urlparse

# Hugging Face token
HF_TOKEN = "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"  # PASTE YOUR TOKEN HERE

# Hugging Face API
API_URL = "https://api-inference.huggingface.co/models/elftsdmr/malware-url-detect"

def url_analyse(url):
    """
    Analyze URL for phishing/malicious content
    
    Args:
        url (str): The URL to check
    
    Returns:
        bool: True if SAFE, False if THREAT
    """
    
    # Calculate danger score
    score = 0
    
    # Pattern analysis
    # 1. IP address instead of domain
    if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url):
        score += 35
    
    # 2. Suspicious TLDs
    bad_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    if any(tld in url.lower() for tld in bad_tlds):
        score += 30
    
    # 3. Too many subdomains
    if urlparse(url).netloc.count('.') > 3:
        score += 25
    
    # 4. Phishing keywords
    keywords = ['login', 'verify', 'account', 'secure', 'paypal', 'banking']
    score += sum(5 for word in keywords if word in url.lower())
    
    # 5. @ symbol trick
    if '@' in url:
        score += 40
    
    # 6. Very long URL
    if len(url) > 75:
        score += 15
    
    # 7. No HTTPS
    if not url.startswith('https://'):
        score += 10
    
    # AI boost (optional - only if API works)
    try:
        headers = {"Authorization": f"Bearer {HF_TOKEN}"}
        response = requests.post(API_URL, headers=headers, json={"inputs": url}, timeout=5)
        
        if response.status_code == 200:
            result = response.json()
            if isinstance(result, list):
                for item in result[0]:
                    if 'malware' in item.get('label', '').lower():
                        score += int(item.get('score', 0) * 30)
                        break
    except:
        pass  # If API fails, just use pattern analysis
    
    # Return True (SAFE) or False (THREAT)
    # Threshold: if score > 50 = THREAT
    return score < 50


# TESTING
if __name__ == "__main__":
    print("="*60)
    print("🛡️  URL ANALYSER - Testing")
    print("="*60 + "\n")
    
    test_urls = [
        ("https://www.google.com", "Should be SAFE"),
        ("http://paypal-verify.tk", "Should be THREAT"),
        ("http://192.168.1.1/login.php", "Should be THREAT"),
        ("https://github.com", "Should be SAFE"),
    ]
    
    for url, expected in test_urls:
        result = url_analyse(url)
        status = "✅ SAFE" if result else "🚨 THREAT"
        print(f"URL: {url}")
        print(f"Result: {status}")
        print(f"Expected: {expected}")
        print("-"*60 + "\n")