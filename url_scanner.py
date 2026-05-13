# url_scanner.py - Real URL Threat Detection using VirusTotal
import requests
import hashlib
import time
from urllib.parse import urlparse

# VirusTotal API Key (FREE - get yours at https://www.virustotal.com/gui/join-us)
VIRUSTOTAL_API_KEY = "442eb9b6509f819c2bcd779cf0e946350a9dbd182935af8231141235b7052caf"  # Get free key at virustotal.com

def scan_url_virustotal(url):
    """
    Scan URL using VirusTotal API
    
    Returns:
        dict: {
            'score': int (0-100),
            'category': str,
            'confidence': int,
            'explanation': str
        }
    """
    
    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        # Step 1: Submit URL for scanning
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        
        scan_url = "https://www.virustotal.com/api/v3/urls"
        response = requests.post(scan_url, headers=headers, data={"url": url}, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            analysis_id = result['data']['id']
            
            # Step 2: Get analysis results
            time.sleep(2)  # Wait for analysis
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers, timeout=10)
            
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                stats = analysis_data['data']['attributes']['stats']
                
                # Extract threat indicators
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                total = malicious + suspicious + harmless + stats.get('undetected', 0)
                
                # Calculate score (0-100, higher = more dangerous)
                if total > 0:
                    threat_ratio = (malicious + suspicious * 0.5) / total
                    score = int(threat_ratio * 100)
                else:
                    score = 50  # Unknown
                
                # Determine category
                if malicious > 0:
                    category = "Dangerous"
                    explanation = f"CRITICAL: {malicious} security vendors flagged this URL as malicious. Do not visit this site."
                elif suspicious > 3:
                    category = "Suspicious"
                    explanation = f"{suspicious} vendors marked this URL as suspicious. Exercise extreme caution."
                elif suspicious > 0:
                    category = "Questionable"
                    explanation = f"{suspicious} vendors found suspicious indicators. Verify source before proceeding."
                else:
                    category = "Safe"
                    explanation = f"No threats detected. {harmless} vendors confirmed this URL is safe."
                
                confidence = 95 if malicious > 0 else 85 if suspicious > 0 else 90
                
                return {
                    'score': score,
                    'category': category,
                    'confidence': confidence,
                    'explanation': explanation
                }
        
        # Fallback to basic pattern analysis if API fails
        return fallback_url_scan(url)
        
    except Exception as e:
        print(f"VirusTotal API error: {e}")
        return fallback_url_scan(url)


def fallback_url_scan(url):
    """
    Backup scanner using pattern analysis (no API needed)
    """
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    
    score = 0
    flags = []
    
    # Security checks
    if parsed.scheme != 'https':
        score += 15
        flags.append("No HTTPS encryption")
    
    # Suspicious patterns
    phishing_keywords = ['login', 'verify', 'account', 'secure', 'update', 'bank', 'paypal']
    for keyword in phishing_keywords:
        if keyword in host or keyword in path:
            score += 12
            flags.append(f"Phishing keyword: {keyword}")
            break
    
    # URL shorteners
    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
    for shortener in shorteners:
        if shortener in host:
            score += 20
            flags.append("URL shortener used")
            break
    
    # Suspicious TLDs
    risky_tlds = ['.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.top']
    for tld in risky_tlds:
        if host.endswith(tld):
            score += 18
            flags.append(f"High-risk TLD: {tld}")
            break
    
    # Domain analysis
    if host.count('-') >= 3:
        score += 10
        flags.append("Multiple hyphens in domain")
    
    if len(host) > 40:
        score += 8
        flags.append("Unusually long domain")
    
    # Determine category
    if score >= 50:
        category = "Dangerous"
        explanation = f"High threat detected. {', '.join(flags[:3])}. Avoid this URL."
    elif score >= 25:
        category = "Suspicious"
        explanation = f"Multiple red flags: {', '.join(flags[:2])}. Proceed with caution."
    else:
        category = "Safe"
        explanation = "No significant threats detected. URL appears legitimate."
    
    confidence = 75
    
    return {
        'score': min(score, 100),
        'category': category,
        'confidence': confidence,
        'explanation': explanation
    }


# # Quick test
# if __name__ == "__main__":
#     test_urls = [
#         "https://google.com",
#         "http://suspicious-bank-login.ru",
#         "https://bit.ly/freeprize"
#     ]
#     
#     for url in test_urls:
#         print(f"\nTesting: {url}")
#         result = scan_url_virustotal(url)
#         print(f"Score: {result['score']}")
#         print(f"Category: {result['category']}")
#         print(f"Explanation: {result['explanation']}")

