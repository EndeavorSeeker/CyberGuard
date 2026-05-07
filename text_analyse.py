# text_analyse.py - Social Engineering / Scam Message Detector
# Returns: True = SAFE, False = SCAM

import requests
import re

# Hugging Face token
HF_TOKEN = "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"  # PASTE YOUR TOKEN HERE

# Hugging Face API - Spam/Phishing Text Classifier
API_URL = "https://api-inference.huggingface.co/models/ealvaradob/bert-finetuned-phishing-email-detection"

def text_analyse(message):
    """
    Analyze text message for scam/phishing content
    
    Args:
        message (str): The text message to check
    
    Returns:
        bool: True if SAFE, False if SCAM
    """
    
    # Calculate suspicion score
    score = 0
    
    # Pattern Analysis - Common scam indicators
    message_lower = message.lower()
    
    # 1. Urgency words
    urgency_words = ['urgent', 'immediately', 'act now', 'limited time', 
                     'expires', 'hurry', 'quick', 'asap', 'right now']
    score += sum(10 for word in urgency_words if word in message_lower)
    
    # 2. Money/prize related
    money_words = ['won', 'winner', 'prize', 'claim', 'reward', 'free money',
                   'cash', 'bitcoin', 'lottery', 'jackpot', '$$$', '€€€']
    score += sum(15 for word in money_words if word in message_lower)
    
    # 3. Credential requests
    credential_words = ['password', 'verify your account', 'confirm your identity',
                       'social security', 'credit card', 'bank account', 'pin code',
                       'cvv', 'verify account', 'update payment']
    score += sum(20 for word in credential_words if word in message_lower)
    
    # 4. Suspicious links (http instead of https, shortened URLs)
    if 'http://' in message_lower:
        score += 15
    
    shortened_urls = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']
    score += sum(15 for url in shortened_urls if url in message_lower)
    
    # 5. Threats/fear tactics
    threat_words = ['suspended', 'blocked', 'locked', 'compromised', 
                   'unauthorized', 'fraud', 'illegal', 'arrest', 'police']
    score += sum(15 for word in threat_words if word in message_lower)
    
    # 6. Too many exclamation marks or capital letters
    if message.count('!') > 2:
        score += 10
    
    capitals = sum(1 for c in message if c.isupper())
    if len(message) > 0 and (capitals / len(message)) > 0.3:
        score += 15
    
    # 7. Poor grammar indicators (multiple spaces, no punctuation)
    if '  ' in message:  # Multiple spaces
        score += 5
    
    # 8. Contact requests from unknown sources
    contact_words = ['click here', 'call now', 'text back', 'reply with',
                    'send us', 'contact us immediately']
    score += sum(10 for word in contact_words if word in message_lower)
    
    # AI Analysis using Hugging Face
    try:
        headers = {"Authorization": f"Bearer {HF_TOKEN}"}
        response = requests.post(API_URL, headers=headers, 
                                json={"inputs": message}, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            
            # Process result
            if isinstance(result, list) and len(result) > 0:
                for item in result[0]:
                    label = item.get('label', '').lower()
                    confidence = item.get('score', 0)
                    
                    # If AI detects spam/scam
                    if 'spam' in label or 'scam' in label:
                        score += int(confidence * 50)
                        break
    except:
        pass  # If API fails, use pattern analysis only
    
    # Return True (SAFE) or False (SCAM)
    # Threshold: if score > 40 = SCAM
    return score < 40


# TESTING
if __name__ == "__main__":
    print("="*60)
    print("🛡️  TEXT ANALYSER - Social Engineering Detector")
    print("="*60 + "\n")
    
    test_messages = [
        ("Hey, are we still meeting for lunch tomorrow?", "Should be SAFE"),
        
        ("URGENT! Your account has been SUSPENDED! Click here immediately to verify your identity and password or we will close your account!", "Should be SCAM"),
        
        ("Congratulations! You have WON $5000! Claim your prize NOW by clicking this link: http://bit.ly/freemoney", "Should be SCAM"),
        
        ("Your package will arrive tomorrow between 2-4 PM", "Should be SAFE"),
        
        ("ALERT: Unauthorized login detected! Verify your bank account details immediately or your account will be locked!", "Should be SCAM"),
        
        ("Can you send me the meeting notes from yesterday?", "Should be SAFE"),
    ]
    
    for message, expected in test_messages:
        result = text_analyse(message)
        status = "✅ SAFE" if result else "🚨 SCAM"
        
        print(f"Message: {message[:60]}...")
        print(f"Result: {status}")
        print(f"Expected: {expected}")
        print("-"*60 + "\n")
        # Note: In real usage, you would not print the message in full if it's long, but for testing we show a snippet.