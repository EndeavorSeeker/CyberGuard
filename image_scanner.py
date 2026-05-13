# image_scanner.py - Simple Image Security Scanner
from PIL import Image
import os

def scan_image(file_path, file_name, file_size):
    """
    Basic image security analysis
    
    Returns:
        dict: {
            'score': int (0-100),
            'category': str,
            'confidence': int,
            'explanation': str
        }
    """
    
    score = 0
    flags = []
    
    try:
        # Open and analyze image
        img = Image.open(file_path)
        width, height = img.size
        file_format = img.format
        
        # 1. Suspicious file names
        name_lower = file_name.lower()
        suspicious_keywords = ['invoice', 'receipt', 'payment', 'verify', 
                              'secure', 'login', 'bank', 'paypal', 'amazon']
        
        for keyword in suspicious_keywords:
            if keyword in name_lower:
                score += 15
                flags.append(f"Suspicious filename pattern: {keyword}")
                break
        
        # 2. Unusual dimensions (screenshots of phishing sites are often specific sizes)
        if width < 400 and height < 400:
            score += 10
            flags.append("Unusually small image (common in phishing)")
        
        if width > 3000 or height > 3000:
            score += 5
            flags.append("Unusually large image")
        
        # 3. File size analysis
        size_mb = file_size / (1024 * 1024)
        
        if size_mb < 0.05:  # Less than 50KB
            score += 12
            flags.append("Suspiciously small file size")
        
        if size_mb > 10:  # Larger than 10MB
            score += 8
            flags.append("Unusually large file")
        
        # 4. Format checks
        if file_format not in ['JPEG', 'PNG', 'GIF', 'WEBP']:
            score += 15
            flags.append(f"Uncommon image format: {file_format}")
        
        # 5. Check for common phishing image patterns
        # Screenshots are usually PNG with specific aspect ratios
        if file_format == 'PNG' and 1.3 < (width/height) < 1.8:
            if any(word in name_lower for word in ['screenshot', 'capture', 'img']):
                score += 10
                flags.append("Possible phishing screenshot")
        
        # Determine category
        if score >= 50:
            category = "Suspicious"
            explanation = f"Image shows multiple red flags: {', '.join(flags[:2])}. Verify source before opening."
        elif score >= 25:
            category = "Questionable"
            explanation = f"Some concerns detected: {', '.join(flags[:2])}. Exercise caution."
        else:
            category = "Safe"
            explanation = "Image appears normal with no obvious security concerns."
        
        confidence = 80 if score > 40 or score < 15 else 65
        
        return {
            'score': min(score, 100),
            'category': category,
            'confidence': confidence,
            'explanation': explanation
        }
        
    except Exception as e:
        # If image can't be opened, it's suspicious
        return {
            'score': 75,
            'category': 'Suspicious',
            'confidence': 90,
            'explanation': f"Unable to process image properly. File may be corrupted or malicious."
        }


# # Test
# if __name__ == "__main__":
#     print("Image scanner ready")

