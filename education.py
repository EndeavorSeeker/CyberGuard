from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import os

class SecurityEducationHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve HTML, CSS, JS files
        if self.path == '/' or self.path == '/index.html':
            self.path = '/game.html'
        return SimpleHTTPRequestHandler.do_GET(self)
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        
        try:
            data = json.loads(body)
        except:
            self.send_error(400)
            return
        
        if self.path == '/api/check-password':
            response = self.check_password(data.get('password', ''))
        elif self.path == '/api/check-phishing':
            response = self.check_phishing(data.get('email', ''))
        else:
            self.send_error(404)
            return
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def check_password(self, password):
        """Check password strength"""
        strength = 0
        feedback = []
        
        # Length check
        if len(password) >= 8:
            strength += 1
        else:
            feedback.append("Use at least 8 characters")
        
        if len(password) >= 12:
            strength += 1
        
        # Complexity checks
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
        
        if has_lower:
            strength += 1
        else:
            feedback.append("Add lowercase letters")
        
        if has_upper:
            strength += 1
        else:
            feedback.append("Add uppercase letters")
        
        if has_digit:
            strength += 1
        else:
            feedback.append("Add numbers")
        
        if has_special:
            strength += 1
        else:
            feedback.append("Add special characters")
        
        # Common passwords check
        common = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if password.lower() in common:
            strength = max(0, strength - 2)
            feedback.append("Too common - avoid well-known passwords")
        
        strength_level = 'Weak' if strength < 3 else 'Fair' if strength < 4 else 'Good' if strength < 5 else 'Strong'
        
        return {
            'strength': strength,
            'level': strength_level,
            'feedback': feedback
        }
    
    def check_phishing(self, email):
        """Check if email is phishing"""
        phishing_indicators = [
            'click here immediately',
            'verify your account',
            'confirm password',
            'update payment',
            'suspended',
            'urgent action required',
            'suspicious activity',
            'dear customer'
        ]
        
        is_phishing = any(indicator in email.lower() for indicator in phishing_indicators)
        confidence = len([ind for ind in phishing_indicators if ind in email.lower()]) * 15
        confidence = min(100, confidence)
        
        if 'bank' in email.lower() and 'http://' in email.lower():
            is_phishing = True
            confidence = 95
        
        return {
            'is_phishing': is_phishing,
            'confidence': confidence if is_phishing else 100 - confidence
        }
    
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        SimpleHTTPRequestHandler.end_headers(self)

if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__))
    server_address = ('', 5000)
    httpd = HTTPServer(server_address, SecurityEducationHandler)
    print('🛡️ CyberGuard Academy is running on http://localhost:5000')
    print('Press Ctrl+C to stop the server')
    httpd.serve_forever()
