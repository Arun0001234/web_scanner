#!/usr/bin/env python3
"""
Simple Web Vulnerability Scanner - Beginner-Friendly Version
A minimal scanner to understand the basics
"""

import requests
from bs4 import BeautifulSoup
import urllib.parse


class SimpleScanner:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        
    def test_sql_injection(self):
        """Test for SQL injection with simple payload"""
        print("\n[*] Testing for SQL Injection...")
        
        # Simple SQL injection payload
        payload = "' OR '1'='1"
        
        # Parse URL and add payload to query parameter
        parsed = urllib.parse.urlparse(self.url)
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            # Test first parameter
            first_param = list(params.keys())[0]
            params[first_param] = [payload]
            
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            try:
                response = self.session.get(test_url, params=params)
                
                # Check for SQL errors
                sql_errors = ['sql', 'mysql', 'syntax error', 'postgresql']
                response_lower = response.text.lower()
                
                for error in sql_errors:
                    if error in response_lower:
                        print(f"[!] Potential SQL Injection found!")
                        print(f"    SQL error keyword detected: {error}")
                        return True
                
                print("[+] No SQL Injection detected")
                return False
            except Exception as e:
                print(f"[!] Error: {e}")
                return False
        else:
            print("[-] No query parameters to test")
            return False
    
    def test_xss(self):
        """Test for XSS vulnerabilities"""
        print("\n[*] Testing for XSS...")
        
        # Simple XSS payload
        payload = "<script>alert('XSS')</script>"
        
        parsed = urllib.parse.urlparse(self.url)
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            first_param = list(params.keys())[0]
            params[first_param] = [payload]
            
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            try:
                response = self.session.get(test_url, params=params)
                
                # Check if payload is in response
                if payload in response.text:
                    print(f"[!] Potential XSS found!")
                    print(f"    Payload reflected in response")
                    return True
                
                print("[+] No XSS detected")
                return False
            except Exception as e:
                print(f"[!] Error: {e}")
                return False
        else:
            print("[-] No query parameters to test")
            return False
    
    def check_https(self):
        """Check if site uses HTTPS"""
        print("\n[*] Checking HTTPS...")
        
        if self.url.startswith('https://'):
            print("[+] Site uses HTTPS")
            return True
        else:
            print("[!] Site does not use HTTPS - insecure!")
            return False
    
    def check_security_headers(self):
        """Check for important security headers"""
        print("\n[*] Checking Security Headers...")
        
        try:
            response = self.session.get(self.url)
            headers = response.headers
            
            # Important headers to check
            important_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Strict-Transport-Security',
                'Content-Security-Policy'
            ]
            
            missing = []
            for header in important_headers:
                if header in headers:
                    print(f"[+] {header}: {headers[header]}")
                else:
                    print(f"[!] Missing: {header}")
                    missing.append(header)
            
            return len(missing) == 0
        except Exception as e:
            print(f"[!] Error: {e}")
            return False
    
    def scan(self):
        """Run all tests"""
        print("="*60)
        print(f"Scanning: {self.url}")
        print("="*60)
        
        # Run all tests
        results = {
            'sql_injection': self.test_sql_injection(),
            'xss': self.test_xss(),
            'https': self.check_https(),
            'security_headers': self.check_security_headers()
        }
        
        # Print summary
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        
        issues = sum(1 for v in results.values() if v == False)
        
        if issues == 0:
            print("✓ No issues found!")
        else:
            print(f"⚠ Found {issues} potential issue(s)")
            print("\nRecommendations:")
            if not results['sql_injection']:
                print("  - Review database queries for SQL injection")
            if not results['xss']:
                print("  - Sanitize user input to prevent XSS")
            if not results['https']:
                print("  - Enable HTTPS with valid SSL certificate")
            if not results['security_headers']:
                print("  - Add security headers to HTTP responses")
        
        print("="*60)


if __name__ == "__main__":
    import sys
    
    print("""
    Simple Web Vulnerability Scanner
    For educational purposes only!
    """)
    
    if len(sys.argv) < 2:
        print("Usage: python simple_scanner.py <url>")
        print("Example: python simple_scanner.py https://example.com/page?id=1")
        sys.exit(1)
    
    url = sys.argv[1]
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print(f"\n⚠️  Only scan sites you own or have permission to test!\n")
    
    scanner = SimpleScanner(url)
    scanner.scan()
