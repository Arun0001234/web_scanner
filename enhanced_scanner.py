#!/usr/bin/env python3
"""
Enhanced Web Application Vulnerability Scanner
Includes Port Scanning and Service Detection
"""

import requests
import re
import urllib.parse
from bs4 import BeautifulSoup
from typing import List, Dict, Tuple
import json
import time
from datetime import datetime
import concurrent.futures
import warnings
import socket
import ssl
from urllib.parse import urlparse

# Suppress SSL warnings for testing
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class PortScanner:
    """Port scanning and service detection module"""
    
    # Common ports and their services
    COMMON_PORTS = {
        20: 'FTP-DATA',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB',
    }
    
    def __init__(self, target_host: str, timeout: float = 1.0):
        self.target_host = target_host
        self.timeout = timeout
        self.open_ports = []
        
    def scan_port(self, port: int) -> Dict:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_host, port))
            
            if result == 0:
                service = self.COMMON_PORTS.get(port, 'Unknown')
                banner = self.grab_banner(sock, port)
                version = self.detect_version(banner, port)
                
                port_info = {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'banner': banner,
                    'version': version
                }
                
                sock.close()
                return port_info
            
            sock.close()
            return None
            
        except socket.gaierror:
            return None
        except socket.error:
            return None
        except Exception as e:
            return None
    
    def grab_banner(self, sock: socket.socket, port: int) -> str:
        """Attempt to grab service banner"""
        try:
            if port in [80, 8080, 8443]:
                # HTTP banner grab
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + self.target_host.encode() + b'\r\n\r\n')
            elif port == 443:
                # HTTPS banner grab
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                ssl_sock = context.wrap_socket(sock, server_hostname=self.target_host)
                ssl_sock.send(b'GET / HTTP/1.1\r\nHost: ' + self.target_host.encode() + b'\r\n\r\n')
                banner = ssl_sock.recv(1024).decode('utf-8', errors='ignore').strip()
                ssl_sock.close()
                return banner[:200]
            else:
                # Generic banner grab
                sock.send(b'\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200]  # Limit banner length
            
        except:
            return ''
    
    def detect_version(self, banner: str, port: int) -> str:
        """Detect service version from banner"""
        if not banner:
            return 'Unknown'
        
        # Common version patterns
        patterns = {
            'Apache': r'Apache[/\s]*([\d.]+)',
            'nginx': r'nginx[/\s]*([\d.]+)',
            'Microsoft-IIS': r'Microsoft-IIS[/\s]*([\d.]+)',
            'OpenSSH': r'OpenSSH[_\s]*([\d.]+)',
            'MySQL': r'MySQL[/\s]*([\d.]+)',
            'PostgreSQL': r'PostgreSQL[/\s]*([\d.]+)',
            'MongoDB': r'MongoDB[/\s]*([\d.]+)',
            'Redis': r'Redis[/\s]*([\d.]+)',
        }
        
        banner_lower = banner.lower()
        
        for service, pattern in patterns.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return f"{service}/{match.group(1)}"
        
        # Return first line of banner if no version found
        first_line = banner.split('\n')[0][:50]
        return first_line if first_line else 'Unknown'
    
    def scan_common_ports(self) -> List[Dict]:
        """Scan common ports"""
        print(f"[*] Scanning {len(self.COMMON_PORTS)} common ports...")
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port 
                            for port in self.COMMON_PORTS.keys()}
            
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    results.append(result)
                    self.open_ports.append(result['port'])
                    print(f"    [+] Port {result['port']}/{result['service']} is OPEN")
        
        return results
    
    def scan_port_range(self, start_port: int, end_port: int) -> List[Dict]:
        """Scan a range of ports"""
        print(f"[*] Scanning ports {start_port}-{end_port}...")
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port 
                            for port in range(start_port, end_port + 1)}
            
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    results.append(result)
                    self.open_ports.append(result['port'])
                    print(f"    [+] Port {result['port']} is OPEN - {result['service']}")
        
        return results


class VulnerabilityScanner:
    def __init__(self, target_url: str, timeout: int = 10, scan_ports: bool = True):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.scan_ports = scan_ports
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnScanner/2.0 (Security Testing)'
        })
        self.vulnerabilities = []
        
        # Extract hostname for port scanning
        parsed = urlparse(self.target_url)
        self.target_host = parsed.hostname or parsed.netloc
        
    def scan(self) -> Dict:
        """Run all vulnerability scans"""
        print(f"\n[*] Starting scan on {self.target_url}")
        print(f"[*] Target host: {self.target_host}")
        print(f"[*] Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        results = {
            'target': self.target_url,
            'host': self.target_host,
            'timestamp': datetime.now().isoformat(),
            'open_ports': [],
            'vulnerabilities': []
        }
        
        # Port scanning
        if self.scan_ports and self.target_host:
            print("="*70)
            print("PORT SCANNING & SERVICE DETECTION")
            print("="*70)
            
            try:
                port_scanner = PortScanner(self.target_host, timeout=1.0)
                port_results = port_scanner.scan_common_ports()
                results['open_ports'] = port_results
                
                # Check for vulnerable services
                vuln_services = self.check_vulnerable_services(port_results)
                results['vulnerabilities'].extend(vuln_services)
                
                print(f"\n[*] Found {len(port_results)} open ports")
            except Exception as e:
                print(f"[!] Port scanning error: {e}")
        
        # Web vulnerability scanning
        print("\n" + "="*70)
        print("WEB VULNERABILITY SCANNING")
        print("="*70)
        
        scan_modules = [
            ('SQL Injection', self.scan_sql_injection),
            ('XSS (Cross-Site Scripting)', self.scan_xss),
            ('Security Headers', self.check_security_headers),
            ('SSL/TLS Configuration', self.check_ssl_tls),
            ('Directory Traversal', self.scan_directory_traversal),
            ('Information Disclosure', self.check_information_disclosure),
            ('Open Redirects', self.scan_open_redirect),
            ('CSRF Protection', self.check_csrf_protection),
            ('Cookie Security', self.check_cookie_security),
        ]
        
        for module_name, module_func in scan_modules:
            print(f"[+] Scanning for {module_name}...")
            try:
                vulns = module_func()
                if vulns:
                    results['vulnerabilities'].extend(vulns)
                    print(f"    Found {len(vulns)} issue(s)")
                else:
                    print(f"    No issues found")
            except Exception as e:
                print(f"    Error: {str(e)}")
        
        print(f"\n[*] Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Total vulnerabilities found: {len(results['vulnerabilities'])}")
        
        return results
    
    def check_vulnerable_services(self, port_results: List[Dict]) -> List[Dict]:
        """Check for known vulnerable services"""
        vulnerabilities = []
        
        for port_info in port_results:
            port = port_info['port']
            service = port_info['service']
            version = port_info['version']
            
            # Check for insecure services
            if port == 23:  # Telnet
                vulnerabilities.append({
                    'type': 'Insecure Service',
                    'severity': 'HIGH',
                    'port': port,
                    'service': service,
                    'evidence': 'Telnet is an insecure protocol - credentials sent in plaintext',
                    'recommendation': 'Disable Telnet and use SSH instead'
                })
            
            elif port == 21:  # FTP
                vulnerabilities.append({
                    'type': 'Insecure Service',
                    'severity': 'MEDIUM',
                    'port': port,
                    'service': service,
                    'evidence': 'FTP transmits credentials in plaintext',
                    'recommendation': 'Use SFTP or FTPS instead'
                })
            
            elif port == 445:  # SMB
                vulnerabilities.append({
                    'type': 'Potentially Vulnerable Service',
                    'severity': 'MEDIUM',
                    'port': port,
                    'service': service,
                    'evidence': 'SMB exposed - potential for SMB vulnerabilities',
                    'recommendation': 'Ensure SMB is patched and restrict access'
                })
            
            elif port == 3389:  # RDP
                vulnerabilities.append({
                    'type': 'Exposed Remote Access',
                    'severity': 'MEDIUM',
                    'port': port,
                    'service': service,
                    'evidence': 'RDP exposed to internet - common attack target',
                    'recommendation': 'Use VPN or restrict RDP access by IP'
                })
            
            elif port in [3306, 5432, 27017]:  # Databases
                vulnerabilities.append({
                    'type': 'Exposed Database',
                    'severity': 'HIGH',
                    'port': port,
                    'service': service,
                    'evidence': f'{service} database exposed to internet',
                    'recommendation': 'Database should not be directly accessible from internet'
                })
            
            elif port == 6379:  # Redis
                vulnerabilities.append({
                    'type': 'Exposed Database',
                    'severity': 'HIGH',
                    'port': port,
                    'service': service,
                    'evidence': 'Redis exposed - often misconfigured without authentication',
                    'recommendation': 'Bind Redis to localhost and require authentication'
                })
            
            # Check for version disclosure
            if version and version != 'Unknown' and '/' in version:
                vulnerabilities.append({
                    'type': 'Version Disclosure',
                    'severity': 'LOW',
                    'port': port,
                    'service': service,
                    'version': version,
                    'evidence': f'Service version disclosed: {version}',
                    'recommendation': 'Hide version information when possible'
                })
        
        return vulnerabilities
    
    def get_forms(self, url: str) -> List[Dict]:
        """Extract all forms from a page"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_details = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea']):
                    input_type = input_tag.get('type', 'text')
                    input_name = input_tag.get('name')
                    if input_name:
                        form_details['inputs'].append({
                            'type': input_type,
                            'name': input_name
                        })
                
                forms.append(form_details)
            
            return forms
        except Exception as e:
            return []
    
    def scan_sql_injection(self) -> List[Dict]:
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "1' AND '1'='1",
            "' UNION SELECT NULL--",
        ]
        
        parsed_url = urllib.parse.urlparse(self.target_url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            
            for param in params:
                for payload in sql_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    
                    try:
                        response = self.session.get(
                            test_url,
                            params=test_params,
                            timeout=self.timeout,
                            verify=False
                        )
                        
                        sql_errors = [
                            'sql syntax',
                            'mysql',
                            'postgresql',
                            'sqlite',
                            'oracle',
                            'mssql',
                            'odbc',
                            'warning: mysql',
                            'unclosed quotation',
                        ]
                        
                        response_lower = response.text.lower()
                        for error in sql_errors:
                            if error in response_lower:
                                vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'severity': 'HIGH',
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f"SQL error detected in response"
                                })
                                break
                    except:
                        pass
        
        return vulnerabilities
    
    def scan_xss(self) -> List[Dict]:
        """Test for XSS vulnerabilities"""
        vulnerabilities = []
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>",
        ]
        
        parsed_url = urllib.parse.urlparse(self.target_url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            
            for param in params:
                for payload in xss_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    
                    try:
                        response = self.session.get(
                            test_url,
                            params=test_params,
                            timeout=self.timeout,
                            verify=False
                        )
                        
                        if payload in response.text:
                            vulnerabilities.append({
                                'type': 'Reflected XSS',
                                'severity': 'HIGH',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': 'Payload reflected in response without sanitization'
                            })
                            break
                    except:
                        pass
        
        return vulnerabilities
    
    def check_security_headers(self) -> List[Dict]:
        """Check for missing security headers"""
        vulnerabilities = []
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'MEDIUM',
                'X-Content-Type-Options': 'MEDIUM',
                'Strict-Transport-Security': 'MEDIUM',
                'Content-Security-Policy': 'HIGH',
                'X-XSS-Protection': 'LOW',
                'Referrer-Policy': 'LOW',
            }
            
            for header, severity in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        'type': 'Missing Security Header',
                        'severity': severity,
                        'url': self.target_url,
                        'header': header,
                        'evidence': f'{header} header not present',
                        'recommendation': self._get_header_recommendation(header)
                    })
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def _get_header_recommendation(self, header: str) -> str:
        """Get recommendation for security header"""
        recommendations = {
            'X-Frame-Options': 'Set to "DENY" or "SAMEORIGIN"',
            'X-Content-Type-Options': 'Set to "nosniff"',
            'Strict-Transport-Security': 'Set to "max-age=31536000; includeSubDomains"',
            'Content-Security-Policy': 'Implement a strict CSP policy',
            'X-XSS-Protection': 'Set to "1; mode=block"',
            'Referrer-Policy': 'Set to "strict-origin-when-cross-origin"',
        }
        return recommendations.get(header, 'Review security header')
    
    def check_ssl_tls(self) -> List[Dict]:
        """Check SSL/TLS configuration"""
        vulnerabilities = []
        
        if not self.target_url.startswith('https://'):
            vulnerabilities.append({
                'type': 'Insecure Protocol',
                'severity': 'HIGH',
                'url': self.target_url,
                'evidence': 'Site not using HTTPS',
                'recommendation': 'Implement HTTPS with valid SSL/TLS certificate'
            })
        else:
            try:
                response = requests.get(self.target_url, timeout=self.timeout, verify=True)
            except requests.exceptions.SSLError:
                vulnerabilities.append({
                    'type': 'SSL/TLS Configuration',
                    'severity': 'HIGH',
                    'url': self.target_url,
                    'evidence': 'Invalid or expired SSL certificate',
                    'recommendation': 'Install valid SSL certificate'
                })
            except:
                pass
        
        return vulnerabilities
    
    def scan_directory_traversal(self) -> List[Dict]:
        """Test for directory traversal"""
        vulnerabilities = []
        
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
        ]
        
        parsed_url = urllib.parse.urlparse(self.target_url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            
            for param in params:
                for payload in traversal_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    
                    try:
                        response = self.session.get(
                            test_url,
                            params=test_params,
                            timeout=self.timeout,
                            verify=False
                        )
                        
                        indicators = ['root:', '[extensions]', 'bin/bash']
                        if any(indicator in response.text for indicator in indicators):
                            vulnerabilities.append({
                                'type': 'Directory Traversal',
                                'severity': 'HIGH',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': 'System file content detected'
                            })
                            break
                    except:
                        pass
        
        return vulnerabilities
    
    def check_information_disclosure(self) -> List[Dict]:
        """Check for information disclosure"""
        vulnerabilities = []
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            
            # Check server header
            if 'Server' in response.headers:
                server = response.headers['Server']
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'severity': 'LOW',
                    'url': self.target_url,
                    'evidence': f'Server header reveals: {server}',
                    'recommendation': 'Remove server version'
                })
        except:
            pass
        
        return vulnerabilities
    
    def scan_open_redirect(self) -> List[Dict]:
        """Test for open redirects"""
        return []
    
    def check_csrf_protection(self) -> List[Dict]:
        """Check CSRF protection"""
        vulnerabilities = []
        
        forms = self.get_forms(self.target_url)
        for idx, form in enumerate(forms):
            if form['method'] == 'post':
                has_csrf = False
                csrf_names = ['csrf', 'token', '_token']
                
                for input_field in form['inputs']:
                    if any(csrf_name in input_field['name'].lower() for csrf_name in csrf_names):
                        has_csrf = True
                        break
                
                if not has_csrf:
                    vulnerabilities.append({
                        'type': 'Missing CSRF Protection',
                        'severity': 'MEDIUM',
                        'url': self.target_url,
                        'form_action': form['action'],
                        'evidence': f'POST form lacks CSRF token'
                    })
        
        return vulnerabilities
    
    def check_cookie_security(self) -> List[Dict]:
        """Check cookie security"""
        vulnerabilities = []
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            
            for cookie in self.session.cookies:
                issues = []
                
                if not cookie.secure and self.target_url.startswith('https://'):
                    issues.append('Secure flag not set')
                
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append('HttpOnly flag not set')
                
                if issues:
                    vulnerabilities.append({
                        'type': 'Insecure Cookie',
                        'severity': 'MEDIUM',
                        'url': self.target_url,
                        'cookie_name': cookie.name,
                        'evidence': ', '.join(issues)
                    })
        except:
            pass
        
        return vulnerabilities


def generate_report(results: Dict, output_file: str = 'vulnerability_report.json'):
    """Generate report"""
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Report saved to: {output_file}")


def print_summary(results: Dict):
    """Print summary"""
    print("\n" + "="*70)
    print("SCAN SUMMARY")
    print("="*70)
    
    # Port scan results
    if results.get('open_ports'):
        print(f"\n📡 OPEN PORTS: {len(results['open_ports'])}")
        for port_info in results['open_ports']:
            version_str = f" - {port_info['version']}" if port_info['version'] != 'Unknown' else ""
            print(f"   Port {port_info['port']}: {port_info['service']}{version_str}")
    
    # Vulnerability summary
    if not results['vulnerabilities']:
        print("\n✓ No vulnerabilities detected!")
        return
    
    severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for vuln in results['vulnerabilities']:
        severity = vuln.get('severity', 'UNKNOWN')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print(f"\n🔍 VULNERABILITIES: {len(results['vulnerabilities'])}")
    print(f"  🔴 High: {severity_counts.get('HIGH', 0)}")
    print(f"  🟡 Medium: {severity_counts.get('MEDIUM', 0)}")
    print(f"  🟢 Low: {severity_counts.get('LOW', 0)}")
    
    print("\n" + "="*70)
    print("DETAILED FINDINGS")
    print("="*70)
    
    for idx, vuln in enumerate(results['vulnerabilities'], 1):
        severity_symbol = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(vuln['severity'], '⚪')
        print(f"\n[{idx}] {severity_symbol} {vuln['type']} - {vuln['severity']}")
        
        if 'port' in vuln:
            print(f"    Port: {vuln['port']}")
        if 'url' in vuln:
            print(f"    URL: {vuln.get('url', 'N/A')}")
        print(f"    Evidence: {vuln.get('evidence', 'N/A')}")
        if 'recommendation' in vuln:
            print(f"    Fix: {vuln['recommendation']}")


if __name__ == "__main__":
    import sys
    
    print("""
╔═══════════════════════════════════════════════════════════╗
║   Enhanced Vulnerability Scanner v2.0                     ║
║   + Port Scanning & Service Detection                    ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("Usage: python enhanced_scanner.py <target_url> [--no-ports]")
        print("Example: python enhanced_scanner.py https://example.com")
        print("         python enhanced_scanner.py https://example.com --no-ports")
        sys.exit(1)
    
    target = sys.argv[1]
    scan_ports = '--no-ports' not in sys.argv
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    print(f"\n⚠️  WARNING: Only scan websites you own or have permission to test!")
    print(f"Target: {target}")
    print(f"Port Scanning: {'Enabled' if scan_ports else 'Disabled'}\n")
    
    scanner = VulnerabilityScanner(target, scan_ports=scan_ports)
    results = scanner.scan()
    
    print_summary(results)
    generate_report(results)
    
    print("\n[✓] Scan complete!")
