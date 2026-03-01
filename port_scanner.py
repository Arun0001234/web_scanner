#!/usr/bin/env python3
"""
Advanced Port Scanner with Service Detection
Scans ports and identifies running services
"""

import socket
import ssl
import concurrent.futures
from datetime import datetime
import json
import re
from typing import List, Dict
import sys


class AdvancedPortScanner:
    """Port scanner with service version detection"""
    
    # Comprehensive port database
    COMMON_PORTS = {
        # Web Services
        80: 'HTTP',
        443: 'HTTPS',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        8000: 'HTTP-Alt',
        8888: 'HTTP-Alt',
        
        # File Transfer
        20: 'FTP-DATA',
        21: 'FTP',
        22: 'SSH/SFTP',
        69: 'TFTP',
        115: 'SFTP',
        
        # Email
        25: 'SMTP',
        110: 'POP3',
        143: 'IMAP',
        465: 'SMTPS',
        587: 'SMTP-Submission',
        993: 'IMAPS',
        995: 'POP3S',
        
        # Databases
        1433: 'MSSQL',
        1521: 'Oracle',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        5984: 'CouchDB',
        6379: 'Redis',
        7474: 'Neo4j',
        8529: 'ArangoDB',
        9042: 'Cassandra',
        9200: 'Elasticsearch',
        27017: 'MongoDB',
        28017: 'MongoDB-Web',
        
        # Remote Access
        23: 'Telnet',
        3389: 'RDP',
        5900: 'VNC',
        5901: 'VNC-1',
        5902: 'VNC-2',
        
        # Network Services
        53: 'DNS',
        67: 'DHCP',
        68: 'DHCP-Client',
        123: 'NTP',
        161: 'SNMP',
        162: 'SNMP-Trap',
        389: 'LDAP',
        636: 'LDAPS',
        
        # Windows/SMB
        135: 'MSRPC',
        137: 'NetBIOS-NS',
        138: 'NetBIOS-DGM',
        139: 'NetBIOS-SSN',
        445: 'SMB/CIFS',
        
        # Application Servers
        1099: 'Java-RMI',
        3000: 'Node.js',
        4000: 'Angular',
        5000: 'Flask/Docker',
        5001: 'Docker-Registry',
        8000: 'Django',
        8080: 'Tomcat/JBoss',
        9000: 'PHP-FPM',
        9090: 'Prometheus',
        
        # Other Services
        514: 'Syslog',
        873: 'Rsync',
        1194: 'OpenVPN',
        1723: 'PPTP',
        2049: 'NFS',
        2375: 'Docker',
        2376: 'Docker-TLS',
        3128: 'Squid-Proxy',
        5555: 'Android-Debug',
        6660: 'IRC',
        6667: 'IRC',
        8291: 'Mikrotik',
        9418: 'Git',
        11211: 'Memcached',
        50000: 'SAP',
    }
    
    def __init__(self, target: str, timeout: float = 1.0):
        self.target = target
        self.timeout = timeout
        self.open_ports = []
        self.results = []
        
    def scan_port(self, port: int) -> Dict:
        """Scan a single port with service detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                service_name = self.COMMON_PORTS.get(port, 'Unknown')
                
                # Grab banner
                banner = self.grab_banner(sock, port)
                
                # Detect version
                version_info = self.detect_version(banner, port)
                
                # Check for vulnerabilities
                vuln_check = self.check_known_vulnerabilities(port, service_name, version_info)
                
                port_info = {
                    'port': port,
                    'state': 'open',
                    'service': service_name,
                    'banner': banner[:200] if banner else '',
                    'version': version_info,
                    'vulnerabilities': vuln_check
                }
                
                self.open_ports.append(port)
                sock.close()
                return port_info
            
            sock.close()
            return None
            
        except socket.gaierror:
            return None
        except socket.error:
            return None
        except Exception:
            return None
    
    def grab_banner(self, sock: socket.socket, port: int) -> str:
        """Enhanced banner grabbing"""
        try:
            # HTTP/HTTPS
            if port in [80, 8080, 8000, 8888]:
                sock.send(b'HEAD / HTTP/1.1\r\nHost: ' + self.target.encode() + b'\r\n\r\n')
                return sock.recv(2048).decode('utf-8', errors='ignore').strip()
            
            # HTTPS
            elif port in [443, 8443]:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
                    ssl_sock.send(b'HEAD / HTTP/1.1\r\nHost: ' + self.target.encode() + b'\r\n\r\n')
                    banner = ssl_sock.recv(2048).decode('utf-8', errors='ignore').strip()
                    
                    # Get SSL certificate info
                    cert = ssl_sock.getpeercert()
                    ssl_sock.close()
                    return banner
                except:
                    return ''
            
            # FTP
            elif port == 21:
                return sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # SSH
            elif port == 22:
                return sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # SMTP
            elif port in [25, 465, 587]:
                return sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Generic
            else:
                sock.send(b'\r\n')
                return sock.recv(1024).decode('utf-8', errors='ignore').strip()
                
        except:
            return ''
    
    def detect_version(self, banner: str, port: int) -> str:
        """Advanced version detection"""
        if not banner:
            return 'Unknown'
        
        # Version patterns
        patterns = {
            'Apache': r'Apache[/\s]*([\d.]+)',
            'nginx': r'nginx[/\s]*([\d.]+)',
            'Microsoft-IIS': r'Microsoft-IIS[/\s]*([\d.]+)',
            'OpenSSH': r'OpenSSH[_\s]*([\d.]+[p\d]*)',
            'vsftpd': r'vsftpd[/\s]*([\d.]+)',
            'ProFTPD': r'ProFTPD[/\s]*([\d.]+)',
            'MySQL': r'MySQL[/\s]*([\d.]+)',
            'MariaDB': r'MariaDB[/\s]*([\d.]+)',
            'PostgreSQL': r'PostgreSQL[/\s]*([\d.]+)',
            'MongoDB': r'MongoDB[/\s]*([\d.]+)',
            'Redis': r'Redis[/\s]*([\d.]+)',
            'Postfix': r'Postfix',
            'Exim': r'Exim[/\s]*([\d.]+)',
            'Sendmail': r'Sendmail',
            'Dovecot': r'Dovecot',
            'PHP': r'PHP[/\s]*([\d.]+)',
            'Python': r'Python[/\s]*([\d.]+)',
            'Express': r'Express',
            'Tomcat': r'Tomcat[/\s]*([\d.]+)',
        }
        
        for service, pattern in patterns.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                if match.groups():
                    return f"{service}/{match.group(1)}"
                else:
                    return service
        
        # Extract first meaningful line
        lines = banner.split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('HTTP'):
                return line[:50]
        
        return 'Unknown'
    
    def check_known_vulnerabilities(self, port: int, service: str, version: str) -> List[str]:
        """Check for known vulnerable configurations"""
        vulnerabilities = []
        
        # Insecure protocols
        if port == 23:
            vulnerabilities.append("CRITICAL: Telnet - Unencrypted protocol")
        
        if port == 21:
            vulnerabilities.append("WARNING: FTP - Consider using SFTP/FTPS")
        
        # Database exposure
        if port in [3306, 5432, 27017, 6379, 9200, 1433]:
            vulnerabilities.append("CRITICAL: Database exposed to network")
        
        # Remote access
        if port == 3389:
            vulnerabilities.append("WARNING: RDP exposed - common attack target")
        
        if port == 5900:
            vulnerabilities.append("WARNING: VNC exposed - ensure strong password")
        
        # SMB
        if port in [139, 445]:
            vulnerabilities.append("WARNING: SMB exposed - ensure patched against EternalBlue")
        
        # Docker
        if port == 2375:
            vulnerabilities.append("CRITICAL: Docker API exposed without TLS")
        
        # Memcached
        if port == 11211:
            vulnerabilities.append("WARNING: Memcached exposed - DDoS amplification risk")
        
        # Redis
        if port == 6379:
            vulnerabilities.append("CRITICAL: Redis exposed - often lacks authentication")
        
        # Elasticsearch
        if port == 9200:
            vulnerabilities.append("CRITICAL: Elasticsearch exposed - check authentication")
        
        return vulnerabilities
    
    def scan_common_ports(self) -> List[Dict]:
        """Scan all common ports"""
        print(f"[*] Scanning {len(self.COMMON_PORTS)} common ports on {self.target}")
        print(f"[*] This may take a minute...\n")
        
        results = []
        scanned = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port 
                            for port in self.COMMON_PORTS.keys()}
            
            for future in concurrent.futures.as_completed(future_to_port):
                scanned += 1
                result = future.result()
                
                if result:
                    results.append(result)
                    vuln_str = ""
                    if result['vulnerabilities']:
                        vuln_str = f" ⚠️  {len(result['vulnerabilities'])} warning(s)"
                    
                    print(f"[+] Port {result['port']:5d} | {result['service']:20s} | {result['version']}{vuln_str}")
                
                # Progress indicator
                if scanned % 20 == 0:
                    print(f"    Progress: {scanned}/{len(self.COMMON_PORTS)} ports scanned...")
        
        self.results = results
        return results
    
    def scan_range(self, start_port: int, end_port: int) -> List[Dict]:
        """Scan a specific port range"""
        total_ports = end_port - start_port + 1
        print(f"[*] Scanning ports {start_port}-{end_port} on {self.target}")
        print(f"[*] Total ports to scan: {total_ports}\n")
        
        results = []
        scanned = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port 
                            for port in range(start_port, end_port + 1)}
            
            for future in concurrent.futures.as_completed(future_to_port):
                scanned += 1
                result = future.result()
                
                if result:
                    results.append(result)
                    print(f"[+] Port {result['port']:5d} | {result['service']:20s} | {result['version']}")
                
                # Progress indicator
                if scanned % 100 == 0:
                    print(f"    Progress: {scanned}/{total_ports} ports scanned...")
        
        self.results = results
        return results
    
    def generate_report(self, filename: str = 'port_scan_report.json'):
        """Generate JSON report"""
        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'total_scanned': len(self.COMMON_PORTS),
            'open_ports': len(self.open_ports),
            'results': self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to: {filename}")
    
    def print_summary(self):
        """Print scan summary"""
        print("\n" + "="*70)
        print("PORT SCAN SUMMARY")
        print("="*70)
        print(f"Target: {self.target}")
        print(f"Open Ports: {len(self.open_ports)}")
        
        if not self.results:
            print("\n✓ No open ports found")
            return
        
        print(f"\nOpen Ports Breakdown:")
        
        # Group by category
        categories = {
            'Web Services': [80, 443, 8080, 8443, 8000, 8888],
            'Databases': [1433, 1521, 3306, 5432, 6379, 9200, 27017],
            'Remote Access': [22, 23, 3389, 5900, 5901, 5902],
            'Email': [25, 110, 143, 465, 587, 993, 995],
            'File Transfer': [20, 21, 69, 115],
            'Windows/SMB': [135, 137, 138, 139, 445],
        }
        
        for category, ports in categories.items():
            found = [p for p in self.open_ports if p in ports]
            if found:
                print(f"\n{category}:")
                for result in self.results:
                    if result['port'] in found:
                        print(f"  Port {result['port']}: {result['service']} - {result['version']}")
        
        # Show vulnerabilities
        critical_vulns = []
        warnings = []
        
        for result in self.results:
            for vuln in result['vulnerabilities']:
                if 'CRITICAL' in vuln:
                    critical_vulns.append(f"Port {result['port']}: {vuln}")
                else:
                    warnings.append(f"Port {result['port']}: {vuln}")
        
        if critical_vulns:
            print("\n🔴 CRITICAL ISSUES:")
            for vuln in critical_vulns:
                print(f"  {vuln}")
        
        if warnings:
            print("\n🟡 WARNINGS:")
            for warn in warnings:
                print(f"  {warn}")
        
        print("="*70)


def main():
    if len(sys.argv) < 2:
        print("""
╔════════════════════════════════════════════════════════╗
║        Advanced Port Scanner v1.0                      ║
║        With Service Version Detection                  ║
╚════════════════════════════════════════════════════════╝

Usage:
  python port_scanner.py <target> [options]

Options:
  --range START END    Scan specific port range
  --common             Scan common ports only (default)

Examples:
  python port_scanner.py example.com
  python port_scanner.py 192.168.1.1
  python port_scanner.py example.com --range 1 1000
        """)
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Remove http:// or https:// if present
    target = target.replace('http://', '').replace('https://', '').split('/')[0]
    
    print(f"\n⚠️  WARNING: Only scan targets you own or have permission to test!")
    print(f"\nTarget: {target}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    scanner = AdvancedPortScanner(target, timeout=1.0)
    
    # Check for range option
    if '--range' in sys.argv:
        try:
            idx = sys.argv.index('--range')
            start = int(sys.argv[idx + 1])
            end = int(sys.argv[idx + 2])
            scanner.scan_range(start, end)
        except:
            print("[!] Invalid range specified")
            sys.exit(1)
    else:
        # Scan common ports
        scanner.scan_common_ports()
    
    # Print summary
    scanner.print_summary()
    
    # Generate report
    scanner.generate_report()
    
    print(f"\n[✓] Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
