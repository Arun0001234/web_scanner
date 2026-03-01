#!/usr/bin/env python3
"""
Web-based Vulnerability Scanner
Flask backend API
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import json
import threading
from datetime import datetime
import uuid
import os

# Import our scanner
from enhanced_scanner import VulnerabilityScanner
from port_scanner import AdvancedPortScanner

app = Flask(__name__)
CORS(app)

# Store scan results in memory (use Redis/database in production)
scan_results = {}
active_scans = {}

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new vulnerability scan"""
    data = request.json
    target_url = data.get('url', '').strip()
    scan_ports = data.get('scan_ports', True)
    
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())
    
    # Initialize scan status
    active_scans[scan_id] = {
        'status': 'running',
        'progress': 0,
        'current_step': 'Initializing...',
        'target': target_url,
        'started_at': datetime.now().isoformat()
    }
    
    # Start scan in background thread
    thread = threading.Thread(
        target=run_scan,
        args=(scan_id, target_url, scan_ports)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'message': 'Scan started successfully'
    })

def run_scan(scan_id, target_url, scan_ports):
    """Run the vulnerability scan in background"""
    try:
        # Update progress
        active_scans[scan_id]['current_step'] = 'Starting scan...'
        active_scans[scan_id]['progress'] = 5
        
        # Create scanner instance
        scanner = VulnerabilityScanner(target_url, scan_ports=scan_ports)
        
        # Port scanning
        if scan_ports:
            active_scans[scan_id]['current_step'] = 'Scanning ports...'
            active_scans[scan_id]['progress'] = 20
        
        # Web vulnerability scanning
        active_scans[scan_id]['current_step'] = 'Checking SQL Injection...'
        active_scans[scan_id]['progress'] = 40
        
        active_scans[scan_id]['current_step'] = 'Checking XSS...'
        active_scans[scan_id]['progress'] = 50
        
        active_scans[scan_id]['current_step'] = 'Checking security headers...'
        active_scans[scan_id]['progress'] = 60
        
        active_scans[scan_id]['current_step'] = 'Checking SSL/TLS...'
        active_scans[scan_id]['progress'] = 70
        
        active_scans[scan_id]['current_step'] = 'Finalizing results...'
        active_scans[scan_id]['progress'] = 90
        
        # Run the actual scan
        results = scanner.scan()
        
        # Store results
        scan_results[scan_id] = results
        
        # Update status
        active_scans[scan_id]['status'] = 'completed'
        active_scans[scan_id]['progress'] = 100
        active_scans[scan_id]['current_step'] = 'Scan completed'
        active_scans[scan_id]['completed_at'] = datetime.now().isoformat()
        
    except Exception as e:
        active_scans[scan_id]['status'] = 'error'
        active_scans[scan_id]['error'] = str(e)
        active_scans[scan_id]['progress'] = 0

@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get the status of a running scan"""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(active_scans[scan_id])

@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get the results of a completed scan"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    results = scan_results[scan_id]
    
    # Calculate statistics
    severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for vuln in results.get('vulnerabilities', []):
        severity = vuln.get('severity', 'UNKNOWN')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Add summary
    results['summary'] = {
        'total_vulnerabilities': len(results.get('vulnerabilities', [])),
        'high_severity': severity_counts.get('HIGH', 0),
        'medium_severity': severity_counts.get('MEDIUM', 0),
        'low_severity': severity_counts.get('LOW', 0),
        'open_ports': len(results.get('open_ports', []))
    }
    
    return jsonify(results)

@app.route('/api/scan/<scan_id>/download', methods=['GET'])
def download_report(scan_id):
    """Download scan results as JSON"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    # Save to temporary file
    filename = f'scan_report_{scan_id}.json'
    filepath = os.path.join('/tmp', filename)
    
    with open(filepath, 'w') as f:
        json.dump(scan_results[scan_id], f, indent=2)
    
    return send_file(
        filepath,
        as_attachment=True,
        download_name=filename,
        mimetype='application/json'
    )

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'active_scans': len([s for s in active_scans.values() if s['status'] == 'running']),
        'completed_scans': len(scan_results)
    })

if __name__ == '__main__':
    print("""
╔════════════════════════════════════════════════════════╗
║     Web Vulnerability Scanner - Web Interface         ║
║     Access at: http://localhost:5000                  ║
╚════════════════════════════════════════════════════════╝
    """)
    app.run(debug=True, host='0.0.0.0', port=5000)
