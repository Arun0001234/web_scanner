# Web Interface Setup Guide

## 🌐 VulnScanner Web Interface

A beautiful, modern web-based vulnerability scanner that anyone can use!

## Features

✅ **Beautiful Modern UI** - Cyberpunk-inspired design with animations
✅ **Real-time Progress** - Live updates during scanning
✅ **Interactive Results** - Tabbed interface for vulnerabilities, ports, and raw data
✅ **One-Click Reports** - Download complete JSON reports
✅ **No Installation for Users** - Just open a browser!

## Installation

### Step 1: Install Dependencies

```bash
pip install -r requirements_web.txt
```

Or install manually:
```bash
pip install Flask Flask-CORS requests beautifulsoup4 lxml
```

### Step 2: Verify Files

Make sure you have these files in your directory:
```
scanner/
├── web_scanner_app.py       (Flask backend)
├── enhanced_scanner.py       (Scanner logic)
├── port_scanner.py          (Port scanning)
├── templates/
│   └── index.html           (Web interface)
└── requirements_web.txt     (Dependencies)
```

## Running the Web Interface

### Option 1: Simple Start

```bash
python web_scanner_app.py
```

### Option 2: Windows Batch File

Create `start_web.bat`:
```batch
@echo off
echo Starting VulnScanner Web Interface...
python web_scanner_app.py
pause
```

Then double-click `start_web.bat`

## Accessing the Interface

Once started, you'll see:
```
╔════════════════════════════════════════════════════════╗
║     Web Vulnerability Scanner - Web Interface         ║
║     Access at: http://localhost:5000                  ║
╚════════════════════════════════════════════════════════╝
```

**Open your browser and go to:**
```
http://localhost:5000
```

## Using the Web Interface

### 1. Enter Target URL
- Type or paste the URL you want to scan
- Example: `http://testphp.vulnweb.com`
- Example: `https://example.com`

### 2. Configure Options
- ✅ **Include Port Scanning** - Check to scan ports + vulnerabilities
- ⬜ **Include Port Scanning** - Uncheck for web vulnerabilities only

### 3. Start Scan
- Click the **"Start Security Scan"** button
- Watch real-time progress with percentage and current step
- Typical scan takes 30-60 seconds

### 4. View Results
Results are organized in tabs:

**📊 Summary Cards:**
- High Severity Issues (Red)
- Medium Severity Issues (Yellow)
- Low Severity Issues (Green)
- Open Ports Found (Blue)

**🔍 Vulnerabilities Tab:**
- Detailed list of all security issues
- Color-coded by severity
- Includes evidence and recommendations

**🔌 Open Ports Tab:**
- All detected open ports
- Service identification
- Version information

**📄 Raw JSON Tab:**
- Complete scan data in JSON format
- Technical details for developers

### 5. Download Report
- Click **"Download Full Report (JSON)"**
- Saves complete scan results
- Can be shared with security team

## Features Explained

### Real-Time Progress
- Live percentage updates
- Current scan step displayed
- Smooth animated progress bar

### Beautiful UI
- Cyberpunk-inspired design
- Animated background grid
- Glowing effects and transitions
- Fully responsive (mobile-friendly)

### Security Categories

**High Severity (Red):**
- SQL Injection
- Cross-Site Scripting (XSS)
- Exposed Databases
- Insecure Protocols

**Medium Severity (Yellow):**
- Missing Security Headers
- CSRF Vulnerabilities
- Insecure Cookies
- Exposed Services

**Low Severity (Green):**
- Information Disclosure
- Version Information
- Missing Headers

## Example Scans

### Test Vulnerable Application

**Scan a known vulnerable site:**
```
URL: http://testphp.vulnweb.com
Options: ✅ Include Port Scanning

Expected Results:
- SQL Injection vulnerabilities
- XSS vulnerabilities
- Missing security headers
- Open ports (80, 443)
```

### Scan Localhost

**Test your own application:**
```
URL: http://localhost:8080
Options: ✅ Include Port Scanning

This scans your local development server
```

### Quick Web-Only Scan

**Fast scan without port scanning:**
```
URL: https://example.com
Options: ⬜ Include Port Scanning

Faster scan, web vulnerabilities only
```

## Architecture

### Backend (Flask)
- `web_scanner_app.py` - API server
- Handles scan requests
- Manages scan status
- Serves results

### Frontend (HTML/CSS/JS)
- `templates/index.html` - Web interface
- Real-time progress updates
- Interactive results display
- Beautiful animations

### Scanner Engine
- `enhanced_scanner.py` - Core scanning logic
- `port_scanner.py` - Port detection

## API Endpoints

The web interface uses these API endpoints:

### Start Scan
```
POST /api/scan
Body: {
  "url": "https://example.com",
  "scan_ports": true
}
Response: {
  "scan_id": "uuid",
  "message": "Scan started"
}
```

### Check Status
```
GET /api/scan/<scan_id>/status
Response: {
  "status": "running",
  "progress": 50,
  "current_step": "Checking SQL Injection..."
}
```

### Get Results
```
GET /api/scan/<scan_id>/results
Response: {
  "target": "https://example.com",
  "vulnerabilities": [...],
  "open_ports": [...],
  "summary": {...}
}
```

### Download Report
```
GET /api/scan/<scan_id>/download
Response: JSON file download
```

## Customization

### Change Port
Edit `web_scanner_app.py`:
```python
app.run(debug=True, host='0.0.0.0', port=8080)  # Change 5000 to 8080
```

### Change Theme Colors
Edit `templates/index.html` CSS variables:
```css
:root {
    --accent-primary: #00ff88;    /* Change to your color */
    --accent-secondary: #00d4ff;  /* Change to your color */
    --bg-dark: #0a0e27;          /* Background color */
}
```

### Add Custom Checks
Extend `enhanced_scanner.py` with new scan modules.

## Troubleshooting

### Issue: Port 5000 already in use
**Solution:**
```bash
# Windows - Kill process on port 5000
netstat -ano | findstr :5000
taskkill /PID <process_id> /F

# Or change port in web_scanner_app.py
```

### Issue: Can't access from other computers
**Solution:**
The scanner runs on `0.0.0.0` so it's accessible from network.
Access from other devices using:
```
http://YOUR_IP_ADDRESS:5000
```

Find your IP:
```bash
# Windows
ipconfig

# Look for IPv4 Address
```

### Issue: Scan gets stuck
**Solution:**
- Check target URL is accessible
- Try with port scanning disabled
- Restart the web server

### Issue: Results not showing
**Solution:**
- Check browser console (F12)
- Verify backend is running
- Try refreshing the page

## Security Considerations

⚠️ **IMPORTANT:**

1. **Only scan sites you own or have permission to test**
2. **Do not expose this publicly without authentication**
3. **Use only in controlled environments**
4. **This is for ethical security testing only**

### Adding Authentication (Optional)

For production use, add basic authentication:

```python
from flask import request, abort

@app.before_request
def check_auth():
    auth = request.authorization
    if not auth or not (auth.username == 'admin' and auth.password == 'password'):
        return abort(401)
```

## Advanced Usage

### Running on Network

**Make accessible to other devices:**
```bash
python web_scanner_app.py
# Access from other devices: http://192.168.1.100:5000
```

### Running as Service (Windows)

Use NSSM (Non-Sucking Service Manager):
```bash
nssm install VulnScanner "C:\Python\python.exe" "C:\scanner\web_scanner_app.py"
nssm start VulnScanner
```

### Running with Gunicorn (Production)

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 web_scanner_app:app
```

## Tips & Best Practices

### For Best Results:
1. ✅ Start with port scanning enabled
2. ✅ Use on test/staging environments first
3. ✅ Review results carefully (check for false positives)
4. ✅ Download reports for documentation
5. ✅ Re-scan after fixing issues

### For Fast Scans:
1. ⚡ Disable port scanning for quick checks
2. ⚡ Scan specific pages with parameters
3. ⚡ Use the simple_scanner.py for basic checks

### For Comprehensive Scans:
1. 🔍 Enable all options
2. 🔍 Scan multiple pages separately
3. 🔍 Compare with other security tools
4. 🔍 Manual verification of findings

## Comparison with CLI Scanners

| Feature | Web Interface | CLI Scanner |
|---------|--------------|-------------|
| Ease of Use | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| Real-time Progress | ✅ Yes | ❌ No |
| Beautiful UI | ✅ Yes | ❌ No |
| Download Reports | ✅ Yes | ✅ Yes |
| Speed | Same | Same |
| Remote Access | ✅ Yes | ❌ No |
| Automation | ❌ No | ✅ Yes |

## Screenshot Tour

### Main Screen
- Large input field for URL
- Checkbox for port scanning option
- Prominent "Start Security Scan" button
- Clean, cyberpunk-themed design

### Scanning Progress
- Animated progress bar (0-100%)
- Current scan step displayed
- Real-time percentage updates
- Smooth transitions

### Results Dashboard
- Four summary cards (High/Med/Low/Ports)
- Color-coded by severity
- Large numbers for quick overview
- Hover effects and animations

### Vulnerabilities List
- Detailed vulnerability cards
- Severity badges (Red/Yellow/Green)
- Evidence and recommendations
- Organized and readable

### Ports List
- Open ports with service names
- Version detection
- Color-coded cards
- Easy to scan quickly

## Next Steps

1. ✅ Install dependencies: `pip install -r requirements_web.txt`
2. ✅ Start web server: `python web_scanner_app.py`
3. ✅ Open browser: `http://localhost:5000`
4. ✅ Enter target URL
5. ✅ Click "Start Security Scan"
6. ✅ Review results
7. ✅ Download report

## Support & Feedback

For issues or questions:
- Check the error in browser console (F12)
- Verify all files are present
- Ensure dependencies are installed
- Try the CLI scanner first to test

## Legal Disclaimer

This tool is for authorized security testing only. Unauthorized scanning of websites is illegal. Always obtain written permission before scanning any system you do not own. The authors are not responsible for misuse of this tool.

---

**Enjoy your professional vulnerability scanner with a beautiful web interface! 🔒✨**
