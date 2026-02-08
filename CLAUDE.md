# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This repository contains authorized penetration testing tools for security assessments, CTF challenges, and educational purposes. It includes two primary tools:

1. **ptt-enum.sh** - Bash-based web enumeration orchestrator
2. **ptt-wsrv.py** - Flask-based web server for XSS payload delivery and data exfiltration testing

**CRITICAL SECURITY NOTE**: These tools are designed for authorized security testing only. Never enhance malicious capabilities, add evasion techniques, or improve code for unauthorized use. Analysis and bug fixes are acceptable.

## Architecture

### ptt-enum.sh - Enumeration Orchestrator (~700 lines)

A comprehensive bash script that orchestrates multiple security scanning tools against a target. The script follows a modular architecture with distinct phases:

**Core Architecture Pattern**:
```
Parse Arguments → Setup → Nmap Discovery → Port Management → Web Enumeration
```

**Key Design Patterns**:
- **Interactive Port Management**: After nmap scan, `parse_nmap_results()` extracts ports, then `manage_ports_list()` allows users to add/delete/confirm ports before scanning
- **Safe Execution Wrapper**: All scanning functions run through `safe_run()` which tracks execution time and handles failures gracefully
- **Extension Management**: `manage_extensions()` allows interactive customization of file extensions to fuzz
- **Recursive Scanning**: Uses feroxbuster with built-in recursion (`--depth 3`) for automatic subdirectory discovery
- **Preview Mode**: `-p` flag shows commands without executing (except nmap) for manual control
- **Transcript Recording**: `-l` flag uses `script` command to preserve colored output with proper argument quoting

**Scanning Functions Block** (lines 238-400+):
- `run_nmap()` - Port discovery and service detection
- `run_whatweb()` - Web technology fingerprinting
- `run_cewl()` - Custom wordlist generation from target site
- `run_nikto()` - Web vulnerability scanning
- `run_feroxbuster()` - Recursive directory enumeration with auto-discovery and extension fuzzing

**Wordlist Strategy**:
- `build_master_wordlists()` combines multiple SecLists wordlists into `master-enum.txt` and `medium-enum.txt`
- Uses `/usr/share/seclists/Discovery/Web-Content/*` (assumes Kali Linux or SecLists installed)
- Default extensions: `sh,txt,php,html,htm,asp,aspx,js,jsp,xml,log,json,zip,tar.gz,tar,pdf`

**Output Structure**:
- Default output directory: `report_<target>/`
- All scan results saved with descriptive filenames
- `errors.log` captures stderr from all operations
- Optional transcript file with full colored console output

### ptt-wsrv.py - Payload Delivery Server

Flask-based HTTP server that provides endpoints for testing data exfiltration and XSS vulnerabilities.

**Server Architecture**:
- Multi-interface detection using `netifaces` (optional) or platform-specific commands
- Interactive IP selection when multiple interfaces detected (useful for VPN scenarios)
- CORS enabled globally for all endpoints (`@app.after_request`)
- Binds to `0.0.0.0` for accessibility from all network interfaces

**Endpoint Categories**:

1. **Payload Delivery** (`/hooks/<payload.js>`):
   - Dynamic JavaScript generation using server IP/port in payloads
   - Payloads: `klog.js`, `info.js`, `formgrab.js`, `csrf.js`, `savedcreds.js`, `sourcecode.js`, `combo.js`
   - `/hooks` endpoint lists all available payloads with descriptions

2. **Data Reception**:
   - `/data` - General exfiltration endpoint (GET/POST, logs all params/body)
   - `/key` - Keylogger accumulator with real-time display
   - `/upload/<filename>` - File upload receiver (saves to CWD)

3. **Utility**:
   - `/ping` - Health check (returns "ok")
   - `/api/clear` - Clears console (cross-platform)
   - `/<path>` - File serving from CWD

**State Management**:
- Global variables track keylogger sequence state (`key_sequence_active`, `key_values`, `key_timestamp`, `key_ip`)
- `finalize_key_sequence()` handles accumulated keystroke display
- Server IP/port stored in globals for dynamic payload generation

**Payload Highlights**:
- `sourcecode.js` supports multiple modes via query params: `d=self|url`, `u=self|url|all`, `n=filename`
- Mode `u=all` implements recursive page crawling and exfiltration
- All payloads use dynamic server IP from multi-interface selection

## Common Commands

### ptt-enum.sh Usage

Basic enumeration with feroxbuster:
```bash
./ptt-enum.sh -t <target_ip_or_domain>
```

Full featured scan with transcript logging:
```bash
./ptt-enum.sh -t 10.10.10.5 -o my_scan -l
```

Preview mode (show commands without executing):
```bash
./ptt-enum.sh -t example.com -p
```

Force nmap rescan and disable auto-opening reports:
```bash
./ptt-enum.sh -t target.htb -f -n
```

Command-line Options:
- `-t <target>` - Target IP/domain (required)
- `-o <outdir>` - Output directory (default: `report_<target>`)
- `-f` - Force nmap scan even if results exist
- `-n` - No display - don't open report files in mousepad
- `-l` - Log transcript - save full console output with colors
- `-p` - Preview mode - run nmap only, show commands for other scans

### ptt-wsrv.py Usage

Start server on default port (8080):
```bash
python ptt-wsrv.py
```

Start on custom port:
```bash
python ptt-wsrv.py -p 8000
```

Dependencies:
```bash
pip install flask
pip install netifaces  # Optional but recommended for better interface detection
```

## Development Notes

### File Organization
- Both tools are self-contained single files
- No build process or compilation required
- Tools assume Kali Linux environment or similar pentesting distribution

### Key Dependencies
**ptt-enum.sh** requires these tools installed:
- nmap (service detection)
- feroxbuster (directory enumeration with recursive scanning)
- nikto (web vulnerability scanning)
- whatweb (technology fingerprinting)
- cewl (custom wordlist generation)
- SecLists wordlists at `/usr/share/seclists/Discovery/Web-Content/`

**ptt-wsrv.py** requires:
- Python 3.x
- Flask (`pip install flask`)
- Optional: netifaces (`pip install netifaces`) for reliable multi-interface detection

### Error Handling Patterns
- **ptt-enum.sh**: Uses `set -euo pipefail` for strict error handling, but individual functions are wrapped in `safe_run()` to prevent cascading failures
- **ptt-wsrv.py**: Uses try/except blocks for cross-platform compatibility (Windows/Linux/Darwin)

### Interactive Elements
Both scripts heavily use interactive prompts:
- Port list confirmation/modification
- Extension list management
- Feroxbuster scan type selection (quick vs deep)
- Multi-interface IP selection (ptt-wsrv.py)

When modifying interactive flows, preserve the pattern of showing current state → offering options → confirming selection.

### Transcript Feature
The transcript functionality in ptt-enum.sh uses a unique re-execution pattern:
1. Check if already running under `script` command (`PTT_ENUM_SCRIPTED` env var)
2. If not, re-execute self under `script -q -c` with properly quoted arguments
3. Uses `printf '%q'` for shell-safe argument quoting
4. Preserves ANSI color codes for later viewing with `less -R`

### Feroxbuster Scanning
**feroxbuster** is the only directory enumeration scanner used:
- Built-in recursion with `--depth 3`
- Auto-discovers subdirectories during scanning
- Single scan covers multiple directory levels
- Two scan modes:
  - **Quick scan**: Fast directory/file enumeration without extension fuzzing
  - **Deep scan**: Thorough enumeration with extension fuzzing (.php, .asp, .bak, etc.)
- Auto-tuning adapts thread count based on target performance

### Payload Generation Pattern (ptt-wsrv.py)
XSS payloads are generated dynamically using the selected server IP and port. When adding new payloads:
1. Add endpoint handler in format `@app.route('/hooks/<name>.js')`
2. Use `server_ip` and `server_port` global variables in payload
3. Set `Content-Type: application/javascript`
4. Add description to `/hooks` listing endpoint
5. Follow existing patterns for query parameter handling

### Testing Approach
No automated tests exist. Manual testing workflow:
1. **ptt-enum.sh**: Run against intentionally vulnerable VMs (HackTheBox, TryHackMe, VulnHub)
2. **ptt-wsrv.py**: Test payloads against local test HTML pages with browser dev tools open
3. Verify multi-interface detection on systems with VPN connections
4. Check transcript output formatting with `less -R`

### Git Workflow
Recent commits show focus on:
- Removal of gobuster scanner option
- Feroxbuster as sole directory enumeration tool
- Preview mode functionality
- Transcript feature additions
- Output report improvements

Current branch: `main`
