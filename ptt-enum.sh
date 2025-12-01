#!/bin/bash

# Perform enumeration against a target

# ---------------------- helper functions block ----------------------

# Build a 'master' web directory worklist from many worklist
function build_master_wordlists() {
  echo "Building master directory wordlist"
  cat /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt > master-dir.txt
  cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt >> master-dir.txt
  cat /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt >> master-dir.txt
  cat /usr/share/seclists/Discovery/Web-Content/big.txt >> master-dir.txt
  sort -u -o master-dir.txt master-dir.txt
}

# Parse nmap scan result and extract port, state, service
function parse_nmap_results() {
  local nmap_file="$1"

  # Clear ports_list in case function is called multiple times
  ports_list=()

  while IFS= read -r line; do
    [[ -z $line ]] && continue
    read -r port state service _ <<<"$line"

    if [[ $port =~ ^([0-9]+)\/(tcp|udp)$ ]]; then
      portnum="${BASH_REMATCH[1]}"
      service="${service:-unknown}"
      [[ "${service,,}" == "http-proxy" ]] && service="http"
      state="${state:-unknown}"
      ports_list+=("${portnum}:${service}:${state}")
    fi
  done < <(awk '/^PORT[ \t]+STATE/{p=1; next} p' "$nmap_file")
}

# Display and manage ports list interactively
function manage_ports_list() {
  while true; do
    echo ""
    echo "========================================"
    echo "Parsed Ports List:"
    echo "========================================"
    if [ ${#ports_list[@]} -eq 0 ]; then
      echo "No ports found."
    else
      for i in "${!ports_list[@]}"; do
        IFS=':' read -r port service state <<<"${ports_list[$i]}"
        printf "[%2d] Port: %-6s Service: %-15s State: %s\n" "$i" "$port" "$service" "$state"
      done
    fi
    echo "========================================"
    echo ""

    # Ask user for action
    echo "Options:"
    echo "  (A)dd entry"
    echo "  (D)elete entry"
    echo "  (C)onfirm - all entries are correct"
    read -p "Choose an option [A/D/C]: " choice

    case "${choice,,}" in
      a)
        # Add entry
        read -p "Enter port number: " new_port
        read -p "Enter service name: " new_service

        # Validate input
        if [[ -n "$new_port" && "$new_port" =~ ^[0-9]+$ ]]; then
          new_service="${new_service:-unknown}"
          new_state="open"
          ports_list+=("${new_port}:${new_service}:${new_state}")
          echo "[+] Added entry: ${new_port}:${new_service}:${new_state}"
        else
          echo "[!] Invalid port number. Entry not added."
        fi
        ;;
      d)
        # Delete entry
        if [ ${#ports_list[@]} -eq 0 ]; then
          echo "[!] No entries to delete."
        else
          read -p "Enter index number to delete [0-$((${#ports_list[@]} - 1))]: " del_index
          if [[ "$del_index" =~ ^[0-9]+$ && "$del_index" -ge 0 && "$del_index" -lt ${#ports_list[@]} ]]; then
            echo "[+] Deleted entry: ${ports_list[$del_index]}"
            unset 'ports_list[$del_index]'
            # Re-index array to remove gaps
            ports_list=("${ports_list[@]}")
          else
            echo "[!] Invalid index. No entry deleted."
          fi
        fi
        ;;
      c)
        # Confirm and exit loop
        echo "[+] Ports list confirmed. Proceeding with scan..."
        break
        ;;
      *)
        echo "[!] Invalid option. Please choose A, D, or C."
        ;;
    esac
  done
}

# Wrap function calls
function safe_run() {
  local func_name="$1"
  local exit_code
  local start_time
  local end_time
  local elapsed_seconds
  local hours
  local minutes
  local seconds

  echo "[*] Running $func_name..."
  start_time=$(date +%s)

  if "$func_name"; then
    end_time=$(date +%s)
    elapsed_seconds=$((end_time - start_time))
    hours=$((elapsed_seconds / 3600))
    minutes=$(((elapsed_seconds % 3600) / 60))
    seconds=$((elapsed_seconds % 60))

    printf "[+] $func_name completed successfully (Elapsed time: %02d:%02d:%02d)\n" "$hours" "$minutes" "$seconds"
  else
    exit_code=$?
    end_time=$(date +%s)
    elapsed_seconds=$((end_time - start_time))
    hours=$((elapsed_seconds / 3600))
    minutes=$(((elapsed_seconds % 3600) / 60))
    seconds=$((elapsed_seconds % 60))

    printf "[!] $func_name failed with exit code $exit_code (Elapsed time: %02d:%02d:%02d)\n" "$hours" "$minutes" "$seconds"
  fi
}

# ---------------------- scanning functions block ----------------------

function run_gobuster() {
  # GoBuster Scan
  for entry in "${ports_list[@]}"; do
    IFS=':' read -r port service state <<<"$entry"
    
    # Skip ports that are not open
    [[ "$state" != "open" ]] && continue

    # Skip non http(s) ports
    [[ ! "${service,,}" =~ ^(https?)$ ]] && continue

    # Run GoBuster
    #gobuster dir -u "$service://${target}:$port" -w ./master-dir.txt -t 50 --timeout 30s --no-error -o "$outdir/gobuster.master-dir.$port.txt"

    cat ./master-dir.txt > "$outdir/gobuster.dir.txt"
    cat "$outdir/cewl.txt" >> "$outdir/gobuster.dir.txt"    

    echo "[*] Running: gobuster dir -u \"$service://${target}:$port\" -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -x old,bak,backup -t 50 --timeout 30s --no-error -o \"$outdir/gobuster.raft_files.$port.txt\""
    gobuster dir -u "$service://${target}:$port" -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -x old,bak,backup -t 50 --timeout 30s --no-error  -o "$outdir/gobuster.raft_files.$port.txt"

    echo "[*] Running: gobuster dir -u \"$service://${target}:$port\" -w ./master-dir.txt -x $webExtensions -t 50 --timeout 30s --no-error -o \"$outdir/gobuster.master-ext.$port.txt\""
    gobuster dir -u "$service://${target}:$port" -w "$outdir/gobuster.dir.txt" -x $webExtensions -t 50 --timeout 30s --no-error  -o "$outdir/gobuster.master-ext.$port.txt"

    # Combine all output in a single file
    sort -u "$outdir/gobuster.raft_files.$port.txt" "$outdir/gobuster.master-ext.$port.txt" -o "$outdir/gobuster_temp.$port.txt"
    sed -i -r 's/\x1B\[([0-9]{1,3}(;[0-9]{1,3})*)?[m|K]//g' "$outdir/gobuster_temp.$port.txt"
    cat "$outdir/gobuster_temp.$port.txt" | grep '(Status: 200)' > "$outdir/gobuster.$port.txt"
    cat "$outdir/gobuster_temp.$port.txt" | grep '(Status: 301)' >> "$outdir/gobuster.$port.txt"    
    echo -e $reportblock >> "$outdir/gobuster.$port.txt"
    cat "$outdir/gobuster_temp.$port.txt" >> "$outdir/gobuster.$port.txt"
    rm "$outdir/gobuster_temp.$port.txt"  
    mousepad "$outdir/gobuster.$port.txt" &
  done  
}

function run_nikto() {
  # Nikto Scan
  for entry in "${ports_list[@]}"; do
    IFS=':' read -r port service state <<<"$entry"
    
    # Skip ports that are not open
    [[ "$state" != "open" ]] && continue

    # Skip non http(s) ports
    [[ ! "${service,,}" =~ ^(https?|http-proxy)$ ]] && continue

    nikto -h $service://${target}:$port -ask no -o "$outdir/nikto.$port.txt"
    mousepad "$outdir/nikto.$port.txt" &
  done  
}

function run_whatweb() {
  # Whatweb Scan
  for entry in "${ports_list[@]}"; do
    IFS=':' read -r port service state <<<"$entry"
    
    # Skip ports that are not open
    [[ "$state" != "open" ]] && continue

    # Skip non http(s) ports
    [[ ! "${service,,}" =~ ^(https?|http-proxy)$ ]] && continue

    whatweb "$service://${target}:$port" --log-verbose="$outdir/whatweb.$port.txt"
    mousepad "$outdir/whatweb.$port.txt" &
  done  
}

function run_cewl() {
  # Generate wordlist
  for entry in "${ports_list[@]}"; do
    IFS=':' read -r port service state <<<"$entry"
    
    # Skip ports that are not open
    [[ "$state" != "open" ]] && continue

    # Skip non http(s) ports
    [[ ! "${service,,}" =~ ^(https?|http-proxy)$ ]] && continue

    cewl "$service://${target}:$port" -d 5 -m 4 -w "$outdir/cewl.$port.txt"
    cat "$outdir/cewl.$port.txt" >> "$outdir/cewl.txt"
  done  

  sort -u -o "$outdir/cewl.txt" "$outdir/cewl.txt"
}

function run_nmap() {
  if [[ $forcenmap == 0 && -f "$outdir/nmap.txt" ]]; then
    parse_nmap_results "$outdir/nmap.stage1.txt"
    manage_ports_list
    echo "nmap report already exists, skipping nmap scan"
    return
  fi

  # Stage 1 scan (quick TCP port scan)
  nmap -T4 -Pn -p- "$target" -oN $outdir/nmap.stage1.txt

  parse_nmap_results "$outdir/nmap.stage1.txt"
  manage_ports_list

  # Stage 2 scan (open port with script and detection)
  PORTLIST=""
  for entry in "${ports_list[@]}"; do
    IFS=':' read -r port service state <<<"$entry"
    PORTLIST="$PORTLIST$port,"
  done
  PORTLIST="${PORTLIST%,}"  # Remove trailing comma
  echo "Stage 2 ports: $PORTLIST"
  nmap -Pn -p $PORTLIST -A -T4 --script=default "$target" -oN $outdir/nmap.stage2.txt

  cat $outdir/nmap.stage1.txt > $outdir/nmap.txt
  echo -e $reportblock >> $outdir/nmap.txt
  cat $outdir/nmap.stage2.txt >> $outdir/nmap.txt
  #mousepad $outdir/nmap.txt &

  parse_nmap_results "$outdir/nmap.stage2.txt"
  manage_ports_list

}

# ---------------------------------- MAIN ----------------------------------

# Variables
declare -g -a ports_list=()
target=""
outdir=""
forcenmap=0
reportblock="\n------------------------------------------------------------------------------------------------------------\n"
webExtensions="sh,txt,php,html,htm,asp,aspx,js,jsp,xml,log,json,zip,tar.gz,tar,pdf"

#  Parse parameters
while getopts "t:o:f" opt; do
    case "$opt" in
        t) target="$OPTARG" ;;
        o) outdir="$OPTARG" ;;
        f) forcenmap=1 ;;
        *) echo "Usage: $0 -t <value> [-o <outdir>] [-f]"; exit 1 ;;
    esac
done

# Check if no IP address or domain provided
if [ -z "$target" ]; then
    echo "Error: No IP address/domain provided."
    echo "Usage: $0 -t <value>"    
    # show_help
    exit 1
fi

# Main
# Set default output directory if not specified with -o
if [ -z "$outdir" ]; then
    outdir="report_${target}"
fi

# Create output directory if it doesn't exist
if [ ! -d "$outdir" ]; then
    mkdir "$outdir"
fi

# Set error handling
exec 2> >(tee "$outdir/errors.log" >&2)
set -euo pipefail

# Check for combined wordlists
if [[ ! -f "./master-dir.txt" ]]; then
  build_master_wordlists
fi

safe_run run_nmap
safe_run run_whatweb
safe_run run_cewl
safe_run run_nikto
safe_run run_gobuster

# feroxbuster -u http://bubo -w ./master-dir.txt -x sh,txt,php,html,htm,asp,aspx,js,jsp,xml,log,json,zip,tar.gz,tar,pdf