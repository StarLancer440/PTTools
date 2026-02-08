#!/bin/bash

# Perform enumeration against a target

# Save original arguments for transcript re-execution
ORIGINAL_ARGS=("$@")

# ---------------------- helper functions block ----------------------

# Build a 'master' web enumaration wordlist from many wordlist
function build_master_wordlists() {
  echo "Building master enumaration wordlist"
  cat /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt > master-enum.txt
  cat /usr/share/seclists/Discovery/Web-Content/combined_directories.txt >> master-enum.txt
  cat /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt > medium-enum.txt
  cat /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt > medium-enum.tmp.txt
  cat /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt > medium-enum.tmp.txt
  sort -u -o medium-enum.tmp.txt medium-enum.tmp.txt
  cat medium-enum.tmp.txt >> medium-enum.txt  
  rm medium-enum.tmp.txt
}

# copy of reference
#function build_master_wordlists() {
#  echo "Building master enumaration wordlist"
#  cat /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt > master-enum.txt
#  cat /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt >> master-enum.txt
#  cat /usr/share/seclists/Discovery/Web-Content/big.txt >> master-enum.txt
#  sort -u -o master-enum.txt master-enum.txt
#}


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
    echo "  (C)onfirm - all entries are correct (default)"
    read -p "Choose an option [A/D/C (default)]: " choice

    # Set default to 'c' if empty
    choice="${choice:-c}"

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

# Display and manage web extensions list interactively
function manage_extensions() {
  # Convert comma-separated string to array
  IFS=',' read -ra ext_array <<< "$webExtensions"

  while true; do
    echo ""
    echo "========================================"
    echo "Web Extensions List:"
    echo "========================================"
    if [ ${#ext_array[@]} -eq 0 ]; then
      echo "No extensions configured."
    else
      for i in "${!ext_array[@]}"; do
        printf "[%2d] %s\n" "$i" "${ext_array[$i]}"
      done
    fi
    echo "========================================"
    echo ""

    # Ask user for action
    echo "Options:"
    echo "  (A)dd extension"
    echo "  (D)elete extension"
    echo "  (C)onfirm - all extensions are correct (default)"
    read -p "Choose an option [A/D/C (default)]: " choice

    # Set default to 'c' if empty
    choice="${choice:-c}"

    case "${choice,,}" in
      a)
        # Add extension
        read -p "Enter extension to add (without dot, e.g., 'py' or 'tar.gz'): " new_ext

        # Validate input - basic check for valid extension format
        if [[ -n "$new_ext" && "$new_ext" =~ ^[a-zA-Z0-9.]+$ ]]; then
          # Check if extension already exists
          if [[ " ${ext_array[*]} " =~ " ${new_ext} " ]]; then
            echo "[!] Extension '$new_ext' already exists in the list."
          else
            ext_array+=("$new_ext")
            echo "[+] Added extension: $new_ext"
          fi
        else
          echo "[!] Invalid extension format. Extension not added."
        fi
        ;;
      d)
        # Delete extension
        if [ ${#ext_array[@]} -eq 0 ]; then
          echo "[!] No extensions to delete."
        else
          read -p "Enter index number to delete [0-$((${#ext_array[@]} - 1))]: " del_index
          if [[ "$del_index" =~ ^[0-9]+$ && "$del_index" -ge 0 && "$del_index" -lt ${#ext_array[@]} ]]; then
            echo "[+] Deleted extension: ${ext_array[$del_index]}"
            unset 'ext_array[$del_index]'
            # Re-index array to remove gaps
            ext_array=("${ext_array[@]}")
          else
            echo "[!] Invalid index. No extension deleted."
          fi
        fi
        ;;
      c)
        # Confirm and exit loop
        # Convert array back to comma-separated string
        webExtensions=$(IFS=','; echo "${ext_array[*]}")
        echo "[+] Extensions list confirmed: $webExtensions"
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

function run_feroxbuster() {
  # Feroxbuster Recursive Scan
  #
  # Built-in recursion (--depth 3) automatically scans discovered directories
  # Auto-tuning adapts thread count based on target performance (starts conservative, increases if stable)
  # Combined wordlists and extensions reduce total scan time and improve thoroughness
  #
  # Quick scan: Directories and files only, no extension fuzzing (faster)
  # Deep scan: Full extension fuzzing with combined wordlists (thorough)
  #
  for entry in "${ports_list[@]}"; do
    IFS=':' read -r port service state <<<"$entry"

    # Skip ports that are not open
    [[ "$state" != "open" ]] && continue

    # Skip non http(s) ports
    [[ ! "${service,,}" =~ ^(https?)$ ]] && continue

    # Prompt user for scan type with validation
    local scan_choice=""
    while [[ ! "$scan_choice" =~ ^[12]$ ]]; do
      echo ""
      echo "[*] Feroxbuster scan options for $service://${target}:$port"
      echo "  [1] Quick scan - Directories and files only (no extension fuzzing)"
      echo "  [2] Deep scan  - Full extension fuzzing (includes .php, .asp, .bak, etc.)"
      echo ""
      read -p "Select scan type (1 or 2): " scan_choice

      if [[ ! "$scan_choice" =~ ^[12]$ ]]; then
        echo "[!] Invalid choice. Please enter 1 or 2."
      fi
    done

    # Prepare combined wordlist (directories + files + cewl)
    echo "[*] Preparing combined wordlist for comprehensive scan..."
    cat "$outdir/cewl.txt" > "$outdir/feroxbuster.combined.txt"
    cat ./master-enum.txt >> "$outdir/feroxbuster.combined.txt"
    cat "$outdir/cewl.txt" > "$outdir/feroxbuster.medium.txt"
    cat ./medium-enum.txt >> "$outdir/feroxbuster.medium.txt"

    # Determine which scans to run
    local run_quick=0
    local run_deep=0

    if [[ "$scan_choice" == "1" ]]; then
      run_quick=1
      # We'll ask about deep scan after quick completes
    else
      run_deep=1
    fi

    # RUN QUICK SCAN if requested
    if [[ $run_quick -eq 1 ]]; then
      echo "[*] Running QUICK feroxbuster scan on: $service://${target}:$port"
      echo "[*] Combined wordlist size: $(wc -l < "$outdir/feroxbuster.medium.txt") unique entries"
      echo -e "\n\033[1;33m>>>\033[0m \033[1;36mferoxbuster -u \"$service://${target}:$port\" -w \"$outdir/feroxbuster.medium.txt\" --depth 3 --timeout 30 --scan-limit 2 --filter-status 404 -o \"$outdir/feroxbuster.quick.raw.$port.txt\"\033[0m\n"

      if [[ $preview -eq 1 ]]; then
        echo "[PREVIEW] Command not executed - preview mode enabled"
      else
        feroxbuster -u "$service://${target}:$port" \
          -w "$outdir/feroxbuster.medium.txt" \
          --depth 3 \
          --timeout 30 \
          --scan-limit 2 \
          --filter-status 404 \
          -o "$outdir/feroxbuster.quick.raw.$port.txt" < /dev/tty

        # Process and format QUICK scan output immediately
        echo "[*] Processing quick scan results..."

        # Remove ANSI color codes from quick scan
        sed -i -r 's/\x1B\[([0-9]{1,3}(;[0-9]{1,3})*)?[m|K]//g' "$outdir/feroxbuster.quick.raw.$port.txt"

        # Add command header to output file
        echo "COMMAND USED:" > "$outdir/feroxbuster.quick.$port.txt"
        echo "feroxbuster -u \"$service://${target}:$port\" -w \"$outdir/feroxbuster.medium.txt\" --depth 3 --timeout 30 --scan-limit 2 --filter-status 404 -o \"$outdir/feroxbuster.quick.raw.$port.txt\"" >> "$outdir/feroxbuster.quick.$port.txt"
        echo -e $reportblock >> "$outdir/feroxbuster.quick.$port.txt"

        # Extract and sort quick scan results into temp file
        temp_sorted=$(mktemp)
        grep -E '^200[[:space:]]' "$outdir/feroxbuster.quick.raw.$port.txt" 2>/dev/null > "$temp_sorted" || touch "$temp_sorted"
        grep -E '^301[[:space:]]' "$outdir/feroxbuster.quick.raw.$port.txt" 2>/dev/null >> "$temp_sorted" || true
        grep -E '^302[[:space:]]' "$outdir/feroxbuster.quick.raw.$port.txt" 2>/dev/null >> "$temp_sorted" || true

        # Sort and remove duplicates, then append to output
        sort -u -f "$temp_sorted" >> "$outdir/feroxbuster.quick.$port.txt"
        rm "$temp_sorted"

        # Add separator
        echo -e $reportblock >> "$outdir/feroxbuster.quick.$port.txt"

        # Keep original unsorted and non unique
        grep -E '^200[[:space:]]' "$outdir/feroxbuster.quick.raw.$port.txt" 2>/dev/null >> "$outdir/feroxbuster.quick.$port.txt" || true
        grep -E '^301[[:space:]]' "$outdir/feroxbuster.quick.raw.$port.txt" 2>/dev/null >> "$outdir/feroxbuster.quick.$port.txt" || true
        grep -E '^302[[:space:]]' "$outdir/feroxbuster.quick.raw.$port.txt" 2>/dev/null >> "$outdir/feroxbuster.quick.$port.txt" || true

        # Add separator
        echo -e $reportblock >> "$outdir/feroxbuster.quick.$port.txt"

        # Append full output for reference
        cat "$outdir/feroxbuster.quick.raw.$port.txt" >> "$outdir/feroxbuster.quick.$port.txt"

        # Open quick scan results in editor if not suppressed
        [[ $nodisplay -eq 0 ]] && setsid mousepad "$outdir/feroxbuster.quick.$port.txt" &

        # Ask if user wants to also run deep scan
        echo ""
        read -p "Quick scan complete. Do you also want to run a DEEP scan with extension fuzzing? (y/n): " run_deep_choice
        [[ "$run_deep_choice" =~ ^[Yy]$ ]] && run_deep=1
      fi

      # Always display deep scan command for reference (even after quick scan or in preview mode)
      local ref_extensions="${webExtensions},old,bak,backup"
      echo ""
      echo "[*] Deep scan command for manual execution later:"
      echo -e "\033[1;33m>>>\033[0m \033[1;36mferoxbuster -u \"$service://${target}:$port\" -w \"$outdir/feroxbuster.combined.txt\" -x $ref_extensions --depth 3 --timeout 30 --threads 100 --scan-limit 3 --filter-status 404 -o \"$outdir/feroxbuster.deep.raw.$port.txt\"\033[0m"
      echo ""
    fi

    # RUN DEEP SCAN if requested (either directly or after quick scan)
    if [[ $run_deep -eq 1 ]]; then
      local combined_extensions="${webExtensions},old,bak,backup"

      # In preview mode, skip interactive prompts
      if [[ $preview -eq 0 ]]; then
        # Display current extensions and offer to modify
        echo ""
        echo "========================================"
        echo "Current Web Extensions:"
        echo "========================================"
        echo "$webExtensions"
        echo "========================================"
        echo ""

        read -p "Do you want to modify the extensions list? (y/n): " modify_ext
        if [[ "$modify_ext" =~ ^[Yy]$ ]]; then
          manage_extensions
        fi
        combined_extensions="${webExtensions},old,bak,backup"
      fi

      echo ""
      echo "[*] Running DEEP feroxbuster scan with extension fuzzing on: $service://${target}:$port"
      echo "[*] Using extensions: $combined_extensions"
      echo "[*] Combined wordlist size: $(wc -l < "$outdir/feroxbuster.combined.txt") unique entries"
      echo -e "\n\033[1;33m>>>\033[0m \033[1;36mferoxbuster -u \"$service://${target}:$port\" -w \"$outdir/feroxbuster.combined.txt\" -x $combined_extensions --depth 3 --timeout 30 --threads 100 --scan-limit 3 --filter-status 404 -o \"$outdir/feroxbuster.deep.raw.$port.txt\"\033[0m\n"

      if [[ $preview -eq 1 ]]; then
        echo "[PREVIEW] Command not executed - preview mode enabled"
      else
        # Run feroxbuster scan with combined wordlist and extensions
        # --depth 3: recursively scan directories up to 3 levels deep
        # --timeout 30: 30 second timeout
        # --threads 100: use 100 threads for deep scan
        feroxbuster -u "$service://${target}:$port" \
          -w "$outdir/feroxbuster.combined.txt" \
          -x $combined_extensions \
          --depth 3 \
          --timeout 30 \
          --threads 100 \
          --scan-limit 3 \
          --filter-status 404 \
          -o "$outdir/feroxbuster.deep.raw.$port.txt" < /dev/tty

        # Process and format DEEP scan output immediately
        echo "[*] Processing deep scan results..."

        # Remove ANSI color codes from deep scan
        sed -i -r 's/\x1B\[([0-9]{1,3}(;[0-9]{1,3})*)?[m|K]//g' "$outdir/feroxbuster.deep.raw.$port.txt"

        # Add command header to output file
        echo "COMMAND USED:" > "$outdir/feroxbuster.deep.$port.txt"
        echo "feroxbuster -u \"$service://${target}:$port\" -w \"$outdir/feroxbuster.combined.txt\" -x $combined_extensions --depth 3 --timeout 30 --threads 100 --scan-limit 3 --filter-status 404 -o \"$outdir/feroxbuster.deep.raw.$port.txt\"" >> "$outdir/feroxbuster.deep.$port.txt"
        echo -e $reportblock >> "$outdir/feroxbuster.deep.$port.txt"

        # Extract and sort deep scan results into temp file
        temp_sorted=$(mktemp)
        grep -E '^200[[:space:]]' "$outdir/feroxbuster.deep.raw.$port.txt" 2>/dev/null > "$temp_sorted" || touch "$temp_sorted"
        grep -E '^301[[:space:]]' "$outdir/feroxbuster.deep.raw.$port.txt" 2>/dev/null >> "$temp_sorted" || true
        grep -E '^302[[:space:]]' "$outdir/feroxbuster.deep.raw.$port.txt" 2>/dev/null >> "$temp_sorted" || true

        # Sort and remove duplicates, then append to output
        sort -u -f "$temp_sorted" >> "$outdir/feroxbuster.deep.$port.txt"
        rm "$temp_sorted"

        # Add separator
        echo -e $reportblock >> "$outdir/feroxbuster.deep.$port.txt"

        # Keep original unsorted and non unique
        grep -E '^200[[:space:]]' "$outdir/feroxbuster.deep.raw.$port.txt" 2>/dev/null >> "$outdir/feroxbuster.deep.$port.txt" || true
        grep -E '^301[[:space:]]' "$outdir/feroxbuster.deep.raw.$port.txt" 2>/dev/null >> "$outdir/feroxbuster.deep.$port.txt" || true
        grep -E '^302[[:space:]]' "$outdir/feroxbuster.deep.raw.$port.txt" 2>/dev/null >> "$outdir/feroxbuster.deep.$port.txt" || true

        # Add separator
        echo -e $reportblock >> "$outdir/feroxbuster.deep.$port.txt"

        # Append full output for reference
        cat "$outdir/feroxbuster.deep.raw.$port.txt" >> "$outdir/feroxbuster.deep.$port.txt"

        # Open deep scan results in editor if not suppressed
        [[ $nodisplay -eq 0 ]] && setsid mousepad "$outdir/feroxbuster.deep.$port.txt" &
      fi
    fi
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

    # Check if nikto output already exists for this port
    if [[ -f "$outdir/nikto.$port.txt" ]]; then
      echo "nikto report for port $port already exists, skipping scan"
      continue
    fi

    echo -e "\n\033[1;33m>>>\033[0m \033[1;36mnikto -h $service://${target}:$port -ask no -o \"$outdir/nikto.$port.txt\"\033[0m\n"
    if [[ $preview -eq 1 ]]; then
      echo "[PREVIEW] Command not executed - preview mode enabled"
    else
      nikto -h $service://${target}:$port -ask no -o "$outdir/nikto.$port.txt"

      # Prepend command to output file
      temp_file=$(mktemp)
      echo "COMMAND USED:" > "$temp_file"
      echo "nikto -h $service://${target}:$port -ask no -o \"$outdir/nikto.$port.txt\"" >> "$temp_file"
      echo -e $reportblock >> "$temp_file"
      cat "$outdir/nikto.$port.txt" >> "$temp_file"
      mv "$temp_file" "$outdir/nikto.$port.txt"

      [[ $nodisplay -eq 0 ]] && setsid mousepad "$outdir/nikto.$port.txt" &
    fi
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

    # Check if whatweb output already exists for this port
    if [[ -f "$outdir/whatweb.$port.txt" ]]; then
      echo "whatweb report for port $port already exists, skipping scan"
      continue
    fi

    echo -e "\n\033[1;33m>>>\033[0m \033[1;36mwhatweb \"$service://${target}:$port\" --log-verbose=\"$outdir/whatweb.$port.txt\"\033[0m\n"
    if [[ $preview -eq 1 ]]; then
      echo "[PREVIEW] Command not executed - preview mode enabled"
    else
      whatweb "$service://${target}:$port" --log-verbose="$outdir/whatweb.$port.txt"

      # Prepend command to output file
      temp_file=$(mktemp)
      echo "COMMAND USED:" > "$temp_file"
      echo "whatweb \"$service://${target}:$port\" --log-verbose=\"$outdir/whatweb.$port.txt\"" >> "$temp_file"
      echo -e $reportblock >> "$temp_file"
      cat "$outdir/whatweb.$port.txt" >> "$temp_file"
      mv "$temp_file" "$outdir/whatweb.$port.txt"

      [[ $nodisplay -eq 0 ]] && setsid mousepad "$outdir/whatweb.$port.txt" &
    fi
  done
}

function run_cewl() {
  # Check if cewl output already exists
  if [[ -f "$outdir/cewl.txt" ]]; then
    echo "cewl wordlist already exists, skipping cewl scan"
    return
  fi

  # Generate wordlist
  for entry in "${ports_list[@]}"; do
    IFS=':' read -r port service state <<<"$entry"

    # Skip ports that are not open
    [[ "$state" != "open" ]] && continue

    # Skip non http(s) ports
    [[ ! "${service,,}" =~ ^(https?|http-proxy)$ ]] && continue

    echo -e "\n\033[1;33m>>>\033[0m \033[1;36mcewl \"$service://${target}:$port\" -d 5 -m 4 -w \"$outdir/cewl.$port.txt\"\033[0m\n"
    # Always run cewl even in preview mode - wordlist is used by other tools
    cewl "$service://${target}:$port" -d 5 -m 4 -w "$outdir/cewl.$port.txt"
    cat "$outdir/cewl.$port.txt" >> "$outdir/cewl.txt"
  done

  # Sort and deduplicate if cewl.txt was created
  if [[ -f "$outdir/cewl.txt" ]]; then
    # Create temp file with command header
    temp_file=$(mktemp)
    echo "COMMAND USED:" > "$temp_file"
    for entry in "${ports_list[@]}"; do
      IFS=':' read -r port service state <<<"$entry"
      [[ "$state" != "open" ]] && continue
      [[ ! "${service,,}" =~ ^(https?|http-proxy)$ ]] && continue
      echo "cewl \"$service://${target}:$port\" -d 5 -m 4 -w \"$outdir/cewl.$port.txt\"" >> "$temp_file"
    done
    echo -e $reportblock >> "$temp_file"

    # Sort and append wordlist
    sort -u "$outdir/cewl.txt" >> "$temp_file"
    mv "$temp_file" "$outdir/cewl.txt"

    # Only open in mousepad if not in preview mode
    [[ $preview -eq 0 && $nodisplay -eq 0 ]] && setsid mousepad "$outdir/cewl.txt" &
  fi
}

function run_nmap() {
  if [[ $forcenmap == 0 && -f "$outdir/nmap.txt" ]]; then
    parse_nmap_results "$outdir/nmap.stage1.txt"
    manage_ports_list
    echo "nmap report already exists, skipping nmap scan"
    return
  fi

  # Stage 1 scan (quick TCP port scan)
  echo -e "\n\033[1;33m>>>\033[0m \033[1;36mnmap -T4 -Pn -p- \"$target\" -oN $outdir/nmap.stage1.txt\033[0m\n"
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
  echo -e "\n\033[1;33m>>>\033[0m \033[1;36mnmap -Pn -p $PORTLIST -A -T4 --script=default \"$target\" -oN $outdir/nmap.stage2.txt\033[0m\n"
  nmap -Pn -p $PORTLIST -A -T4 --script=default "$target" -oN $outdir/nmap.stage2.txt

  # Create combined nmap report with command headers
  echo "COMMAND USED (Stage 1 - Port Scan):" > $outdir/nmap.txt
  echo "nmap -T4 -Pn -p- \"$target\" -oN $outdir/nmap.stage1.txt" >> $outdir/nmap.txt
  echo -e $reportblock >> $outdir/nmap.txt
  cat $outdir/nmap.stage1.txt >> $outdir/nmap.txt
  echo -e $reportblock >> $outdir/nmap.txt
  echo "" >> $outdir/nmap.txt
  echo "COMMAND USED (Stage 2 - Service Detection):" >> $outdir/nmap.txt
  echo "nmap -Pn -p $PORTLIST -A -T4 --script=default \"$target\" -oN $outdir/nmap.stage2.txt" >> $outdir/nmap.txt
  echo -e $reportblock >> $outdir/nmap.txt
  cat $outdir/nmap.stage2.txt >> $outdir/nmap.txt
  #mousepad $outdir/nmap.txt &

  parse_nmap_results "$outdir/nmap.stage2.txt"
  manage_ports_list

}

function reprocess_reports() {
  echo "[*] Reprocessing existing scan outputs..."
  echo "[*] Output directory: $outdir"
  echo ""

  # Check if output directory exists
  if [[ ! -d "$outdir" ]]; then
    echo "[!] Error: Output directory '$outdir' does not exist"
    exit 1
  fi

  # Parse nmap results to get port list
  if [[ -f "$outdir/nmap.stage1.txt" ]]; then
    echo "[*] Parsing nmap results for port information..."
    parse_nmap_results "$outdir/nmap.stage1.txt"
    # In reprocess mode, use parsed ports directly without prompting
    echo "[*] Found ${#ports_list[@]} ports from nmap scan"
  elif [[ -f "$outdir/nmap.stage2.txt" ]]; then
    echo "[*] Parsing nmap results for port information..."
    parse_nmap_results "$outdir/nmap.stage2.txt"
    # In reprocess mode, use parsed ports directly without prompting
    echo "[*] Found ${#ports_list[@]} ports from nmap scan"
  else
    echo "[!] Warning: No nmap results found. Port detection may be incomplete."
  fi

  # Reprocess nmap combined report
  if [[ -f "$outdir/nmap.stage1.txt" && -f "$outdir/nmap.stage2.txt" ]]; then
    echo "[*] Reprocessing nmap combined report..."
    PORTLIST=""
    for entry in "${ports_list[@]}"; do
      IFS=':' read -r port service state <<<"$entry"
      PORTLIST="$PORTLIST$port,"
    done
    PORTLIST="${PORTLIST%,}"

    echo "COMMAND USED (Stage 1 - Port Scan):" > $outdir/nmap.txt
    echo "nmap -T4 -Pn -p- \"$target\" -oN $outdir/nmap.stage1.txt" >> $outdir/nmap.txt
    echo -e $reportblock >> $outdir/nmap.txt
    cat $outdir/nmap.stage1.txt >> $outdir/nmap.txt
    echo -e $reportblock >> $outdir/nmap.txt
    echo "" >> $outdir/nmap.txt
    echo "COMMAND USED (Stage 2 - Service Detection):" >> $outdir/nmap.txt
    echo "nmap -Pn -p $PORTLIST -A -T4 --script=default \"$target\" -oN $outdir/nmap.stage2.txt" >> $outdir/nmap.txt
    echo -e $reportblock >> $outdir/nmap.txt
    cat $outdir/nmap.stage2.txt >> $outdir/nmap.txt
    echo "  ✓ Created: nmap.txt"
  fi

  # Reprocess feroxbuster outputs
  for raw_file in "$outdir"/feroxbuster.*.raw.*.txt; do
    [[ ! -f "$raw_file" ]] && continue

    # Extract scan type and port from filename
    if [[ "$raw_file" =~ feroxbuster\.([^.]+)\.raw\.([0-9]+)\.txt$ ]]; then
      scan_type="${BASH_REMATCH[1]}"
      port="${BASH_REMATCH[2]}"

      echo "[*] Reprocessing feroxbuster $scan_type scan for port $port..."

      # Determine service type from port list
      service="http"
      for entry in "${ports_list[@]}"; do
        IFS=':' read -r p s state <<<"$entry"
        if [[ "$p" == "$port" ]]; then
          service="$s"
          break
        fi
      done

      # Remove ANSI color codes
      sed -i -r 's/\x1B\[([0-9]{1,3}(;[0-9]{1,3})*)?[m|K]//g' "$raw_file"

      # Create processed output
      output_file="$outdir/feroxbuster.$scan_type.$port.txt"

      # Reconstruct command based on scan type
      if [[ "$scan_type" == "quick" ]]; then
        echo "COMMAND USED:" > "$output_file"
        echo "feroxbuster -u \"$service://${target}:$port\" -w \"$outdir/feroxbuster.medium.txt\" --depth 3 --timeout 30 --scan-limit 2 --filter-status 404 -o \"$raw_file\"" >> "$output_file"
      elif [[ "$scan_type" == "deep" ]]; then
        echo "COMMAND USED:" > "$output_file"
        echo "feroxbuster -u \"$service://${target}:$port\" -w \"$outdir/feroxbuster.combined.txt\" -x $webExtensions --depth 3 --timeout 30 --threads 100 --scan-limit 3 --filter-status 404 -o \"$raw_file\"" >> "$output_file"
      fi
      echo -e $reportblock >> "$output_file"

      # Extract and sort results into temp file
      temp_sorted=$(mktemp)
      grep -E '^200[[:space:]]' "$raw_file" 2>/dev/null > "$temp_sorted" || touch "$temp_sorted"
      grep -E '^301[[:space:]]' "$raw_file" 2>/dev/null >> "$temp_sorted" || true
      grep -E '^302[[:space:]]' "$raw_file" 2>/dev/null >> "$temp_sorted" || true

      # Sort and append
      sort -u -f "$temp_sorted" >> "$output_file"
      rm "$temp_sorted"

      # Add separator
      echo -e $reportblock >> "$output_file"

      # Keep original unsorted
      grep -E '^200[[:space:]]' "$raw_file" 2>/dev/null >> "$output_file" || true
      grep -E '^301[[:space:]]' "$raw_file" 2>/dev/null >> "$output_file" || true
      grep -E '^302[[:space:]]' "$raw_file" 2>/dev/null >> "$output_file" || true

      # Add separator
      echo -e $reportblock >> "$output_file"

      # Append full output
      cat "$raw_file" >> "$output_file"

      echo "  ✓ Created: feroxbuster.$scan_type.$port.txt"
    fi
  done

  # Reprocess nikto outputs
  for entry in "${ports_list[@]}"; do
    IFS=':' read -r port service state <<<"$entry"
    [[ "$state" != "open" ]] && continue
    [[ ! "${service,,}" =~ ^(https?|http-proxy)$ ]] && continue

    nikto_file="$outdir/nikto.$port.txt"
    if [[ -f "$nikto_file" ]]; then
      echo "[*] Reprocessing nikto output for port $port..."
      temp_file=$(mktemp)

      # Check if command header already exists
      if ! grep -q "^COMMAND USED:" "$nikto_file"; then
        echo "COMMAND USED:" > "$temp_file"
        echo "nikto -h $service://${target}:$port -ask no -o \"$nikto_file\"" >> "$temp_file"
        echo -e $reportblock >> "$temp_file"
        cat "$nikto_file" >> "$temp_file"
        mv "$temp_file" "$nikto_file"
        echo "  ✓ Updated: nikto.$port.txt"
      else
        echo "  - Already processed: nikto.$port.txt"
      fi
    fi
  done

  # Reprocess whatweb outputs
  for entry in "${ports_list[@]}"; do
    IFS=':' read -r port service state <<<"$entry"
    [[ "$state" != "open" ]] && continue
    [[ ! "${service,,}" =~ ^(https?|http-proxy)$ ]] && continue

    whatweb_file="$outdir/whatweb.$port.txt"
    if [[ -f "$whatweb_file" ]]; then
      echo "[*] Reprocessing whatweb output for port $port..."
      temp_file=$(mktemp)

      # Check if command header already exists
      if ! grep -q "^COMMAND USED:" "$whatweb_file"; then
        echo "COMMAND USED:" > "$temp_file"
        echo "whatweb \"$service://${target}:$port\" --log-verbose=\"$whatweb_file\"" >> "$temp_file"
        echo -e $reportblock >> "$temp_file"
        cat "$whatweb_file" >> "$temp_file"
        mv "$temp_file" "$whatweb_file"
        echo "  ✓ Updated: whatweb.$port.txt"
      else
        echo "  - Already processed: whatweb.$port.txt"
      fi
    fi
  done

  # Reprocess cewl wordlist
  if [[ -f "$outdir/cewl.txt" ]]; then
    echo "[*] Reprocessing cewl wordlist..."
    temp_file=$(mktemp)

    # Check if command header already exists
    if ! grep -q "^COMMAND USED:" "$outdir/cewl.txt"; then
      echo "COMMAND USED:" > "$temp_file"
      for entry in "${ports_list[@]}"; do
        IFS=':' read -r port service state <<<"$entry"
        [[ "$state" != "open" ]] && continue
        [[ ! "${service,,}" =~ ^(https?|http-proxy)$ ]] && continue
        echo "cewl \"$service://${target}:$port\" -d 5 -m 4 -w \"$outdir/cewl.$port.txt\"" >> "$temp_file"
      done
      echo -e $reportblock >> "$temp_file"

      # Sort and append wordlist
      sort -u "$outdir/cewl.txt" >> "$temp_file"
      mv "$temp_file" "$outdir/cewl.txt"
      echo "  ✓ Updated: cewl.txt"
    else
      echo "  - Already processed: cewl.txt"
    fi
  fi

  echo ""
  echo "[*] Reprocessing complete!"
  echo "[*] All output reports have been recreated from existing scan files."
}

function generate_html_report() {
  local report_file="$outdir/report_${target}_$(date +%Y%m%d_%H%M%S).html"

  echo "[*] Generating HTML report..."
  echo "[*] Report file: $report_file"

  # HTML escaping function
  escape_html() {
    sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'\''/\&#39;/g'
  }

  # Start HTML document
  cat > "$report_file" << 'HTML_HEADER'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enumeration Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }

        .container {
            display: flex;
            min-height: 100vh;
        }

        /* Fixed Sidebar */
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 280px;
            height: 100vh;
            background: linear-gradient(180deg, #2d3748 0%, #1a202c 100%);
            color: white;
            overflow-y: auto;
            box-shadow: 4px 0 15px rgba(0,0,0,0.3);
            z-index: 1000;
        }

        .sidebar::-webkit-scrollbar {
            width: 8px;
        }

        .sidebar::-webkit-scrollbar-track {
            background: #1a202c;
        }

        .sidebar::-webkit-scrollbar-thumb {
            background: #667eea;
            border-radius: 4px;
        }

        .sidebar-header {
            padding: 30px 20px;
            border-bottom: 2px solid #667eea;
            background: rgba(102, 126, 234, 0.1);
        }

        .sidebar-header h2 {
            font-size: 1.3em;
            margin-bottom: 5px;
            color: #667eea;
        }

        .sidebar-header .subtitle {
            font-size: 0.85em;
            color: #cbd5e0;
            font-weight: normal;
        }

        .toc {
            padding: 20px 0;
        }

        .toc ul {
            list-style: none;
        }

        .toc li {
            margin-bottom: 5px;
        }

        .toc li a {
            display: block;
            padding: 12px 20px;
            color: #e2e8f0;
            text-decoration: none;
            transition: all 0.3s ease;
            border-left: 4px solid transparent;
            font-size: 0.95em;
        }

        .toc li a:hover,
        .toc li a.active {
            background: rgba(102, 126, 234, 0.2);
            border-left-color: #667eea;
            color: white;
            padding-left: 25px;
        }

        .toc li a .icon {
            margin-right: 10px;
            font-size: 1.1em;
        }

        /* Main Content Area */
        .main-content {
            margin-left: 280px;
            flex: 1;
            background: white;
        }

        header {
            background: linear-gradient(135deg, #2d3748 0%, #1a202c 100%);
            color: white;
            padding: 40px 50px;
            border-bottom: 4px solid #667eea;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }

        header .meta {
            color: #cbd5e0;
            font-size: 0.95em;
        }

        .content {
            padding: 40px 50px;
            background: #f7fafc;
        }

        .section {
            margin-bottom: 40px;
            background: #f7fafc;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .section-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 30px;
            font-size: 1.3em;
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .section-header .badge {
            background: rgba(255,255,255,0.2);
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: normal;
        }

        .section-content {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            max-height: 600px;
            overflow-y: auto;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.5;
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        .section-content::-webkit-scrollbar {
            width: 12px;
        }

        .section-content::-webkit-scrollbar-track {
            background: #2d2d2d;
        }

        .section-content::-webkit-scrollbar-thumb {
            background: #667eea;
            border-radius: 6px;
        }

        .section-content::-webkit-scrollbar-thumb:hover {
            background: #764ba2;
        }

        .empty-section {
            color: #a0aec0;
            font-style: italic;
            padding: 20px;
            text-align: center;
        }

        footer {
            background: #2d3748;
            color: #cbd5e0;
            padding: 20px 40px;
            text-align: center;
            font-size: 0.9em;
        }

        .highlight-200 { color: #48bb78; }
        .highlight-301 { color: #f6ad55; }
        .highlight-302 { color: #f6ad55; }
        .highlight-403 { color: #fc8181; }
        .highlight-404 { color: #e53e3e; }
        .highlight-500 { color: #f56565; }

        @media print {
            .sidebar {
                position: static;
                width: 100%;
                height: auto;
            }
            .main-content {
                margin-left: 0;
            }
            .section-content {
                max-height: none;
                overflow: visible;
            }
        }

        @media (max-width: 768px) {
            .sidebar {
                width: 100%;
                position: relative;
                height: auto;
            }
            .main-content {
                margin-left: 0;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Fixed Sidebar -->
        <div class="sidebar">
            <div class="sidebar-header">
                <h2>📋 Navigation</h2>
                <div class="subtitle">Jump to section</div>
            </div>
            <nav class="toc">
                <ul>
HTML_HEADER

  # Collect available reports for TOC
  local -a toc_items=()
  [[ -f "$outdir/nmap.txt" ]] && toc_items+=("nmap:🌐 Nmap Port Scan")
  [[ -f "$outdir/whatweb.80.txt" || -f "$outdir/whatweb.443.txt" || -f "$outdir/whatweb.8080.txt" ]] && toc_items+=("whatweb:🔎 WhatWeb Analysis")
  [[ -f "$outdir/nikto.80.txt" || -f "$outdir/nikto.443.txt" || -f "$outdir/nikto.8080.txt" ]] && toc_items+=("nikto:🛡️ Nikto Scan")

  # Check for feroxbuster results
  for ffile in "$outdir"/feroxbuster.*.txt; do
    [[ -f "$ffile" ]] && ! [[ "$ffile" =~ \.raw\. ]] && toc_items+=("feroxbuster:📁 Feroxbuster") && break
  done

  [[ -f "$outdir/cewl.txt" ]] && toc_items+=("cewl:📝 CeWL Wordlist")

  # Generate TOC links in sidebar
  for item in "${toc_items[@]}"; do
    IFS=':' read -r anchor title <<< "$item"
    echo "                    <li><a href=\"#${anchor}\">${title}</a></li>" >> "$report_file"
  done

  cat >> "$report_file" << 'SIDEBAR_END'
                </ul>
            </nav>
        </div>

        <!-- Main Content -->
        <div class="main-content">
            <header>
SIDEBAR_END

  # Add dynamic header with target and date
  cat >> "$report_file" << HTML_HEADER_CONTENT
                <h1>🔍 Enumeration Report: ${target}</h1>
                <div class="meta">
                    Generated: $(date '+%Y-%m-%d %H:%M:%S') |
                    Output Directory: ${outdir} |
                    Tool: ptt-enum.sh
                </div>
            </header>
            <div class="content">
HTML_HEADER_CONTENT

  # TOC is already generated in the sidebar above, start with sections

  # Section: Nmap
  if [[ -f "$outdir/nmap.txt" ]]; then
    local nmap_lines=$(wc -l < "$outdir/nmap.txt")
    cat >> "$report_file" << 'NMAP_SECTION'
            <div class="section" id="nmap">
                <div class="section-header">
                    <span>🌐 Nmap Port Scan</span>
NMAP_SECTION
    echo "                    <span class=\"badge\">${nmap_lines} lines</span>" >> "$report_file"
    echo '                </div>' >> "$report_file"
    echo '                <div class="section-content">' >> "$report_file"
    cat "$outdir/nmap.txt" | escape_html >> "$report_file"
    echo '                </div>' >> "$report_file"
    echo '            </div>' >> "$report_file"
  fi

  # Section: WhatWeb (combine all ports)
  local whatweb_found=0
  local whatweb_content=$(mktemp)
  for entry in "${ports_list[@]}"; do
    IFS=':' read -r port service state <<<"$entry"
    [[ "$state" != "open" ]] && continue
    [[ ! "${service,,}" =~ ^(https?|http-proxy)$ ]] && continue

    if [[ -f "$outdir/whatweb.$port.txt" ]]; then
      echo "=== Port $port ===" >> "$whatweb_content"
      cat "$outdir/whatweb.$port.txt" >> "$whatweb_content"
      echo -e "\n" >> "$whatweb_content"
      whatweb_found=1
    fi
  done

  if [[ $whatweb_found -eq 1 ]]; then
    local whatweb_lines=$(wc -l < "$whatweb_content")
    cat >> "$report_file" << 'WHATWEB_SECTION'
            <div class="section" id="whatweb">
                <div class="section-header">
                    <span>🔎 WhatWeb Analysis</span>
WHATWEB_SECTION
    echo "                    <span class=\"badge\">${whatweb_lines} lines</span>" >> "$report_file"
    echo '                </div>' >> "$report_file"
    echo '                <div class="section-content">' >> "$report_file"
    cat "$whatweb_content" | escape_html >> "$report_file"
    echo '                </div>' >> "$report_file"
    echo '            </div>' >> "$report_file"
  fi
  rm -f "$whatweb_content"

  # Section: Nikto (combine all ports)
  local nikto_found=0
  local nikto_content=$(mktemp)
  for entry in "${ports_list[@]}"; do
    IFS=':' read -r port service state <<<"$entry"
    [[ "$state" != "open" ]] && continue
    [[ ! "${service,,}" =~ ^(https?|http-proxy)$ ]] && continue

    if [[ -f "$outdir/nikto.$port.txt" ]]; then
      echo "=== Port $port ===" >> "$nikto_content"
      cat "$outdir/nikto.$port.txt" >> "$nikto_content"
      echo -e "\n" >> "$nikto_content"
      nikto_found=1
    fi
  done

  if [[ $nikto_found -eq 1 ]]; then
    local nikto_lines=$(wc -l < "$nikto_content")
    cat >> "$report_file" << 'NIKTO_SECTION'
            <div class="section" id="nikto">
                <div class="section-header">
                    <span>🛡️ Nikto Vulnerability Scan</span>
NIKTO_SECTION
    echo "                    <span class=\"badge\">${nikto_lines} lines</span>" >> "$report_file"
    echo '                </div>' >> "$report_file"
    echo '                <div class="section-content">' >> "$report_file"
    cat "$nikto_content" | escape_html >> "$report_file"
    echo '                </div>' >> "$report_file"
    echo '            </div>' >> "$report_file"
  fi
  rm -f "$nikto_content"

  # Section: Feroxbuster (combine all results)
  local ferox_found=0
  local ferox_content=$(mktemp)
  for ffile in "$outdir"/feroxbuster.*.txt; do
    [[ ! -f "$ffile" ]] && continue
    [[ "$ffile" =~ \.raw\. ]] && continue

    if [[ "$ffile" =~ feroxbuster\.([^.]+)\.([0-9]+)\.txt$ ]]; then
      scan_type="${BASH_REMATCH[1]}"
      port="${BASH_REMATCH[2]}"
      echo "=== ${scan_type^^} Scan - Port $port ===" >> "$ferox_content"
      cat "$ffile" >> "$ferox_content"
      echo -e "\n" >> "$ferox_content"
      ferox_found=1
    fi
  done

  if [[ $ferox_found -eq 1 ]]; then
    local ferox_lines=$(wc -l < "$ferox_content")
    cat >> "$report_file" << 'FEROX_SECTION'
            <div class="section" id="feroxbuster">
                <div class="section-header">
                    <span>📁 Feroxbuster Directory Enumeration</span>
FEROX_SECTION
    echo "                    <span class=\"badge\">${ferox_lines} lines</span>" >> "$report_file"
    echo '                </div>' >> "$report_file"
    echo '                <div class="section-content">' >> "$report_file"
    cat "$ferox_content" | escape_html >> "$report_file"
    echo '                </div>' >> "$report_file"
    echo '            </div>' >> "$report_file"
  fi
  rm -f "$ferox_content"

  # Section: CeWL
  if [[ -f "$outdir/cewl.txt" ]]; then
    local cewl_lines=$(wc -l < "$outdir/cewl.txt")
    cat >> "$report_file" << 'CEWL_SECTION'
            <div class="section" id="cewl">
                <div class="section-header">
                    <span>📝 Custom Wordlist (CeWL)</span>
CEWL_SECTION
    echo "                    <span class=\"badge\">${cewl_lines} words</span>" >> "$report_file"
    echo '                </div>' >> "$report_file"
    echo '                <div class="section-content">' >> "$report_file"
    cat "$outdir/cewl.txt" | escape_html >> "$report_file"
    echo '                </div>' >> "$report_file"
    echo '            </div>' >> "$report_file"
  fi

  # Close HTML
  cat >> "$report_file" << 'HTML_FOOTER'
            </div>
            <footer>
                Generated by ptt-enum.sh | Penetration Testing Tools | Use for authorized testing only
            </footer>
        </div>
    </div>
</body>
</html>
HTML_FOOTER

  echo "[+] HTML report generated: $report_file"

  # Ask user if they want to open the report
  echo ""
  read -p "Do you want to open the HTML report in your default browser? [y/N]: " open_report

  if [[ "${open_report,,}" =~ ^(y|yes)$ ]]; then
    echo "[*] Opening report in browser..."

    # Cross-platform browser opening
    if command -v xdg-open &> /dev/null; then
      # Linux
      xdg-open "$report_file" &> /dev/null &
    elif command -v open &> /dev/null; then
      # macOS
      open "$report_file"
    elif command -v start &> /dev/null; then
      # Windows (Git Bash/WSL)
      start "$report_file"
    elif [[ -n "$BROWSER" ]]; then
      # Use BROWSER environment variable
      "$BROWSER" "$report_file" &> /dev/null &
    else
      echo "[!] Could not detect default browser. Please open manually:"
      echo "    $report_file"
    fi
  else
    echo "[*] Report saved to: $report_file"
    echo "[*] You can open it later with your browser"
  fi
}

# ---------------------------------- MAIN ----------------------------------

# Variables
declare -g -a ports_list=()
target=""
outdir=""
forcenmap=0
nodisplay=0
transcript=0
preview=0
reprocess=0
reportblock="\n------------------------------------------------------------------------------------------------------------\n"
webExtensions="sh,txt,php,html,htm,asp,aspx,js,jsp,xml,log,json,zip,tar.gz,tar,pdf"

#  Parse parameters
while getopts "t:o:fnlpr" opt; do
    case "$opt" in
        t) target="$OPTARG" ;;
        o) outdir="$OPTARG" ;;
        f) forcenmap=1 ;;
        n) nodisplay=1 ;;
        l) transcript=1 ;;
        p) preview=1 ;;
        r) reprocess=1 ;;
        *) echo "Usage: $0 -t <value> [-o <outdir>] [-f] [-n] [-l] [-p] [-r]"; exit 1 ;;
    esac
done

# Check if no IP address or domain provided
# Exception: In reprocess mode with -o flag, target can be inferred from outdir
if [ -z "$target" ]; then
    if [[ $reprocess -eq 1 && -n "$outdir" ]]; then
        # Try to extract target from output directory name (format: report_<target>)
        if [[ "$outdir" =~ report_(.+)$ ]]; then
            target="${BASH_REMATCH[1]}"
            echo "[*] Target inferred from output directory: $target"
        elif [[ "$outdir" =~ ([^/]+)$ ]]; then
            # If no report_ prefix, use the directory name itself
            target="${BASH_REMATCH[1]}"
            echo "[*] Using output directory name as target: $target"
        else
            echo "Error: Could not infer target from output directory."
            echo "Please specify target with -t option or use standard directory naming (report_<target>)."
            exit 1
        fi
    else
        echo "Error: No IP address/domain provided."
        echo "Usage: $0 -t <target> [-o <outdir>] [-f] [-n] [-l] [-p] [-r]"
        echo ""
        echo "Note: In reprocess mode (-r), target can be inferred from -o directory name"
        exit 1
    fi
fi

# Continue with normal validation if target was not provided
if [ -z "$target" ]; then
    echo "Error: No IP address/domain provided."
    echo "Usage: $0 -t <target> [-o <outdir>] [-f] [-n] [-l] [-p] [-r]"
    echo ""
    echo "Options:"
    echo "  -t <target>   Target IP address or domain (required, except with -r and -o)"
    echo "  -o <outdir>   Output directory (default: report_<target>)"
    echo "  -f            Force nmap scan even if results exist"
    echo "  -n            No display - don't open report files in mousepad"
    echo "  -l            Log transcript - save full console output with colors"
    echo "  -p            Preview mode - run nmap only, show commands for other scans"
    echo "  -r            Reprocess mode - recreate output reports from existing raw scan files"
    echo ""
    echo "Feroxbuster Directory Enumeration:"
    echo "  Built-in recursion (depth 3) with auto-discovery of subdirectories"
    echo "  Quick scan: Fast directory/file enumeration"
    echo "  Deep scan: Thorough with extension fuzzing (.php, .asp, .bak, etc.)"
    echo ""
    echo "Transcript:"
    echo "  Use -l to create a transcript file preserving colors and cursor positioning."
    echo "  View with: less -R <transcript_file> or cat <transcript_file>"
    echo ""
    echo "Preview Mode:"
    echo "  Use -p to run only nmap scans. Other tools (whatweb, cewl, nikto, feroxbuster)"
    echo "  will display their commands without executing, allowing manual control."
    echo ""
    echo "Reprocess Mode:"
    echo "  Use -r to recreate output reports from existing raw scan files. Useful when scans"
    echo "  were run manually or in preview mode. Combines, sorts, and formats existing outputs."
    echo "  With -r and -o together, target can be inferred from directory name (e.g., report_target.com)"
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

# Handle transcript recording with script command
# Re-execute under script if -l is set and not already running under script
if [[ $transcript -eq 1 && -z "${PTT_ENUM_SCRIPTED:-}" ]]; then
    transcript_file="$outdir/transcript_$(date +%Y%m%d_%H%M%S).log"
    echo "[*] Transcript enabled - recording to: $transcript_file"
    echo "[*] Note: Transcript preserves colors. View with: less -R $transcript_file"
    export PTT_ENUM_SCRIPTED=1
    # Re-execute this script under 'script' to capture all output with colors
    # Using printf %q to properly quote arguments for shell execution
    quoted_args=""
    for arg in "${ORIGINAL_ARGS[@]}"; do
        quoted_args+="$(printf '%q ' "$arg")"
    done
    exec script -q -c "$0 $quoted_args" "$transcript_file"
fi

# Set error handling
exec 2> >(tee "$outdir/errors.log" >&2)
set -euo pipefail

# Handle reprocess mode
if [[ $reprocess -eq 1 ]]; then
  reprocess_reports
  echo ""
  generate_html_report
  exit 0
fi

# Check for combined wordlists
if [[ ! -f "./master-enum.txt" ]]; then
  build_master_wordlists
fi

safe_run run_nmap
safe_run run_whatweb
safe_run run_cewl
safe_run run_nikto

# Run feroxbuster for recursive directory enumeration
echo "[*] Using Feroxbuster for recursive directory enumeration"
safe_run run_feroxbuster

# Generate HTML report after all scans complete
echo ""
echo "[*] All enumeration scans completed!"
generate_html_report