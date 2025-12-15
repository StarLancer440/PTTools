#!/bin/bash

# Perform enumeration against a target

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
    #gobuster dir -u "$service://${target}:$port" -w ./master-enum.txt -t 50 --timeout 30s --no-error -o "$outdir/gobuster.master-dir.$port.txt"

    cat ./master-enum.txt > "$outdir/gobuster.dir.txt"
    cat "$outdir/cewl.txt" >> "$outdir/gobuster.dir.txt"

    echo "[*] Running: gobuster dir -u \"$service://${target}:$port\" -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -x old,bak,backup -t 50 --timeout 30s --no-error -o \"$outdir/gobuster.raft_files.$port.txt\""
    gobuster dir -u "$service://${target}:$port" -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -x old,bak,backup -t 50 --timeout 30s --no-error  -o "$outdir/gobuster.raft_files.$port.txt"

    echo "[*] Running: gobuster dir -u \"$service://${target}:$port\" -w ./master-enum.txt -x $webExtensions -t 50 --timeout 30s --no-error -o \"$outdir/gobuster.master-ext.$port.txt\""
    gobuster dir -u "$service://${target}:$port" -w "$outdir/gobuster.dir.txt" -x $webExtensions -t 50 --timeout 30s --no-error  -o "$outdir/gobuster.master-ext.$port.txt"

    # Combine all output in a single file
    sort -u "$outdir/gobuster.raft_files.$port.txt" "$outdir/gobuster.master-ext.$port.txt" -o "$outdir/gobuster_temp.$port.txt"
    sed -i -r 's/\x1B\[([0-9]{1,3}(;[0-9]{1,3})*)?[m|K]//g' "$outdir/gobuster_temp.$port.txt"
    cat "$outdir/gobuster_temp.$port.txt" | grep '(Status: 200)' > "$outdir/gobuster.$port.txt"
    cat "$outdir/gobuster_temp.$port.txt" | grep '(Status: 301)' >> "$outdir/gobuster.$port.txt"
    echo -e $reportblock >> "$outdir/gobuster.$port.txt"
    cat "$outdir/gobuster_temp.$port.txt" >> "$outdir/gobuster.$port.txt"
    rm "$outdir/gobuster_temp.$port.txt"
    [[ $nodisplay -eq 0 ]] && mousepad "$outdir/gobuster.$port.txt" &
  done
}

function extract_directories() {
  # Extract directories from gobuster output files
  local -a dirs=()

  for gobuster_file in "$outdir"/gobuster.*.txt; do
    [[ ! -f "$gobuster_file" ]] && continue

    # Skip extended scan results
    [[ "$gobuster_file" =~ gobuster\.extended\. ]] && continue

    # Extract directories (lines with Status: 301 or ending with /)
    while IFS= read -r line; do
      if [[ $line =~ ^([^[:space:]]+)[[:space:]]+\(Status:[[:space:]]+(200|301)\) ]]; then
        local path="${BASH_REMATCH[1]}"
        # Only add if it's a directory (ends with / or has 301 status)
        if [[ $path == */ ]] || [[ $line =~ Status:[[:space:]]+301 ]]; then
          # Remove trailing slash for consistency
          path="${path%/}"
          [[ -n "$path" ]] && dirs+=("$path")
        fi
      fi
    done < "$gobuster_file"
  done

  # Remove duplicates and sort
  printf '%s\n' "${dirs[@]}" | sort -u
}

function extract_extended_directories() {
  # Extract directories from first level extended gobuster output files
  local -a dirs=()
  local -A dir_map=()  # Use associative array to track parent directories

  for gobuster_file in "$outdir"/gobuster.extended.*.txt; do
    [[ ! -f "$gobuster_file" ]] && continue

    # Skip level 2 extended scan results
    [[ "$gobuster_file" =~ gobuster\.extended2\. ]] && continue

    # Extract parent directory from filename (e.g., gobuster.extended._admin.80.txt -> /admin)
    if [[ "$gobuster_file" =~ gobuster\.extended\.([^.]+)\.([0-9]+)\.txt$ ]]; then
      local safe_parent="${BASH_REMATCH[1]}"
      # Convert safe name back to path (e.g., _admin -> /admin, _api_v1 -> /api/v1)
      local parent_path="${safe_parent//_//}"

      # Extract directories from this file
      while IFS= read -r line; do
        if [[ $line =~ ^([^[:space:]]+)[[:space:]]+\(Status:[[:space:]]+(200|301)\) ]]; then
          local path="${BASH_REMATCH[1]}"
          # Only add if it's a directory (ends with / or has 301 status)
          if [[ $path == */ ]] || [[ $line =~ Status:[[:space:]]+301 ]]; then
            # Remove trailing slash for consistency
            path="${path%/}"
            # Combine parent path with found path
            local full_path="${parent_path}${path}"
            [[ -n "$full_path" ]] && dir_map["$full_path"]=1
          fi
        fi
      done < "$gobuster_file"
    fi
  done

  # Output unique sorted directories
  printf '%s\n' "${!dir_map[@]}" | sort -u
}

function run_extended_gobuster() {
  local selected_dirs=("$@")

  for entry in "${ports_list[@]}"; do
    IFS=':' read -r port service state <<<"$entry"

    # Skip ports that are not open
    [[ "$state" != "open" ]] && continue

    # Skip non http(s) ports
    [[ ! "${service,,}" =~ ^(https?)$ ]] && continue

    # Run extended scan for each selected directory
    for dir in "${selected_dirs[@]}"; do
      local safe_dir="${dir//\//_}"
      local base_url="$service://${target}:$port$dir"

      echo "[*] Extended scan on: $base_url"
      echo "[*] Running: gobuster dir -u \"$base_url\" -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -x old,bak,backup -t 50 --timeout 30s --no-error -o \"$outdir/gobuster.extended.raft_files.${safe_dir}.$port.txt\""
      gobuster dir -u "$base_url" -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -x old,bak,backup -t 50 --timeout 30s --no-error -o "$outdir/gobuster.extended.raft_files.${safe_dir}.$port.txt"

      echo "[*] Running: gobuster dir -u \"$base_url\" -w ./master-enum.txt -x $webExtensions -t 50 --timeout 30s --no-error -o \"$outdir/gobuster.extended.master-ext.${safe_dir}.$port.txt\""
      gobuster dir -u "$base_url" -w "$outdir/gobuster.dir.txt" -x $webExtensions -t 50 --timeout 30s --no-error -o "$outdir/gobuster.extended.master-ext.${safe_dir}.$port.txt"

      # Combine all output in a single file
      sort -u "$outdir/gobuster.extended.raft_files.${safe_dir}.$port.txt" "$outdir/gobuster.extended.master-ext.${safe_dir}.$port.txt" -o "$outdir/gobuster_temp.${safe_dir}.$port.txt"
      sed -i -r 's/\x1B\[([0-9]{1,3}(;[0-9]{1,3})*)?[m|K]//g' "$outdir/gobuster_temp.${safe_dir}.$port.txt"
      cat "$outdir/gobuster_temp.${safe_dir}.$port.txt" | grep '(Status: 200)' > "$outdir/gobuster.extended.${safe_dir}.$port.txt"
      cat "$outdir/gobuster_temp.${safe_dir}.$port.txt" | grep '(Status: 301)' >> "$outdir/gobuster.extended.${safe_dir}.$port.txt"
      echo -e $reportblock >> "$outdir/gobuster.extended.${safe_dir}.$port.txt"
      cat "$outdir/gobuster_temp.${safe_dir}.$port.txt" >> "$outdir/gobuster.extended.${safe_dir}.$port.txt"
      rm "$outdir/gobuster_temp.${safe_dir}.$port.txt"
      [[ $nodisplay -eq 0 ]] && mousepad "$outdir/gobuster.extended.${safe_dir}.$port.txt" &
    done
  done
}

function prompt_extended_scan() {
  echo ""
  echo "========================================"
  echo "Gobuster Scan Results - Directories Found"
  echo "========================================"

  # Extract and display directories
  local -a all_dirs=()
  while IFS= read -r dir; do
    all_dirs+=("$dir")
  done < <(extract_directories)

  if [ ${#all_dirs[@]} -eq 0 ]; then
    echo "No directories found."
    return
  fi

  # Display directories with index
  for i in "${!all_dirs[@]}"; do
    printf "[%2d] %s\n" "$i" "${all_dirs[$i]}"
  done

  echo "========================================"
  echo ""

  # Ask if user wants extended scan
  read -p "Do you want to perform an extended gobuster scan on specific directories? [y/N]: " answer

  if [[ ! "${answer,,}" =~ ^(y|yes)$ ]]; then
    echo "[*] Skipping extended scan."
    return
  fi

  # Let user select directories
  echo ""
  echo "Select directories to scan (comma-separated indices, or 'all'):"
  read -p "Selection: " selection

  local -a selected_dirs=()

  if [[ "${selection,,}" == "all" ]]; then
    selected_dirs=("${all_dirs[@]}")
  else
    IFS=',' read -ra indices <<< "$selection"
    for idx in "${indices[@]}"; do
      # Trim whitespace
      idx=$(echo "$idx" | xargs)
      if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -ge 0 ] && [ "$idx" -lt ${#all_dirs[@]} ]; then
        selected_dirs+=("${all_dirs[$idx]}")
      else
        echo "[!] Invalid index: $idx"
      fi
    done
  fi

  if [ ${#selected_dirs[@]} -eq 0 ]; then
    echo "[!] No valid directories selected."
    return
  fi

  echo ""
  echo "[*] Selected directories for extended scan:"
  for dir in "${selected_dirs[@]}"; do
    echo "    - $dir"
  done
  echo ""

  # Run extended scan
  run_extended_gobuster "${selected_dirs[@]}"
}

function run_extended_gobuster_level2() {
  local selected_dirs=("$@")

  for entry in "${ports_list[@]}"; do
    IFS=':' read -r port service state <<<"$entry"

    # Skip ports that are not open
    [[ "$state" != "open" ]] && continue

    # Skip non http(s) ports
    [[ ! "${service,,}" =~ ^(https?)$ ]] && continue

    # Run extended scan for each selected directory
    for dir in "${selected_dirs[@]}"; do
      local safe_dir="${dir//\//_}"
      local base_url="$service://${target}:$port$dir"

      echo "[*] Level 2 extended scan on: $base_url"
      echo "[*] Running: gobuster dir -u \"$base_url\" -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -x old,bak,backup -t 50 --timeout 30s --no-error -o \"$outdir/gobuster.extended2.raft_files.${safe_dir}.$port.txt\""
      gobuster dir -u "$base_url" -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -x old,bak,backup -t 50 --timeout 30s --no-error -o "$outdir/gobuster.extended2.raft_files.${safe_dir}.$port.txt"

      echo "[*] Running: gobuster dir -u \"$base_url\" -w ./master-enum.txt -x $webExtensions -t 50 --timeout 30s --no-error -o \"$outdir/gobuster.extended2.master-ext.${safe_dir}.$port.txt\""
      gobuster dir -u "$base_url" -w "$outdir/gobuster.dir.txt" -x $webExtensions -t 50 --timeout 30s --no-error -o "$outdir/gobuster.extended2.master-ext.${safe_dir}.$port.txt"

      # Combine all output in a single file
      sort -u "$outdir/gobuster.extended2.raft_files.${safe_dir}.$port.txt" "$outdir/gobuster.extended2.master-ext.${safe_dir}.$port.txt" -o "$outdir/gobuster_temp.${safe_dir}.$port.txt"
      sed -i -r 's/\x1B\[([0-9]{1,3}(;[0-9]{1,3})*)?[m|K]//g' "$outdir/gobuster_temp.${safe_dir}.$port.txt"
      cat "$outdir/gobuster_temp.${safe_dir}.$port.txt" | grep '(Status: 200)' > "$outdir/gobuster.extended2.${safe_dir}.$port.txt"
      cat "$outdir/gobuster_temp.${safe_dir}.$port.txt" | grep '(Status: 301)' >> "$outdir/gobuster.extended2.${safe_dir}.$port.txt"
      echo -e $reportblock >> "$outdir/gobuster.extended2.${safe_dir}.$port.txt"
      cat "$outdir/gobuster_temp.${safe_dir}.$port.txt" >> "$outdir/gobuster.extended2.${safe_dir}.$port.txt"
      rm "$outdir/gobuster_temp.${safe_dir}.$port.txt"
      [[ $nodisplay -eq 0 ]] && mousepad "$outdir/gobuster.extended2.${safe_dir}.$port.txt" &
    done
  done
}

function prompt_second_level_scan() {
  echo ""
  echo "========================================"
  echo "Extended Scan Results - Level 2 Directories Found"
  echo "========================================"

  # Extract and display directories from extended scans
  local -a all_dirs=()
  while IFS= read -r dir; do
    all_dirs+=("$dir")
  done < <(extract_extended_directories)

  if [ ${#all_dirs[@]} -eq 0 ]; then
    echo "No new directories found in extended scans."
    return
  fi

  # Display directories with index
  for i in "${!all_dirs[@]}"; do
    printf "[%2d] %s\n" "$i" "${all_dirs[$i]}"
  done

  echo "========================================"
  echo ""

  # Ask if user wants second level extended scan
  read -p "Do you want to perform a level 2 extended scan on specific directories? [y/N]: " answer

  if [[ ! "${answer,,}" =~ ^(y|yes)$ ]]; then
    echo "[*] Skipping level 2 extended scan."
    return
  fi

  # Let user select directories
  echo ""
  echo "Select directories to scan (comma-separated indices, or 'all'):"
  read -p "Selection: " selection

  local -a selected_dirs=()

  if [[ "${selection,,}" == "all" ]]; then
    selected_dirs=("${all_dirs[@]}")
  else
    IFS=',' read -ra indices <<< "$selection"
    for idx in "${indices[@]}"; do
      # Trim whitespace
      idx=$(echo "$idx" | xargs)
      if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -ge 0 ] && [ "$idx" -lt ${#all_dirs[@]} ]; then
        selected_dirs+=("${all_dirs[$idx]}")
      else
        echo "[!] Invalid index: $idx"
      fi
    done
  fi

  if [ ${#selected_dirs[@]} -eq 0 ]; then
    echo "[!] No valid directories selected."
    return
  fi

  echo ""
  echo "[*] Selected directories for level 2 extended scan:"
  for dir in "${selected_dirs[@]}"; do
    echo "    - $dir"
  done
  echo ""

  # Run level 2 extended scan
  run_extended_gobuster_level2 "${selected_dirs[@]}"
}

function run_feroxbuster() {
  # Feroxbuster Recursive Scan
  #
  # Advantages over gobuster:
  # - Built-in recursion (--depth 3) automatically scans discovered directories
  # - No need for manual extended scans (replaces prompt_extended_scan and prompt_second_level_scan)
  # - Faster overall enumeration with automatic subdirectory discovery
  # - Single scan covers multiple directory levels
  # - Auto-tuning adapts thread count based on target performance (starts conservative, increases if stable)
  # - Combined wordlists and extensions reduce total scan time and improve thoroughness
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
      echo "[*] Running: feroxbuster -u \"$service://${target}:$port\" -w \"$outdir/feroxbuster.medium.txt\" --depth 3 --timeout 30 --scan-limit 2 --filter-status 404 -o \"$outdir/feroxbuster.quick.raw.$port.txt\""

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

      # Extract and sort quick scan results
      grep -E '^200[[:space:]]' "$outdir/feroxbuster.quick.raw.$port.txt" 2>/dev/null > "$outdir/feroxbuster.quick.$port.txt" || touch "$outdir/feroxbuster.quick.$port.txt"
      grep -E '^301[[:space:]]' "$outdir/feroxbuster.quick.raw.$port.txt" 2>/dev/null >> "$outdir/feroxbuster.quick.$port.txt" || true
      grep -E '^302[[:space:]]' "$outdir/feroxbuster.quick.raw.$port.txt" 2>/dev/null >> "$outdir/feroxbuster.quick.$port.txt" || true      

      # Sort and remove duplicate
      sort -u -f -o "$outdir/feroxbuster.quick.$port.txt" "$outdir/feroxbuster.quick.$port.txt"

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
      [[ $nodisplay -eq 0 ]] && mousepad "$outdir/feroxbuster.quick.$port.txt" &

      # Ask if user wants to also run deep scan
      echo ""
      read -p "Quick scan complete. Do you also want to run a DEEP scan with extension fuzzing? (y/n): " run_deep_choice
      [[ "$run_deep_choice" =~ ^[Yy]$ ]] && run_deep=1
    fi

    # RUN DEEP SCAN if requested (either directly or after quick scan)
    if [[ $run_deep -eq 1 ]]; then
      local combined_extensions="${webExtensions},old,bak,backup"

      echo ""
      echo "[*] Running DEEP feroxbuster scan with extension fuzzing on: $service://${target}:$port"
      echo "[*] Combined wordlist size: $(wc -l < "$outdir/feroxbuster.combined.txt") unique entries"
      echo "[*] Running: feroxbuster -u \"$service://${target}:$port\" -w \"$outdir/feroxbuster.combined.txt\" -x $combined_extensions --depth 3 --timeout 30 --threads 100 --scan-limit 3 --filter-status 404 -o \"$outdir/feroxbuster.deep.raw.$port.txt\""

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

      # Extract and sort deep scan results
      grep -E '^200[[:space:]]' "$outdir/feroxbuster.deep.raw.$port.txt" 2>/dev/null > "$outdir/feroxbuster.deep.$port.txt" || touch "$outdir/feroxbuster.deep.$port.txt"
      grep -E '^301[[:space:]]' "$outdir/feroxbuster.deep.raw.$port.txt" 2>/dev/null >> "$outdir/feroxbuster.deep.$port.txt" || true
      grep -E '^302[[:space:]]' "$outdir/feroxbuster.quick.raw.$port.txt" 2>/dev/null >> "$outdir/feroxbuster.quick.$port.txt" || true      

      # Sort and remove duplicate
      sort -u -f -o "$outdir/feroxbuster.quick.$port.txt" "$outdir/feroxbuster.deep.$port.txt"

      # Add separator
      echo -e $reportblock >> "$outdir/feroxbuster.quick.$port.txt"

      # Keep original unsorted and non unique
      grep -E '^200[[:space:]]' "$outdir/feroxbuster.quick.raw.$port.txt" 2>/dev/null >> "$outdir/feroxbuster.deep.$port.txt" || true
      grep -E '^301[[:space:]]' "$outdir/feroxbuster.quick.raw.$port.txt" 2>/dev/null >> "$outdir/feroxbuster.deep.$port.txt" || true
      grep -E '^302[[:space:]]' "$outdir/feroxbuster.quick.raw.$port.txt" 2>/dev/null >> "$outdir/feroxbuster.deep.$port.txt" || true      

      # Add separator
      echo -e $reportblock >> "$outdir/feroxbuster.deep.$port.txt"

      # Append full output for reference
      cat "$outdir/feroxbuster.deep.raw.$port.txt" >> "$outdir/feroxbuster.deep.$port.txt"

      # Open deep scan results in editor if not suppressed
      [[ $nodisplay -eq 0 ]] && mousepad "$outdir/feroxbuster.deep.$port.txt" &
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

    nikto -h $service://${target}:$port -ask no -o "$outdir/nikto.$port.txt"
    [[ $nodisplay -eq 0 ]] && mousepad "$outdir/nikto.$port.txt" &
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

    whatweb "$service://${target}:$port" --log-verbose="$outdir/whatweb.$port.txt"
    [[ $nodisplay -eq 0 ]] && mousepad "$outdir/whatweb.$port.txt" &
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

    cewl "$service://${target}:$port" -d 5 -m 4 -w "$outdir/cewl.$port.txt"
    cat "$outdir/cewl.$port.txt" >> "$outdir/cewl.txt"
  done

  # Sort and deduplicate if cewl.txt was created
  if [[ -f "$outdir/cewl.txt" ]]; then
    sort -u -o "$outdir/cewl.txt" "$outdir/cewl.txt"
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
nodisplay=0
scanner="feroxbuster"  # Default scanner (gobuster or feroxbuster)
reportblock="\n------------------------------------------------------------------------------------------------------------\n"
webExtensions="sh,txt,php,html,htm,asp,aspx,js,jsp,xml,log,json,zip,tar.gz,tar,pdf"

#  Parse parameters
while getopts "t:o:fns:" opt; do
    case "$opt" in
        t) target="$OPTARG" ;;
        o) outdir="$OPTARG" ;;
        f) forcenmap=1 ;;
        n) nodisplay=1 ;;
        s) scanner="$OPTARG" ;;
        *) echo "Usage: $0 -t <value> [-o <outdir>] [-f] [-n] [-s <gobuster|feroxbuster>]"; exit 1 ;;
    esac
done

# Check if no IP address or domain provided
if [ -z "$target" ]; then
    echo "Error: No IP address/domain provided."
    echo "Usage: $0 -t <target> [-o <outdir>] [-f] [-n] [-s <scanner>]"
    echo ""
    echo "Options:"
    echo "  -t <target>   Target IP address or domain (required)"
    echo "  -o <outdir>   Output directory (default: report_<target>)"
    echo "  -f            Force nmap scan even if results exist"
    echo "  -n            No display - don't open report files in mousepad"
    echo "  -s <scanner>  Directory scanner to use: gobuster (default) or feroxbuster"
    echo ""
    echo "Scanner Comparison:"
    echo "  gobuster     - Fast, requires manual recursive scanning (extended scans)"
    echo "  feroxbuster  - Built-in recursion (depth 3), auto-discovers subdirectories"
    echo "               - Quick scan: Fast directory/file enumeration"
    echo "               - Deep scan: Thorough with extension fuzzing (.php, .asp, .bak, etc.)"
    exit 1
fi

# Validate scanner choice
if [[ ! "$scanner" =~ ^(gobuster|feroxbuster)$ ]]; then
    echo "[!] Error: Invalid scanner '$scanner'. Must be 'gobuster' or 'feroxbuster'."
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
if [[ ! -f "./master-enum.txt" ]]; then
  build_master_wordlists
fi

safe_run run_nmap
safe_run run_whatweb
safe_run run_cewl
safe_run run_nikto

# Run selected directory scanner
if [[ "$scanner" == "gobuster" ]]; then
  echo "[*] Using Gobuster for directory enumeration"
  safe_run run_gobuster

  # Prompt for extended gobuster scan
  prompt_extended_scan

  # Prompt for second level extended gobuster scan
  prompt_second_level_scan
elif [[ "$scanner" == "feroxbuster" ]]; then
  echo "[*] Using Feroxbuster for recursive directory enumeration"
  safe_run run_feroxbuster
fi