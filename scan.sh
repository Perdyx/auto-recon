#!/usr/bin/env bash

# Description: Automated subdomain enumeration, DNS resolution/brute-forcing (optional), and host fingerprinting for a given scope.
#
# Usage:
# ./scan.sh <scope_id_string>
#
# Example (output will be saved in scans/google-<timestamp>/):
# ./scan.sh google
#
# Dependencies:
# anew - https://github.com/tomnomnom/anew
# dnsx - https://github.com/projectdiscovery/dnsx
# jq
# massdns - https://github.com/blechschmidt/massdns
# nmap
# notify - https://github.com/projectdiscovery/notify (optional, functionality commented out and needs to be configured manually by the user)
# puredns - https://github.com/d3mondev/puredns
# shuffledns - https://github.com/projectdiscovery/shuffledns
# subfinder - https://github.com/projectdiscovery/subfinder


##################### CONFIGURATION #####################

DEBUG=false # Set to true to enable debug mode (removes previous scans with same scope_id which is useful for testing)
DNSBF=false # Set to true to enable DNS brute-forcing with ShuffleDNS (takes forever and not fully tested)
VRSLV=true # Set to true to generate a new DNS resolvers list before scanning (can take a long time)
LRSLV=false # Set to true to use a larger list of DNS resolvers from Trickest (may be slower, but could yield better results)


##################### INITIALIZE VARIABLES #####################

ppath="$(pwd)"
resolvers="$ppath/lists/updated-resolvers.txt"

scope_id="$1"
scopes_dir="$ppath/scope"
scope_path="$scopes_dir/$scope_id"

timestamp="$(date +%s)"
scan_id="$scope_id-$timestamp"
scan_path="$ppath/scans/$scan_id"

subdomains_file="$scan_path/subdomains.txt"


##################### FIRST RUN #####################

if [ ! -d "$scopes_dir" ]; then
    echo "Starting first run setup..."
    mkdir -p "$scopes_dir"

    # Prompt user to create a new scope
    read -rp "Enter the name of a new scope (e.g., name of target organization): " new_scope

    # Initialize the new scope
    new_scope_path="$scopes_dir/$new_scope"
    mkdir -p "$new_scope_path"
    touch "$new_scope_path/roots.txt"

    # Prompt user to add root domains and re-run
    echo "Created new scope at $new_scope_path. Please add root domains to $new_scope_path/roots.txt (wildcards are ok) and re-run the script."
    exit 0
fi


##################### PREPARE ENVIRONMENT #####################

# Ensure required directories exist
mkdir -p "$ppath/lists/trickest"
mkdir -p "$ppath/lists/assetnote"

# If validating resolvers, remove any existing resolvers file to ensure a fresh list is generated
if [ "$VRSLV" = true ]; then
    if [ -f "$resolvers" ]; then
        rm -f "$resolvers"
    fi
fi


################## UPDATE LISTS #####################

# Download the latest resolvers from Trickest (more information: https://github.com/trickest/resolvers/blob/main/README.md)
if [ "$LRSLV" = false ]; then
    echo "Updating https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt"
    curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt | anew "$ppath/lists/trickest/resolvers-trusted.txt"
fi

# Optionally, use a larger list of resolvers from Trickest
if [ "$LRSLV" = true ]; then
    echo "Updating https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
    curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt | anew "$ppath/lists/trickest/resolvers.txt"
fi

# Download the latest DNS wordlist from Assetnote
echo "Updating https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt"
curl -s https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt | anew "$ppath/lists/assetnote/best-dns-wordlist.txt"


##################### VALIDATE DNS RESOLVERS #####################

if [ "$VRSLV" = true ]; then
    # Generate resolvers file using DNSValidator
    echo "Validating resolvers from trickest/resolvers-trusted.txt and saving results to $resolvers"
    dnsvalidator -tL $ppath/lists/trickest/resolvers-trusted.txt -threads 20 -o $resolvers

    # Validate that fresh resolvers file exists
    if [ ! -f "$resolvers" ]; then
        echo "Could not find fresh resolvers." >&2
    fi
fi


##################### PREPARE SCAN #####################

# Exit if scope path is not found
if [ ! -d "$scope_path" ]; then
    echo "Specified scope was not found."
    exit 1
fi

# If DEBUG mode is on, remove any previous scans with the same scope_id
if [ "$DEBUG" = true ]; then
    rm -rf scans/${scope_id}-*
fi

# Initialize a new scan directory
mkdir -p "$scan_path"

# Prepare scan directory
cp -v "$scope_path/roots.txt" "$scan_path/roots.txt"
sleep 2

# If DEBUG false, ensure lists are up to date before starting
if [ "$DEBUG" = false ]; then
    bash "$ppath/update_lists.sh"
fi

# Notify and show scan details
echo "Starting new scan with ID: $scan_id"
echo "Scan roots:"
cat "$scan_path/roots.txt"


##################### MAIN SCAN LOGIC #####################

# Run subdomain enumeration
cat "$scan_path/roots.txt" | subfinder | anew $subdomains_file

# Optionally run DNS brute-force against roots with ShuffleDNS using Assetnote's best-dns-wordlist and Trickest's public resolvers
if [ "$DNSBF" = true ]; then
    while read -r domain; do
        echo "Starting DNS brute-force against $domain"
        shuffledns -d $domain -w "$ppath/lists/assetnote/best-dns-wordlist.txt" -r $resolvers -mode bruteforce | anew $subdomains_file
    done < "$scan_path/roots.txt"
fi

# Resolve discovered subdomains with PureDNS using Trickest's public resolvers
puredns resolve "$scan_path/subdomains.txt" -r "$ppath/lists/trickest/resolvers-trusted.txt" -w "$scan_path/resolved.txt" | wc -l

# Extract A records from resolved subdomains with dnsx
dnsx -l "$scan_path/resolved.txt" -json -o "$scan_path/dns.json" | jq -r '.a?[]?' | anew "$scan_path/ips.txt" | wc -l
rm -f "$scan_path/dns.json"

# Fingerprint hosts
echo "Fingerprinting hosts using Nmap..."
nmap -iL "$scan_path/ips.txt" -Pn -T4 -A "$ip" -oN "$scan_path/fingerprints.txt"

##################### FINISH AND CLEANUP #####################

# Calculate scan duration
end_time=$(date +%s)
seconds="$(expr $end_time - $timestamp)"
time=""

if [[ "$seconds" -gt 59 ]]
then
    minutes=$(expr $seconds / 60)
    time="$minutes minutes"
else
    time="$seconds seconds"
fi

# Show time taken and notify
echo "Done! Scan $scan_id took $time." # | notify
