#!/bin/bash
#
# This script filters a list of domains from an input file, resolving each domain to its IP address(es)
# and checking if any of the resolved IP addresses fall within predefined CIDR ranges for Google,
# Cloudflare, and Amazon. If a domain resolves to an IP within these ranges, it is considered a
# "filtered domain" and is written to an output file.
#
# Copyright (C) 2025            spirillen
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Default values for source and output file
default_source="instance.txt"
default_output="filtered_domains.txt"

# Function to display usage
usage() {
    echo "Usage: $0 [-i input_file] [-o output_file] [-u]"
    echo "  -i   Input file containing domain list (default: $default_source)"
    echo "  -o   Output file for filtered domains (default: $default_output)"
    echo "  -u   Update CIDR ranges for providers"
    exit 1
}

# Parse command-line arguments
while getopts "i:o:u" opt; do
    case $opt in
    i) source_file="$OPTARG" ;;
    o) output_file="$OPTARG" ;;
    u) update_cidr=true ;;
    *) usage ;;
    esac
done

# Set defaults if arguments are not provided
source_file="${source_file:-$default_source}"
output_file="${output_file:-$default_output}"

# Check if source file exists
if [[ ! -f "$source_file" ]]; then
    echo "Error: Source file '$source_file' does not exist."
    exit 1
fi

# Clear the output file if it exists
>"$output_file"

# Function to check if an IP is in a given CIDR range
ip_in_cidr() {
    local ip="$1"
    local cidr="$2"

    # Precompute and cache results for efficiency
    local cidr_base cidr_mask ip_dec cidr_base_dec mask network_dec ip_network_dec
    cidr_base="${cidr%/*}"
    cidr_mask="${cidr#*/}"

    # Convert IP and CIDR base to decimal
    ip_dec=$(ip_to_dec "$ip")
    [[ $? -ne 0 ]] && return 1

    cidr_base_dec=$(ip_to_dec "$cidr_base")
    [[ $? -ne 0 ]] && return 1

    mask=$(((1 << (32 - cidr_mask)) - 1))
    network_dec=$((cidr_base_dec & ~mask))
    ip_network_dec=$((ip_dec & ~mask))

    [[ "$ip_network_dec" -eq "$network_dec" ]]
}

# Function to convert IP to decimal
ip_to_dec() {
    local ip="$1"

    # Validate the IP address format (IPv4 only)
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "Error: Invalid IP address format '$ip'" >&2
        return 1
    fi

    local a b c d
    IFS=. read -r a b c d <<<"$ip"
    echo $(((a << 24) + (b << 16) + (c << 8) + d))
}

# Recursive function to resolve CNAME to IP
resolve_to_ip() {
    local domain="$1"
    local resolved_ips

    # Use dig to get A or CNAME records
    resolved_ips=$(dig -4 +short -t A "$domain" 2>/dev/null)
    if [[ $? -ne 0 || -z "$resolved_ips" ]]; then
        echo "Warning: Unable to resolve domain '$domain'" >&2
        return
    fi

    # Loop through the results to check if they are IPs or CNAMEs
    for record in $resolved_ips; do
        if [[ "$record" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            # If it's an IP, print it
            echo "$record"
        else
            # If it's a CNAME, resolve it recursively
            resolve_to_ip "$record"
        fi
    done
}

# Function to update CIDR ranges for providers
update_cidr_ranges() {
    echo "Updating CIDR ranges..."
    # Amazon
    amazon_cidrs=$(curl -x socks5h://127.0.0.1:9050 -s https://ip-ranges.amazonaws.com/ip-ranges.json | jq -r '.prefixes[] | select((.service | test("^CLOUDFRONT"; "i")) or (.service | test("^EC2"; "i")) or .service == "S3") | .ip_prefix' | sort -u | tr '\n' ' ')
    # Cloudflare
    cloudflare_cidrs=$(curl -x socks5h://127.0.0.1:9050 -s https://www.cloudflare.com/ips-v4 | tr '\n' ' ')
    # Google
    google_cidrs=$(curl -x socks5h://127.0.0.1:9050 -s https://www.gstatic.com/ipranges/cloud.json | jq -r '.prefixes[] | .ipv4Prefix' | grep -v 'null' | sort -u | tr '\n' ' ')

    providers["google"]="$google_cidrs"
    providers["cloudflare"]="$cloudflare_cidrs"
    providers["amazon"]="$amazon_cidrs"
    echo "CIDR ranges updated."
}

# Define CIDR ranges for Google, Cloudflare, and Amazon
declare -A providers
providers=(
    ["google"]="35.191.0.0/16 104.154.113.0/24"
    ["cloudflare"]="173.245.48.0/20 108.162.192.0/18"
    ["amazon"]="52.0.0.0/8 100.24.0.0/13"
)

# Update CIDR ranges if -u option is used
if [[ "$update_cidr" == "true" ]]; then
    update_cidr_ranges
fi

# Function to process a single domain
process_domain() {
    local domain="$1"
    local ip_addresses
    ip_addresses=$(resolve_to_ip "$domain")

    for ip in $ip_addresses; do
        for provider in "${!providers[@]}"; do
            for cidr in ${providers[$provider]}; do
                if ip_in_cidr "$ip" "$cidr"; then
                    echo -e "$domain\t$ip" >>"$output_file"
                    return
                fi
            done
        done
    done
}

# Process domains sequentially
while IFS= read -r domain; do
    # Skip empty lines and comments
    [[ -z "$domain" || "$domain" =~ ^# ]] && continue
    process_domain "$domain"
done <"$source_file"

# Sort and remove duplicates in the output file
sort -u "$output_file" -o "$output_file"

echo "Filtered domains have been written to $output_file"
