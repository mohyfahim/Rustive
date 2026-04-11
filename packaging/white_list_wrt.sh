#!/bin/sh

# Configuration
IPSET_NAME="authorized_clients"
CONFIG="firewall"

# Usage Instruction
usage() {
	echo "Usage: $0 {add|del|list} [IP_ADDRESS]"
	echo "  add  : Adds an IP to the persistent UCI config and reloads firewall."
	echo "  del  : Removes an IP from the persistent UCI config and reloads firewall."
	echo "  list : Lists IPs currently in the UCI config for this ipset."
	exit 1
}

# 1. Find the section ID of the ipset (e.g., @ipset[0])
get_section_id() {
	# We search `uci show` output for the section that contains option name 'authorized_clients'
	# returns something like "@ipset[0]"
	SECTION=$(uci show $CONFIG | grep name | grep "$IPSET_NAME" | cut -d'.' -f2)

	if [ -z "$SECTION" ]; then
		echo "Error: ipset '$IPSET_NAME' not found in /etc/config/$CONFIG"
		exit 1
	fi
	echo "$SECTION"
}

# 2. List IPs
list_ips() {
	SECTION=$(get_section_id)
	echo "IPs in $IPSET_NAME (UCI Config):"
	uci -q get $CONFIG.$SECTION.entry
}

# 3. Add IP
add_ip() {
	IP=$1
	if [ -z "$IP" ]; then
		echo "Error: Missing IP address"
		usage
	fi

	SECTION=$(get_section_id)

	# Check if IP already exists to prevent duplicates (optional logic)
	EXISTING=$(uci -q get $CONFIG.$SECTION.entry | grep -w "$IP")
	if [ -n "$EXISTING" ]; then
		echo "IP $IP is already in the list."
		exit 0
	fi

	echo "Adding $IP to $IPSET_NAME..."
	uci add_list $CONFIG.$SECTION.entry="$IP"
	apply_changes
}

# 4. Commit and Reload
apply_changes() {
	echo "Committing changes..."
	uci commit $CONFIG

	# echo "Reloading firewall to update ipset..."
	/etc/init.d/firewall reload

	echo "Done."
}

# 5. Delete IP
del_ip() {
	IP=$1
	if [ -z "$IP" ]; then
		echo "Error: Missing IP address"
		usage
	fi

	SECTION=$(get_section_id)

	echo "Removing $IP from $IPSET_NAME..."
	# del_list removes the entry matching the value
	uci del_list $CONFIG.$SECTION.entry="$IP"
	apply_changes
}

# Main Logic
case "$1" in
add)
	add_ip "$2"
	;;
del)
	del_ip "$2"
	;;
list)
	list_ips
	;;
*)
	usage
	;;
esac
