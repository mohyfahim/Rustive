#!/bin/sh

# dnsmasq call args:
# $1 = add|old|del, $2 = MAC, $3 = IP, $4 = HOSTNAME, $5 = CLIENTID (maybe)
ACTION="$1"
MAC="$2"
IP="$3"
HOSTNAME="$4"
CLIENTID="$5"

logger -t dnsmasq-hook "dhcp-event action=$ACTION mac=$MAC ip=$IP host=$HOSTNAME client-id=$CLIENTID"

if [ "$ACTION" = "del" ] || [ "$ACTION" = "add" ] || [ "$ACTION" = "old" ]; then

	## check IP is IPv4 and not IPv6
	if [[ "$IP" =~ : ]]; then
		logger -t dnsmasq-hook "Skipping IPv6 address: $IP"
		exit 0
	fi

	wget -q -O /dev/null --timeout=2 --header='Content-Type: application/json' \
		--post-data="{\"action\":\"$ACTION\",\"mac\":\"$MAC\",\"ip\":\"$IP\",\"hostname\":\"$HOSTNAME\",\"clientid\":\"$CLIENTID\"}" \
		http://127.0.0.1:8090/dhcp || true

	wget -q -O /dev/null --timeout=2 --header='Content-Type: application/json' \
		--post-data="{\"action\":\"$ACTION\",\"mac\":\"$MAC\",\"ip\":\"$IP\",\"hostname\":\"$HOSTNAME\",\"clientid\":\"$CLIENTID\"}" \
		http://192.168.2.127:8090/dhcp || true

fi

exit 0
