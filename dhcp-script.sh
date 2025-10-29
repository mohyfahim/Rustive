#!/bin/bash

# dnsmasq call args:
# $1 = add|old|del, $2 = MAC, $3 = IP, $4 = HOSTNAME, $5 = CLIENTID (maybe)
ACTION="$1"
MAC="$2"
IP="$3"
HOSTNAME="$4"
CLIENTID="$5"

logger -t dnsmasq-hook "dhcp-event action=$ACTION mac=$MAC ip=$IP host=$HOSTNAME client-id=$CLIENTID"

# if [[ "$ACTION" == "add" ]] || [[ "$ACTION" == "del" ]];then
	# Post to local service (adjust target URL/port)
curl -s -m 3 -X POST http://127.0.0.1:8090/dhcp \
-H 'Content-Type: application/json' \
-d "{\"action\":\"$ACTION\",\"mac\":\"$MAC\",\"ip\":\"$IP\",\"hostname\":\"$HOSTNAME\",\"clientid\":\"$CLIENTID\"}" || true


# fi
exit 0