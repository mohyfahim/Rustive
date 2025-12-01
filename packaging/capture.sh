#!/bin/bash
# adjust these if your values differ
BR_IF="br0"
CAPTIVE_IP="192.168.2.127"
LAN_NET="192.168.2.0/24"
CAPTIVE_CHAIN="CAPTIVE"
FLUSH_CAPTIVE="${FLUSH_CAPTIVE:-yes}"

# helper: check-rule uses iptables -C if available, otherwise greps the listing.
check_rule() {
  	# args forwarded to iptables (table/chain not included). returns 0 if exists
	local check_args=()
	local replaced=0
  	for token in "$@"; do
    	if [ $replaced -eq 0 ] && { [ "$token" = "-A" ] || [ "$token" = "-I" ]; }; then
      		check_args+=("-C"); replaced=1
    	else
      		check_args+=("$token")
    	fi
	done

  	if iptables "${check_args[@]}" >/dev/null 2>&1; then
	    return 0
  	fi

  return 1
}

add_rule() {
  # usage: add_rule <full iptables args...>
  if check_rule "$@"; then
    echo "rule exists: iptables $*"
  else
    echo "adding rule: iptables $*"
    iptables "$@"
  fi
}

# Create chain if not exists
if ! iptables -t nat -nL "${CAPTIVE_CHAIN}" >/dev/null 2>&1; then
  iptables -t nat -N "${CAPTIVE_CHAIN}"
  echo "Created nat chain ${CAPTIVE_CHAIN}"
fi

# Optionally flush (be careful: removes whitelists)
if [ "${FLUSH_CAPTIVE}" = "yes" ]; then
  iptables -t nat -F "${CAPTIVE_CHAIN}"
  echo "Flushed ${CAPTIVE_CHAIN}"
fi

# If destination is in the LAN, do nothing (don't redirect local-to-local)
add_rule -t nat -A "${CAPTIVE_CHAIN}" -d "${LAN_NET}" -j RETURN
add_rule -t nat -A "${CAPTIVE_CHAIN}" -d "${CAPTIVE_IP}" -j RETURN


# Redirect HTTP/HTTPS to the local server
add_rule -t nat -A "${CAPTIVE_CHAIN}" -p tcp --dport 80  -j DNAT --to-destination "${CAPTIVE_IP}:8090"
add_rule -t nat -A "${CAPTIVE_CHAIN}" -p tcp --dport 443 -j DNAT --to-destination "${CAPTIVE_IP}:8090"



# Hook CAPTIVE chain from PREROUTING - only one hook needed
# We check existence by inspecting nat PREROUTING for the exact jump
if ! iptables -t nat -C PREROUTING -i "${BR_IF}" -j "${CAPTIVE_CHAIN}" >/dev/null 2>&1; then
  echo "Adding PREROUTING hook to ${CAPTIVE_CHAIN}"
  iptables -t nat -A PREROUTING -i "${BR_IF}" -j "${CAPTIVE_CHAIN}"
else
  echo "PREROUTING hook already exists"
fi


# Allow the router itself (if webserver runs on router) to accept those connections:
add_rule -A INPUT -i "${BR_IF}" -d "${CAPTIVE_IP}" -p tcp --dport 8090 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#sudo iptables -A INPUT -i ${BR_IF} -d ${CAPTIVE_IP} -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Accept related/established forwarding (general safety)
add_rule -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
add_rule -A FORWARD -i "${BR_IF}" -o "${BR_IF}" -j ACCEPT

# # (optional) show the nat table so you can verify
# # Show final state for verification
# echo
# echo "---- nat PREROUTING ----"
# iptables -t nat -L PREROUTING -n -v || true
# echo
# echo "---- nat ${CAPTIVE_CHAIN} ----"
# iptables -t nat -L "${CAPTIVE_CHAIN}" -n -v || true
# echo
# echo "---- filter INPUT/FORWARD ----"
# iptables -L INPUT -n -v --line-numbers || true
# iptables -L FORWARD -n -v --line-numbers || true
