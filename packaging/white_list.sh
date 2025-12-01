#!/bin/bash
# whitelist_client.sh
# Usage:
#   ./whitelist_client.sh add  192.168.2.50 aa:bb:cc:dd:ee:ff
#   ./whitelist_client.sh add  192.168.2.50          # allow by IP only
#   ./whitelist_client.sh add  ""  aa:bb:cc:dd:ee:ff  # allow by MAC only
#   ./whitelist_client.sh del  192.168.2.50 aa:bb:cc:dd:ee:ff
#   ./whitelist_client.sh list
#
# Assumptions:
# - Your captive logic uses a nat chain named "CAPTIVE" hooked from PREROUTING (per previous scripts).
# - Interface used by clients is br0 (optional: you can change BR_IF).
# - Script is run as root.

BR_IF="br0"
CAPTIVE_CHAIN="CAPTIVE"

die() { echo "ERROR: $*" >&2; exit 1; }

# simple validators
is_ip() {
  printf "%s" "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
}
is_mac() {
  printf "%s" "$1" | grep -Eiq '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'
}

if [ "$(id -u)" -ne 0 ]; then
  die "run as root"
fi

if ! iptables -n -t nat -L "${CAPTIVE_CHAIN}" >/dev/null 2>&1; then
  die "nat chain ${CAPTIVE_CHAIN} not found. Ensure captive script created it."
fi

op="$1"
ip="$2"
mac="$3"

case "${op}" in
  add)
    [ -z "$ip" ] && [ -z "$mac" ] && die "provide at least IP or MAC to add"
    # Add nat rule(s) to RETURN before the DNAT so this client is not redirected.
    if [ -n "$mac" ]; then
      is_mac "$mac" || die "invalid MAC format"
      # Check existence first
      if iptables -t nat -C "${CAPTIVE_CHAIN}" -m mac --mac-source "${mac}" -j RETURN >/dev/null 2>&1; then
        echo "MAC ${mac} already whitelisted in ${CAPTIVE_CHAIN}"
      else
        # Insert at top so it matches before other RETURN checks or DNAT
        iptables -t nat -I "${CAPTIVE_CHAIN}" 1 -m mac --mac-source "${mac}" -j RETURN \
          || die "failed to add MAC whitelist rule"
        echo "Added MAC whitelist: ${mac}"
      fi
      # Also allow forwarding in filter table
      if iptables -C FORWARD -m mac --mac-source "${mac}" -j ACCEPT >/dev/null 2>&1; then
        echo "FORWARD accept already present for MAC ${mac}"
      else
        iptables -I FORWARD 1 -m mac --mac-source "${mac}" -j ACCEPT \
          || die "failed to add FORWARD accept for MAC"
        echo "Added FORWARD accept for MAC ${mac}"
      fi
    fi

    if [ -n "$ip" ]; then
      is_ip "$ip" || die "invalid IP format"
      if iptables -t nat -C "${CAPTIVE_CHAIN}" -s "${ip}" -j RETURN >/dev/null 2>&1; then
        echo "IP ${ip} already whitelisted in ${CAPTIVE_CHAIN}"
      else
        iptables -t nat -I "${CAPTIVE_CHAIN}" 1 -s "${ip}" -j RETURN \
          || die "failed to add IP whitelist rule"
        echo "Added IP whitelist: ${ip}"
      fi
      # Allow forwarding to/from this IP (useful if default FORWARD policy is DROP)
      if iptables -C FORWARD -s "${ip}" -j ACCEPT >/dev/null 2>&1; then
        echo "FORWARD accept already present for source IP ${ip}"
      else
        iptables -I FORWARD 1 -s "${ip}" -j ACCEPT || die "failed to add FORWARD accept (src)"
        echo "Added FORWARD accept for source IP ${ip}"
      fi
      if iptables -C FORWARD -d "${ip}" -j ACCEPT >/dev/null 2>&1; then
        echo "FORWARD accept already present for dest IP ${ip}"
      else
        iptables -I FORWARD 1 -d "${ip}" -j ACCEPT || die "failed to add FORWARD accept (dst)"
        echo "Added FORWARD accept for dest IP ${ip}"
      fi
    fi

    ;;

  del)
    [ -z "$ip" ] && [ -z "$mac" ] && die "provide at least IP or MAC to delete"
    if [ -n "$mac" ]; then
      is_mac "$mac" || die "invalid MAC format"
      if iptables -t nat -C "${CAPTIVE_CHAIN}" -m mac --mac-source "${mac}" -j RETURN >/dev/null 2>&1; then
        iptables -t nat -D "${CAPTIVE_CHAIN}" -m mac --mac-source "${mac}" -j RETURN \
          || die "failed to remove MAC whitelist nat rule"
        echo "Removed MAC whitelist: ${mac}"
      else
        echo "No MAC whitelist nat rule found for ${mac}"
      fi
      iptables  -C FORWARD -m mac --mac-source "${mac}" -j ACCEPT >/dev/null 2>&1 && \
        iptables  -D FORWARD -m mac --mac-source "${mac}" -j ACCEPT && echo "Removed FORWARD accept for MAC ${mac}"
    fi

    if [ -n "$ip" ]; then
      is_ip "$ip" || die "invalid IP format"
      if iptables -t nat -C "${CAPTIVE_CHAIN}" -s "${ip}" -j RETURN >/dev/null 2>&1; then
        iptables -t nat -D "${CAPTIVE_CHAIN}" -s "${ip}" -j RETURN || die "failed to remove IP whitelist nat rule"
        echo "Removed IP whitelist: ${ip}"
      else
        echo "No IP whitelist nat rule found for ${ip}"
      fi
      iptables -C FORWARD -s "${ip}" -j ACCEPT >/dev/null 2>&1 && \
        iptables -D FORWARD -s "${ip}" -j ACCEPT && echo "Removed FORWARD accept for src IP ${ip}"
      iptables -C FORWARD -d "${ip}" -j ACCEPT >/dev/null 2>&1 && \
        iptables -D FORWARD -d "${ip}" -j ACCEPT && echo "Removed FORWARD accept for dst IP ${ip}"
    fi
    ;;

  list)
    echo "nat ${CAPTIVE_CHAIN} rules (showing lines that RETURN for whitelist):"
    iptables -t nat -L "${CAPTIVE_CHAIN}" -n --line-numbers | grep -E 'RETURN|mac' || true
    echo
    echo "filter FORWARD rules relevant to whitelisted IP/MAC:"
    iptables -L FORWARD -n --line-numbers | grep -E 'ACCEPT|'"${ip}"'|'"${mac}" || true
    ;;

  *)
    cat <<EOF
Usage:
  $0 add  <ip> <mac>   - whitelist client (either field may be empty "")
  $0 del  <ip> <mac>   - remove whitelist
  $0 list              - show whitelist-like rules
Examples:
  $0 add  192.168.2.50 aa:bb:cc:dd:ee:ff
  $0 add  192.168.2.50
  $0 add  "" aa:bb:cc:dd:ee:ff
EOF
    exit 1
    ;;
esac

exit 0
