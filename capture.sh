#!/bin/sh
# adjust these if your values differ
BR_IF="br0"
CAPTIVE_IP="192.168.2.127"
LAN_NET="192.168.2.0/24"

# (optional) create a small nat chain to keep PREROUTING tidy
sudo iptables -t nat -N CAPTIVE 2>/dev/null || true
sudo iptables -t nat -F CAPTIVE

# If destination is in the LAN, do nothing (don't redirect local-to-local)
sudo iptables -t nat -A CAPTIVE -d ${LAN_NET} -j RETURN

# Redirect HTTP/HTTPS to the local server
sudo iptables -t nat -A CAPTIVE -p tcp --dport 80  -j DNAT --to-destination ${CAPTIVE_IP}:8090
sudo iptables -t nat -A CAPTIVE -p tcp --dport 443 -j DNAT --to-destination ${CAPTIVE_IP}:8090

# Hook the chain for traffic arriving on br0
sudo iptables -t nat -A PREROUTING -i ${BR_IF} -j CAPTIVE

# Allow the router itself (if webserver runs on router) to accept those connections:
sudo iptables -A INPUT -i ${BR_IF} -d ${CAPTIVE_IP} -p tcp --dport 8090  -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#sudo iptables -A INPUT -i ${BR_IF} -d ${CAPTIVE_IP} -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Accept related/established forwarding (general safety)
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A FORWARD -i ${BR_IF} -o ${BR_IF} -j ACCEPT

# (optional) show the nat table so you can verify
sudo iptables -t nat -L PREROUTING -n -v
sudo iptables -t nat -L CAPTIVE -n -v
