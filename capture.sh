#!/bin/bash

LAN_IFACE=br0


# Redirect TCP 80 incoming on LAN to local server port 8080
sudo iptables -t nat -A PREROUTING -i $LAN_IFACE -p tcp --dport 80 -j DNAT --to-destination 192.168.2.127:8090
sudo iptables -t nat -A PREROUTING -i $LAN_IFACE -p tcp --dport 443 -j DNAT --to-destination 192.168.2.127:8090

# # Allow forwarding (if using NAT/gw)
# sudo iptables -A FORWARD -i <lan_iface> -o <wan_iface> -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# sudo iptables -A FORWARD -i <lan_iface> -o <wan_iface> -j DROP
