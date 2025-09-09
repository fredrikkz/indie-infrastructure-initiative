#!/bin/bash
set -ex

hostname=$(hostname)
report_progress() {{
    curl -sS -o /dev/null --insecure --json "{{\"hostname\":\"$hostname\",\"message\":\"$1\"}}" https://indie.{domain}:8000/report-progress?token={token}
}}
# NOTE: Enable firewall as soon as possible, we'll however replace it with OpenWRT soon
physical_network_interface=$(find /sys/class/net -type l -not -lname '*virtual*' -printf '%f;' | cut -d';' -f1)
report_progress "Physical network interface identified as $physical_network_interface"
report_progress "Configuring proxmox host firewall..."
cat << EOF > /etc/pve/firewall/cluster.fw
[OPTIONS]
enable: 1
[RULES]
OUT ACCEPT -i $physical_network_interface -p tcp -dport 80,443,8000 -log nolog # http/https/indie webserver
OUT ACCEPT -i $physical_network_interface -p udp -dport 53 -log nolog # DNS
IN ACCEPT -i $physical_network_interface -p tcp -dport 22 -log nolog # proxmox SSH
IN ACCEPT -i $physical_network_interface -p tcp -dport 8006 -log nolog # proxmox GUI
EOF
report_progress "Starting proxmox host firewall..."
pve-firewall restart
sleep 3
proxmox_firewall_status=$(pve-firewall status)
report_progress "Firewall status reported as: $proxmox_firewall_status"

report_progress "Re-writing apt sources..."
sed -i 's|URIs: https://enterprise.proxmox.com/debian/ceph-squid|URIs: http://download.proxmox.com/debian/ceph-squid|g' /etc/apt/sources.list.d/ceph.sources
sed -i 's|Components: enterprise|Components: no-subscription|g' /etc/apt/sources.list.d/ceph.sources
sed -i 's|URIs: https://enterprise.proxmox.com/debian/pve|URIs: http://download.proxmox.com/debian/pve|g' /etc/apt/sources.list.d/pve-enterprise.sources
sed -i 's|Components: pve-enterprise|Components: pve-no-subscription|g' /etc/apt/sources.list.d/pve-enterprise.sources
report_progress "Running apt update..."
apt-get update
report_progress "Running apt upgrade, this can take a while..."
apt-get upgrade -y

report_progress "Installing vim..."
apt install vim -y

report_progress "Enable ipv4 forwarding..."
echo "net.ipv4.ip_forward=1" > /usr/lib/sysctl.d/99-indie.conf
sysctl --system
sysctl net.ipv4.ip_forward

report_progress "Fetching $hostname internal IP..."
host_internal_ip=$(wget --no-check-certificate -O - "https://indie.{domain}:8000/get-info?token={token}&hostname=$hostname&attribute=internal-ip")
report_progress "Resolved $hostname internal IP as $host_internal_ip..."
report_progress "Creating indie vm network bridge..."
cat << EOF >> /etc/network/interfaces

auto indiebr0
iface indiebr0 inet static
        address $host_internal_ip/16
        bridge-ports none
        bridge-stp off
        bridge-fd 0
        post-up   iptables -t nat -A POSTROUTING -s '10.111.0.0/16' -o $physical_network_interface -j MASQUERADE
        post-down iptables -t nat -D POSTROUTING -s '10.111.0.0/16' -o $physical_network_interface -j MASQUERADE
EOF
report_progress "Restarting network..."
ifreload -a

while ! ping -c 1 -W 1 86.54.11.1 &> /dev/null; do
  echo "Waiting for network..."
  sleep 1
done

report_progress "Remove subscription popup..."
sed -i 's|checked_command: function (orig_cmd) {{|checked_command: function (orig_cmd) {{ orig_cmd(); return;|g' /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js
systemctl restart pveproxy.service

report_progress "Running apt purge proxmox-first-boot..."
apt purge proxmox-first-boot -y

{api}

report_progress "Script in first-boot completed successfully, server will now reboot a final time"
#reboot

