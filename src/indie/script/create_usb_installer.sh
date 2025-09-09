#!/bin/bash
set -ex
if [[ $# -ne 1 ]]; then
    echo "Illegal number of parameters" >&2
    exit 2
fi

apt install proxmox-auto-install-assistant -y

# Prepare USB
mkfs.vfat -I $1
fatlabel $1 "AUTOPROXMOX"

# Get ISO
wget https://enterprise.proxmox.com/iso/{iso_name}.iso
proxmox-auto-install-assistant prepare-iso {iso_name}.iso --fetch-from http --url "https://indie.{domain}:8000/proxmox-answer?token={token}" --cert-fingerprint "{fingerprint}" --output {iso_name}-auto.iso
dd bs=1M conv=fdatasync if=./{iso_name}-auto.iso of=$1
rm {iso_name}.iso
rm {iso_name}-auto.iso

