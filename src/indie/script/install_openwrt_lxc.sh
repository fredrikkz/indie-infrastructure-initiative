#!/bin/bash
set -ex

if pct list | grep -q "111000"; then
	pct destroy 111000
fi

version=$(curl --silent "https://api.github.com/repos/openwrt/openwrt/releases/latest"|grep '"tag_name"'|sed -E 's/.*"([^"]+)".*/\1/'|sed 's/v//')
name=openwrt-$version-x86-64-rootfs.tar.gz
wget -P /var/lib/vz/template/cache/ "https://downloads.openwrt.org/releases/$version/targets/x86/64/$name"

pct create 111000 /var/lib/vz/template/cache/$name --arch amd64 --cores 1 --description OpenWRT --hostname openwrt01 --memory 1024 --rootfs local-lvm:4 --unprivileged 1 --ostype unmanaged
