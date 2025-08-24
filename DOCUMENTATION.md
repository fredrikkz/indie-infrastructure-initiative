# Implementation details

## Proxmox
Setup: 
* Install
* Remove subscription notice
* Remove enterprise APTs
* Add no-sub APTs
* Enable firewall
* Enable IP forwarding
* Add iiivmbr0


## OpenWRT
Links:
* https://openwrt.org/docs/guide-user/installation/openwrt_x86
* https://github.com/fdcastel/Proxmox-Automation?tab=readme-ov-file#openwrt

Commands:
```
wget -P /var/lib/vz/template/cache https://downloads.openwrt.org/releases/24.10.2/targets/x86/64/openwrt-24.10.2-x86-64-rootfs.tar.gz
pct create 301 local:vztmpl/openwrt-24.10.2-x86-64-rootfs.tar.gz --rootfs local:0.256 --ostype unmanaged --hostname openwrt --arch amd64 --cores 1 --memory 256 --swap 0 --unprivileged 1
```
