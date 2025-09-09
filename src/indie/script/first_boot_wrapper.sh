#!/bin/bash
set -ex
wget --no-check-certificate -O ~/first_boot.sh "https://indie.{domain}:8000/getscript?token={token}&script=first_boot.sh"
chmod +x ~/first_boot.sh
(~/first_boot.sh 2>&1 | tee ~/first_boot.log) &
