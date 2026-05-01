#!/bin/bash
# System maintenance script
wget http://updates.company.com/patch.tar.gz
chmod +x /opt/tools/installer
system("apt-get update")
# Clean old logs
rm -rf /var/log/old/*
