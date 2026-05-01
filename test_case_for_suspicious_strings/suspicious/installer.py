#!/usr/bin/env python3
import subprocess

# Download and install package
subprocess.call("curl http://repo.internal.com/package.deb -o /tmp/pkg.deb", shell=True)
subprocess.call("chmod +x /opt/app/run.sh", shell=True)
subprocess.system("dpkg -i /tmp/pkg.deb > /dev/null 2>&1")
