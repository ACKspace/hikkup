# Hikkup - Hikvision wifi doorbell MITM proxy

**NOTE:** the provided script is not fully functional yet; please help and improve it.

This python script tries to run a man-in-the-middle proxy service to intercept traffic from and to a Hikvision rebranded wifi camera doorbell.
The current script is targeted at a _Uniden DB1_ unit, but it exists under other labels as well: _Clare - CVP-B2DB50-ODIW_, _RCA - HSDB1_, _LTS - LTK6128W-WIFI_ and _Nelly - NSC-DB1_.
It accepts connections and tries to change foreign IP addresses in the _XML_ it receives to its own IP address.

# Prerequisites
Everything is written and tested only using Ubuntu Mate Linux; your mileage may vary on different systems 
* python3
* python libraries (some are packaged with python) :
  * sys
  * select
  * socket
  * ssl
  * re
  * hashlib
  * Crypto.Cipher
  * time
* Router/gateway that lets you enter a DNS entry manually

# Setup
* Add a DNS entry for `dev.ezvizlife.com` that points to the IP address of your PC (verify with `ping` that this works)
* You might want to do the same for `alarmeu.ezvizlife.com` (not sure)
* run the script in a command prompt: `./hikkup.py` and it will show something like this:
```[*] Listening on 192.168.2.202 8555 (SSL)
[*] Listening on 192.168.2.202 6900 (SSL)
[*] Listening on 192.168.2.202 6800
[*] Listening on 192.168.2.202 7400 (SSL)
```
* After this, power your wifi doorbell and make sure it connects to the same network as your PC resides in

It now should start spitting out logs of information and the doorbell should succeed with connecting (via the proxy).

# Notes
The script connects to `52.212.63.175` (initially) and `34.246.99.36` (after initial connection); these IP addresses were the addresses where the DNS entries were pointing to officially.

