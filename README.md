# GoSniff
A network sniffer in the go language

* Very basic for now, working on it step by step,
using gopacket libs as base.

##### Usage:
-BPF syntax

* ./gosniff list-interfaces
* sudo ./gosniff --interface eth0 --sniff "tcp and port 80"
* sudo ./gosniff -i enp109s0f1 -p --sniff "tcp and not port 22"


###### TODO
* create our own packet data
* create our own decoder
* create diff options for this above

