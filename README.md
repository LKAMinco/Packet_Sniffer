# IPK PROJECT 2 - PACKET SNIFFER

### Author: Milan Hrabovský - xhrabo15

### Description:

A server that enable client to obtain info from server. Client can obtain, hostname, cpu name, cpu's load.

## Installation and use

* Build code with command ```make```.
* Use
  command ```./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}```
  to run packet sniffer.

### Available configurations

* *-i/--interface* - specify interface where will be packets captured, if it not set or if it is empty, program will print all awaiable
  interfaces
* *-p PORT* - specify the **port** where will be packet sniffing performed. **PORT** is unsigned integer
* *--tcp|-t* - filtering just **tcp** packets
* *--udp|-u* - filtering just **udp** packets
* *--arp* - filtering just **arp** packets
* *--icmp* - filtering just **icmp/icmp6** packets
* *-n NUM* - specify how many packets will be captured. Default value is 1, **NUM** is unsigned integer

##Examples
```
./ipk-sniffer

1. eth0
2. any
3. lo
4. dummy0
5. tunl0
6. sit0
7. bluetooth-monitor
8. nflog
9. nfqueue
10. dbus-system
11. dbus-session
12. bond0
```
```
./ipk-sniffer -i eth0 --udp

timestamp: 2022-04-24T14:39:10.552+02:00
src MAC:  00:15:5d:25:db:49
dst MAC:  01:00:5e:7f:ff:fa
frame length: 217 bytes
src IP: 172.24.224.1
dst IP: 239.255.255.250
src port: 65473
dst port: 1900

0x0000:  01 00 5e 7f ff fa 00 15   5d 25 db 49 08 00 45 00   ..^....]%.I..E.
0x0010:  00 cb c9 60 00 00 01 11   73 ad ac 18 e0 01 ef ff   ...`....s.......
0x0020:  ff fa ff c1 07 6c 00 b7   08 ca 4d 2d 53 45 41 52   .....l....M-SEAR
0x0030:  43 48 20 2a 20 48 54 54   50 2f 31 2e 31 0d 0a 48   CH * HTTP/1.1..H
0x0040:  4f 53 54 3a 20 32 33 39   2e 32 35 35 2e 32 35 35   OST: 239.255.255
0x0050:  2e 32 35 30 3a 31 39 30   30 0d 0a 4d 41 4e 3a 20   .250:1900..MAN:
0x0060:  22 73 73 64 70 3a 64 69   73 63 6f 76 65 72 22 0d   "ssdp:discover".
0x0070:  0a 4d 58 3a 20 31 0d 0a   53 54 3a 20 75 72 6e 3a   .MX: 1..ST: urn:
0x0080:  64 69 61 6c 2d 6d 75 6c   74 69 73 63 72 65 65 6e   dial-multiscreen
0x0090:  2d 6f 72 67 3a 73 65 72   76 69 63 65 3a 64 69 61   -org:service:dia
0x00a0:  6c 3a 31 0d 0a 55 53 45   52 2d 41 47 45 4e 54 3a   l:1..USER-AGENT:
0x00b0:  20 47 6f 6f 67 6c 65 20   43 68 72 6f 6d 65 2f 31    Google Chrome/1
0x00c0:  30 30 2e 30 2e 34 38 39   36 2e 31 32 37 20 57 69   00.0.4896.127 Wi
0x00d0:  6e 64 6f 77 73 0d 0a 0d   0a                        ndows....
```
##Files
* xhrabo15.cpp
* README.md
* Makefile

## Sources

* pcap library - https://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap/
* Convert time - https://www.epochconverter.com/programming/c
* Getting ip address - https://stackoverflow.com/questions/21222369/getting-ip-address-of-a-packet-in-pcap-file
* Getting mac address
    - https://stackoverflow.com/questions/4526576/how-do-i-capture-mac-address-of-access-points-and-hosts-connected-to-it