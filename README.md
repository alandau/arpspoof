# arpspoof - A simple ARP spoofer for Windows

`arpspoof` mounts an [ARP spoofing](https://en.wikipedia.org/wiki/ARP_spoofing) attack against a host on the local network. This results in traffic from the attacked host to the default gateway (and all non-LAN hosts) and back going through the local computer and can thus be captured with tools like Wireshark. `arpspoof` will also forward this traffic, so Windows does NOT have to be configured as a router.

### TL;DR:
```
C:\>arpspoof.exe 192.168.1.10
Resolving victim and target...
Redirecting 192.168.1.10 (00:11:22:33:44:55) ---> 192.168.1.1 (22:33:44:55:66:77)
        and in the other direction
Press Ctrl+C to stop
```

Then run `tcpdump` (or Wireshark) on the local host with the victim's MAC as a filter:
```
tcpdump ether host 00:11:22:33:44:55
```

When done, stop `arpspoof`:
```
^C
Unspoofing
Done
```

### Download

Download `arpspoof.exe` from the [Releases](https://github.com/alandau/arpspoof/releases) page.

### Usage
```
C:\>arpspoof.exe --help
arpspoof.exe --list | [-i iface] [--oneway] victim-ip [target-ip]
```
- `--list` lists the available network interfaces
- `victim-ip` is the IP of the host against which the spoofing attack is mounted (i.e., it is the host that will send us its traffic thinking we are the target host (the default gateway).
- `target-ip` is the host we are pretending to be (as far as `victim-ip` is concerned). If not specified, the default gateway is used as the target (and thus victim's Internet-bound traffic can be captured).
- By default, traffic in both the `victim -> target` and `target -> victim` directions are redirected to the local computer. `--oneway` makes only the `victim -> target` direction to be redirected.
- `-i iface`. An interface on which to spoof ARPs will be automatically detected based on the IP addresses and masks assigned to the local interfaces and `victim-ip`. Use this option to force a specific interface. Use `--list` to see the available options. Both `-i 1` and `-i \Device\NPF_{A91C1830-2930-4B12-8017-6664270142F4}` formats are supported.


List available interfaces for capturing/spoofing:

```
C:\>arpspoof.exe --list
1. \Device\NPF_{A91C1830-2930-4B12-8017-6664270142F4}   VirtualBox Host-Only Ethernet Adapter (VirtualBox Host-Only Network)
        192.168.56.1/24 gw=0.0.0.0
2. \Device\NPF_{9E13DC15-DBFB-4CE2-95D5-8DD283412185}   Intel(R) Dual Band Wireless-AC 8265 (Wi-Fi)
        192.168.1.10/24 gw=192.168.1.1
```

Make host 192.168.1.5 believe our computer to be the default gateway 192.168.1.1, and thus send us its Internet-bound traffic, and make the gateway 192.168.1.1 believe our computer to be 192.168.1.5, and thus send replies to us:

```
C:\>arpspoof.exe 192.168.1.5
```

The same, but only in one direction 192.168.1.5 -> 192.168.1.1. The other direction does not pass through our computer:

```
C:\>arpspoof.exe --oneway 192.168.1.5
```

### System Requirements

`arpspoof` was developed and tested on Windows 10. It should work on Windows Vista/7/8/10. It does NOT work on Windows XP, since it uses APIs introduced in Vista.

`arpspoof` uses [WinPcap](https://www.winpcap.org/) to send spoofed packets and forward traffic. WinPcap should be installed for `arpspoof` to run. Note that Wireshark installs WinPcap by default, so having Wireshark installed should be enough.
