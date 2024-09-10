# ethernet_ssn
This repo includes scripts to test your Safe and secure layer over Ethernet. It got tested with Python 3.11.8.

It requires the following modules:
- pycryptodome - https://pypi.org/project/pycryptodome/
```
pip install pycryptodome
```

- Scapy - https://pypi.org/project/scapy/
```
pip install scapy
```

## Included scripts
### show_ifaces.py
It prints the different interfaces. Use it to find your Ethernet interface.
```
> python .\show_ifaces.py
WARNING: Wireshark is installed, but cannot read manuf !
Source   Index  Name                                     MAC                IPv4             IPv6
libpcap  1      Software Loopback Interface 1            00:00:00:00:00:00  127.0.0.1        ::1
libpcap  10     WAN Miniport (IPv6)
libpcap  104    Hyper-V Virtual Ethernet Adapter #5      00:15:5d:53:23:c5  172.18.208.1     fe80::b79:19d9:928c:b14d
libpcap  11     Hyper-V Virtual Ethernet Adapter #2      c8:4b:d6:49:3f:fd  169.254.69.71    fe80::74b5:cb35:34ba:7d26
libpcap  13     Intel(R) Ethernet Connection (16) I219_  c8:4b:d6:49:3f:fd
libpcap  18     Intel(R) Wi-Fi 6E AX211 160MHz           00:d4:9e:52:20:15
libpcap  19     WAN Miniport (Network Monitor)
libpcap  22     Microsoft Wi-Fi Direct Virtual Adapter   00:d4:9e:52:20:16  169.254.248.218  fe80::1f6a:bdfc:da63:6f68
libpcap  24     Bluetooth Device (Personal Area Networ_  00:d4:9e:52:20:19  169.254.31.191   fe80::2498:aad9:5df4:8e45
libpcap  25     Hyper-V Virtual Ethernet Adapter #4      00:d4:9e:52:20:15  192.168.3.214    fe80::bb4f:58e:7867:eca
libpcap  27     Microsoft Network Adapter Multiplexor _  00:d4:9e:52:20:15
libpcap  28     Microsoft Wi-Fi Direct Virtual Adapter_  02:d4:9e:52:20:15  169.254.101.136  fe80::e5f:243e:a0fa:7830
libpcap  29     Hyper-V Virtual Ethernet Adapter #3      c8:4b:d6:49:3f:fe  169.254.200.40   fe80::55e7:b19a:d21e:6895
libpcap  31     WAN Miniport (IP)
libpcap  7      TAP-Windows Adapter V9                   00:ff:2e:d2:23:f9
libpcap  87     Hyper-V Virtual Ethernet Adapter         00:15:5d:3f:de:41  172.27.160.1     fe80::393b:c55a:7a74:e6e4
```

### raw_loopback.py
Implements a loopback over ethernet.
- It only replies to frames from this MAC address: 'd4:be:d9:45:22:61'
- It uses this MAC address as source address for sent messages: 'd4:be:d9:45:22:62'

Edit this file to replace the interface name with the name of your Ethernet adapter:
```python
    # Configure Scapy to use the ethernet interface
    conf.iface="Intel(R) Ethernet Connection (16) I219-LM"
```

### ethernet_ssn.py
Also implements a loopback but with encrypted frames. It also checks CRC on received frames. And puts CRC on sent frames.

Edit this file to replace the interface name with the name of your Ethernet adapter:
```python
    # Configure Scapy to use the ethernet interface
    conf.iface="Intel(R) Ethernet Connection (16) I219-LM"
```
