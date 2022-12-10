[![Pcap_summary, 3.7, 3.8, 3.9, 3.10](https://github.com/craigarms/pcap_summary/actions/workflows/python-package.yml/badge.svg)](https://github.com/craigarms/pcap_summary/actions/workflows/python-package.yml)

# Pcap_summary

This is a wrapper script for Scapy that will parse a pcap file and output a summary of the packets in the file. 
It will also output a summary of the protocols used in the pcap file.

## Usage

### Summarizing a pcap file:

    pcap_summary <pcap file>

Example:
    
        pcap_summary http.pcap

Output:
```
Proto    Src                 Dst                Flags      Flow Size    FCount    RCount
-------  ------------------  -----------------  -------  -----------  --------  --------
UDP      24.6.173.220:53867  75.75.75.75:53     --               142         1         1
UDP      24.6.173.220:54997  75.75.75.75:53     --               368         2         2
TCP      24.6.173.220:42379  174.137.42.75:80   SAPFR          14175         7        11
TCP      24.6.173.220:42380  174.137.42.75:80   SAP             7251         7         8
UDP      24.6.173.220:49643  75.75.75.75:53     --               276         1         1
UDP      24.6.173.220:59261  75.75.75.75:53     --               297         1         1
[...]
```

TCP flags are decoded as follows and added to the flow summary:

    S = SYN
    A = ACK
    F = FIN
    R = RST
    P = PSH
    U = URG
    E = ECE
    C = CWR

The flow size is the total size of the flow in bytes incremented via the IP length field.

The FCount is the number of packets for a given source and destination socket pair in one direction  
The RCount is the number of packets for the given pair in the opposite direction.


### Summarizing a pcap file and filtering:
    
    pcap_summary <pcap file> <search>

Example:
    
        pcap_summary http.pcap 174.137.42.75

Output:
```
Proto    Src                 Dst               Flags      Flow Size    FCount    RCount
-------  ------------------  ----------------  -------  -----------  --------  --------
TCP      24.6.173.220:42379  174.137.42.75:80  SAPFR          14175         7        11
TCP      24.6.173.220:42380  174.137.42.75:80  SAP             7251         7         8
TCP      24.6.173.220:42381  174.137.42.75:80  SAP             8126         5         7
TCP      24.6.173.220:42383  174.137.42.75:80  SAP              452         2         1
TCP      24.6.173.220:42384  174.137.42.75:80  SA               144         2         1
```

The search is performed by looking if the given string is present in the list formed by the flow.

## Installation

Available on Pypi:

    pip install pcap_summary
