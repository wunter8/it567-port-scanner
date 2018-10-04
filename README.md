# it567-port-scanner

This is a simple port scanner built for IT567 at BYU using Scapy/Python3

## Getting Started

This was developed and tested on Kali Linux using Python3. `sudo` access is required to run the script as it opens sockets.

### Prerequisites

You will need the following Python3 packages:
* scapy
* netaddr
* argparse

You can install them with `pip`
```
python3 -m pip install scapy
```

## Usage
```
usage: scanner.py [-h] (--host HOST | -a A) (-p PORT | -I | -T)
                  [--type {tcp_connect,tcp_stealth,udp}] [--html HTML]

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           The host you want to scan.
			Use one of following formats:
				Range (192.168.0.1-192.168.0.255)
				Subnet mask (192.168.0.0/24)
				Comma separated (192.168.0.5,192.168.0.10)
  -a A                  Text file with 1 host per line
  -p PORT, --port PORT  The port you want to scan
  -I, --icmp            Perform ICMP echo request
  -T, --traceroute      Perform UDP traceroute
  --type {tcp_connect,tcp_stealth,udp}
                        The scan type you want to perform
			(Default: tcp_connect)
  --html HTML           Store results to HTML file
```

## Grading Rubric Features
* command-line switches for host and port
* simple response to user
* text file with hosts
* subnet mask host entry
* range host entry
* multiple ports
* ICMP
* UDP
* TCP
* UDP traceroute
* export to HTML file
* Extra:
  * TCP Stealth/Half-open scan
