#!/usr/bin/env python3

from scapy.all import *
import argparse
import sys
from netaddr import IPNetwork
from netaddr import IPRange
from netaddr.core import AddrFormatError

results = {}

# basic tcp scan
def tcp_connect(host, port):
    global results

    print("tcp_connect scan - {}:{}".format(host, port))

    ip = IP()
    ip.dst = host

    tcp = TCP()
    tcp.dport = port
    tcp.sport = RandShort()
    tcp.flags = "S"

    tcp_connect = sr1((ip/tcp), timeout=10, verbose=0)
    if type(tcp_connect) == type(None):
        # got no response, port closed
        print("Port {} on {} is closed".format(port, host))
        results[host]["{}/tcp".format(port)] = "closed"

    elif tcp_connect.haslayer(TCP) and tcp_connect.getlayer(TCP).flags == 0x12:
        # got SYN/ACK, send ACK/RST
        tcp.flags = "AR"

        send_rst = sr((ip/tcp), timeout=10, verbose=0)
        print("Port {} on {} is open".format(port, host))
        results[host]["{}/tcp".format(port)] = "open"

    elif tcp_connect.haslayer(TCP) and tcp_connect.getlayer(TCP).flags == 0x14:
        # got RST, port closed
        print("Port {} on {} is closed".format(port, host))
        results[host]["{}/tcp".format(port)] = "closed"

# half-open/stealth tcp scan
def tcp_stealth(host, port):
    global results

    print("tcp_stealth scan - {}:{}".format(host, port))

    ip = IP()
    ip.dst = host

    tcp = TCP()
    tcp.dport = port
    tcp.sport = RandShort()
    tcp.flags = "S"

    tcp_connect = sr1((ip/tcp), timeout=10, verbose=0)
    if type(tcp_connect) == type(None):
        # got no response, port filtered
        print("Port {} on {} is filtered".format(port, host))
        results[host]["{}/tcp".format(port)] = "filtered"

    elif tcp_connect.haslayer(TCP) and tcp_connect.getlayer(TCP).flags == 0x12:
        # got SYN/ACK, send RST
        tcp.flags = "R"

        send_rst = sr((ip/tcp), timeout=10, verbose=0)
        print("Port {} on {} is open".format(port, host))
        results[host]["{}/tcp".format(port)] = "open"
        
    elif tcp_connect.haslayer(TCP) and tcp_connect.getlayer(TCP).flags == 0x14:
        # got RST, port closed
        print("Port {} on {} is closed".format(port, host))
        results[host]["{}/tcp".format(port)] = "closed"

# ICMP echo request
def icmp_echo_request(host):
    global results

    print("icmp_echo_request - {}".format(host))

    ip = IP()
    ip.dst = host

    icmp = ICMP()

    icmp_echo_request = sr1((ip/icmp), timeout=10, verbose=0)
    if type(icmp_echo_request) == type(None):
        # got not response, host is down
        print("{} did not respond to echo request".format(host))
        results[host]["icmp"] = "No response"

    elif icmp_echo_request.haslayer(ICMP) and icmp_echo_request.getlayer(ICMP).type == 0:
        # host gave a reply
        print("{} is up".format(host))
        results[host]["icmp"] = "Host is up"

    elif icmp_echo_request.haslayer(ICMP) and icmp_echo_request.getlayer(ICMP).type == 3 and icmp_echo_request.getlayer(ICMP).code in [1,2,3,9,10,13]:
        # icmp error
        print("{} is not reachable".format(host)) 
        results[host]["icmp"] = "Not reachable"

# basic UDP scan
def udp_scan(host, port):
    global results

    print("udp_scan - {}:{}".format(host, port))

    ip = IP()
    ip.dst = host

    udp = UDP()
    udp.dport = port
    
    udp_response = sr1((ip/udp), timeout=10, verbose=0)
    if type(udp_response) == type(None):
        # no response, might be open
        print("Port {} on {} is open or filtered".format(port, host))
        results[host]["{}/udp".format(port)] = "Open or filtered"

    elif udp_response.haslayer(ICMP) and udp_response.getlayer(ICMP).type == 3 and udp_response.getlayer(ICMP).code in [1,2,3,9,10,13]:
        # icmp error
        print("Port {} on {} is closed".format(port, host))
        results[host]["{}/udp".format(port)] = "Closed"
        
# UDP traceroute
def traceroute(host):
    global results

    print("traceroute - {}".format(host))

    ip = IP()
    ip.dst = host

    udp = UDP()
    udp.dport = RandShort()

    timeout_count = 0
    results[host]["traceroute"] = []

    for ttl in range(1, 31):
        # if the last three packets have timed out, let's stop
        if timeout_count >= 3:
            break

        ip.ttl = ttl

        traceroute_packet = sr1((ip/udp), timeout=10, verbose=0)
        if type(traceroute_packet) == type(None):
            # response timed out, probably as far as we can go
            print("Timed out")
            results[host]["traceroute"].append("Timed out")

            timeout_count += 1

        elif traceroute_packet.haslayer(ICMP) and traceroute_packet.getlayer(ICMP).type == 3:
            # got to end of route
            print(traceroute_packet.getlayer(IP).src)
            results[host]["traceroute"].append(traceroute_packet.getlayer(IP).src)

            break

        else:
            # ttl expired, send another packet with ttl+=1
            print("{}\t{}".format(ttl,traceroute_packet.getlayer(IP).src))
            results[host]["traceroute"].append(traceroute_packet.getlayer(IP).src)

# create simple HTML file with Bootstrap styling to show results
def output_html(filename):
    global results

    try:
        with open(filename, 'w') as f:
            # set up document header
            f.write('<!doctype html>\n<html lang="en" style="height: 100%">')
            f.write('<head>\n<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"><link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" integrity="sha384-WskhaSGFgHYWDcbwN70/dfYBj47jz9qbsMId/iRN3ewGhXQFZCSftd1LZCfmhktB" crossorigin="anonymous">\n<title>Port Scanner Results</title>\n</head>')
            f.write('<body style="height: 100%;display: flex; align-items:center; padding-top: 40px; padding-bottom: 40px; background-color: #f5f5f5;">')
            f.write('<div style="width: 100%; max-width: 500px; padding: 15px; margin: auto;">')
            f.write('<div class="row"><h1 class="col border-bottom">Results</h1></div>')
            # for each host
            for host,result in results.items():
                f.write('<div class="row mb-3">')
                f.write('<div class="col">')
                f.write('<h2>' + str(host) + '</h2>')
                # for each port that was scanned on host
                for port,status in result.items():
                    f.write('<div class="row">')
                    f.write('<div class="col">' + str(port) + '</div>')
                    f.write('<div class="col">' + str(status) + '</div>')
                    f.write('</div>')
                f.write('</div>')
                f.write('</div>')
            f.write('</div>')
            f.write('</body>')
            f.write('</html>')
    except OSError as e:
        print(e, file=sys.stderr)

def main():
    global results

    # grab command line arguments
    parser = argparse.ArgumentParser()
    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument('--host', help="The host you want to scan. Range (192.168.0.1-192.168.0.255), subnet mask (192.168.0.0/24), or comma separated (192.168.0.5,192.168.0.10) allowed", type=str, action="store")
    host_group.add_argument('-a', help="Text file with 1 host per line", type=str, action="store")

    port_group = parser.add_mutually_exclusive_group(required=True)
    port_group.add_argument('-p', '--port', help="The port you want to scan", type=str, action="store")
    port_group.add_argument('-I', '--icmp', help="Perform ICMP echo request", action="store_true")
    port_group.add_argument('-T', '--traceroute', help="Perform UDP traceroute", action="store_true")

    parser.add_argument('--type', help="The scan type you want to perform (Default: tcp_connect)", type=str, choices=['tcp_connect', 'tcp_stealth', 'udp'], action="store", default="tcp_connect")
    parser.add_argument('--html', help="Store results to HTML file", type=str, action="store")
    args = parser.parse_args()

    scan_type = args.type

    hosts = []
    ports = []

    # parse hosts from command line
    try:
        if args.a:
            with open(args.a, 'r') as f:
                hosts = f.readlines()
            hosts = [host.strip() for host in hosts]
        elif args.host:
            if '-' in args.host:
                lower_bound, upper_bound = args.host.split('-', 2)
                ip_range = IPRange(lower_bound, upper_bound)
                hosts = [str(host) for host in ip_range]
            elif '/' in args.host:
                ip_range = IPNetwork(args.host)
                hosts = [str(host) for host in ip_range]
            elif ',' in args.host:
                hosts = [str(host) for host in args.host.split(',')]
            else:
                hosts = [args.host]
    except OSError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    except (ValueError, AddrFormatError) as e:
        print("Improper host format", file=sys.stderr)
        print("Hosts must match one of following:\n\trange: 192.168.0.1-192.168.0.255\n\tsubnet mask: 192.168.0.0/24\n\tcomma separated: 192.168.0.5,192.168.0.10", file=sys.stderr)
        sys.exit(1)

    # parse ports from command line
    if args.port:
        try:
            if '-' in args.port:
                lower_bound, upper_bound = [int(x) for x in args.port.split('-', 2)]
                for i in range(lower_bound, upper_bound+1):
                    ports.append(i)
            elif ',' in args.port:
                ports = [int(x) for x in args.port.split(',')]
            else:
                ports = [int(args.port)]
        except ValueError as e:
            print("Improper port format", file=sys.stderr)
            print("Ports must match one of following:\n\trange: 1-65535\n\tcomma separated: 22,80,443", file=sys.stderr)
            sys.exit(1)
    
    # set up global results dictionary
    results = {host:{} for host in hosts}

    print("Hosts: {}".format(hosts))
    if not args.icmp and not args.traceroute:
        print("Ports: {}".format(ports))

    if args.icmp:
        for host in hosts:
            icmp_echo_request(host)
        sys.exit(0)

    if args.traceroute:
        for host in hosts:
            traceroute(host)
        sys.exit(0)

    if scan_type == "tcp_connect":
        # try tcp connect
        for host in hosts:
            for port in ports:
                tcp_connect(host, port)
    elif scan_type == "tcp_stealth":
        # try tcp stealth
        for host in hosts:
            for port in ports:
                tcp_stealth(host, port)
    elif scan_type == "udp":
        # try udp scan
        for host in hosts:
            for port in ports:
                udp_scan(host, port)
    else:
        print("The scan type '{}' has not yet been implemented.".format(scan_type))
        sys.exit(1)

    # output results
    if args.html:
        output_html(args.html)

if __name__ == "__main__":
    main()
