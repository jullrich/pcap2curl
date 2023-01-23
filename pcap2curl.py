#!/usr/bin/env python

import argparse
import sys

from scapy.all import PcapReader, re, Raw, TCP

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('infile')
arg_parser.add_argument('-p', '--port', type=int, default=80, required=False)
args = arg_parser.parse_args()
print(args.port, args.infile)

infile = args.infile



VALID_METHODS = [
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH"
]  # see https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods


def payload2curl(p):
    lines = re.compile("[\n\r]+").split(p.decode())
    start_line = re.search("^([A-Z]+) ([^ ]+) (HTTP\/[0-9\/]+)", lines[0])
    method = start_line.group(1)
    url = start_line.group(2)
    version = start_line.group(3)  # Never used

    if method not in VALID_METHODS:
        return

    del lines[0]
    headers = []
    for line in lines:
        if ":" in line:
            headers.append("-H '{}'".format(line))
        if "Host:" in line:
            host_header = re.search("^Host: (.*)", line)
            host_name = host_header.group(1)

    proto_host = 'http://{}/'.format(host_name)
    if not url.startswith(proto_host):
        url = "{}{}".format(proto_host, url[1:] if url[0] == "/" else url)
    curl = "curl '{}' \\\n -X {} \\\n ".format(url, method)
    curl += " \\\n ".join(headers)
    return curl


def main():
    with PcapReader(infile) as packets:
        for p in packets:
            if p.haslayer(TCP) and p.haslayer(Raw) and p[TCP].dport == args.port:
                payload = p[Raw].load
                cmd = payload2curl(payload)
                if cmd:
                    print(cmd)
                    print('\n')


if __name__ == "__main__":
    main()
