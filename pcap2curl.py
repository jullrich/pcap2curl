#!/usr/bin/env python

import sys
from scapy.all import *


if len(sys.argv) != 2:
  print "I need an input file. Usage ./pcap2curl.py inputfilename"
  exit()

infile = sys.argv[1]

packets=rdpcap(infile)

def payload2curl(p):
   lines=re.compile("[\n\r]+").split(p)
   startline=re.search('^([A-Z]+) ([^ ]+) (HTTP\/[0-9\/]+)',lines[0])
   curl='curl ';
   method=startline.group(1)
   url=startline.group(2)
   version=startline.group(3)

   del lines[0]
   headers=[]
   for line in lines:
       if ":" in line:
         headers.append("-H '"+line+"'")
       if "Host:" in line:
         hostheader=re.search("^Host: (.*)",line)
         hostname=hostheader.group(1)

   if hostname not in url:
     url='http://'+hostname+'/'+url
   curl=curl+' '+"'"+url+"' \\\n"
   curl=curl+'-X'+method+" \\\n"
   curl=curl+" \\\n".join(headers)
   return curl

for p in packets:
  payload=''
  if p.haslayer(TCP) and p.haslayer(Raw) and  p[TCP].dport == 80:
    payload=p[Raw].load
    print payload2curl(payload)
