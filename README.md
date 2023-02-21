# pcap2curl
Read a packet capture, extract HTTP requests and turn them into cURL commands for replay.

See https://isc.sans.edu/diary.html?storyid=22900

This is a simple (too simple?) Python script that will read a pcap, find HTTP requests and turn them into cURL commands for replay.

Little effort is made to verify that the requests are valid. This is intended to extract well formed requests that were created by your browser. Not necessarily intended for malicious requests. It also does not reassemble TCP streams (yet). Browsers typically send requests as one packet, but large requests will fail.

DISCLAIMER: I am not a Python coder. I do not like Python. I have to use it once in a while because I love [Scapy](http://www.secdev.org/projects/scapy/).

## Usage with docker
```sh
docker build . -t pcap2curl
docker run -v /host/path/to/capture.pcap:/capture.pcap pcap2curl bash
pcap2curl.py /capture.pcap
```

CREDIT: Stackoverflow
