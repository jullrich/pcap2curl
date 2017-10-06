# pcap2curl
Read a packet capture, extract HTTP requests and turn them into cURL commands for replay.

See https://isc.sans.edu/diary.html?storyid=22900

This is a simple (too simple?) Python script that will read a pcap, find HTTP requests and turn them into cURL commands for replay.

Little effort is made to verify that the requests are valid. This is intended to extract well formed requests that were created by your browser. Not necessarily intedned for malicious requests. It also does not reassemble TCP streams (yet). Browsers typically send requests as one packet, but large requests will fail.

DISCLAIMER: I am not a Python coder. I do not like Python. I have to use it once in a while because I love [Scrapy](https://scrapy.org/).

CREDIT: Stackoverflow

