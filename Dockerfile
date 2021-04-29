FROM python

WORKDIR /pcap2curl

COPY . .

RUN pip install .
RUN chmod +x pcap2curl.py
RUN echo "export PATH=/pcap2curl:\"$PATH\"" >> ~/.bashrc
