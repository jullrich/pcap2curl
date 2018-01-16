from setuptools import setup

setup(
    name='pcap2curl',

    version='0.1',

    description='Extract HTTP requests from pcap and turn them into cURL',

    url='https://github.com/jullrich/pcap2curl',

    author='Johannes Ullrich',

    license='GNU',

    install_requires=['scapy']

)
