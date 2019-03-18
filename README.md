# RGW info
Script to connect to residential gateways and collect useful information or reboot them.

## Supported gateways
Built and tested against the following Vodafone New Zealand gateways:
- UltraHub and UltraHub Plus
- Huawei HG659
- Vodafone station
- B315 wireless

## Requirements
Although built and tested on Ubuntu, the one test on Windows worked fine.
- python3
- requests
- srp >= 1.0.12
- netifaces >= 0.10.0

## Installation
For example, on Ubuntu 18.04 (install srp via pip because the packaged version is too old):
```bash
sudo apt install python3 python3-requests python3-netifaces python3-pip
sudo -H pip3 install srp
git clone https://github.com/gaddman/rgw-info
```
Or on Windows, assuming you've already got Python3 installed:
```
pip3 install requests srp netifaces
git clone https://github.com/gaddman/rgw-info
```

## Usage
```bash
$ getRGWinfo.py
Huawei HG659 detected
SerialNumber:   S3G7N161xxxxxxxx
Firmware:       V100R001C206B020
DownRate(Mbps): 21.626
UpRate(Mbps):   0.901
```
