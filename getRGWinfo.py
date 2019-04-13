#!/usr/bin/env python3
# Get RGW info from supported devices
# There's very litle error handling in here, it either works or fails horribly
# Chris Gadd
# https://github.com/gaddman/rgw-info
# 2017-08-13

# Requirements
# srp v1.0.12 or newer
# netifaces v0.10.0 or newer

import argparse
import binascii
import base64
import hashlib
import json
import netifaces
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from ipaddress import ip_address

# Non default libraries may not be installed
missingimports = False
try:
    import requests
    import srp
except ImportError:
    print("One or more required python modules not installed: 'requests' & 'srp'")
    sys.exit()

parser = argparse.ArgumentParser()
parser.add_argument("-u", help="Username to log into gateway")
parser.add_argument("-p", help="Password to log into gateway")
parser.add_argument("-r", help="Reboot gateway", action="store_true")
args = parser.parse_args()
user = args.u
passwd = args.p
reboot = args.r


def connectUltraHub(version, baseURL, user, passwd, reboot):
    # Vodafone UltraHub & UltraHub+ (Technicolor H 500-t)
    # UH doesn't have an API (AFAIK) or support UPNP (by default)
    # SRP auth from https://github.com/mkj/tgiistat

    def login(baseurl, username, password):
        sess = requests.Session()
        # Load auth page to get CSRF token
        token = sess.get(baseurl + "login.lp?action=getcsrf").text

        # Calculate SRP variables
        srp_user = srp.User(user, passwd, hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        if hasattr(srp._mod, "BN_hex2bn"):
            # _mod == _ctsrp, openssl
            srp._mod.BN_hex2bn(
                srp_user.k,
                b"05b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300",
            )
        else:
            # _mod == _pysrp, pure python
            srp_user.k = int(
                "05b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300", 16
            )
        I, A = srp_user.start_authentication()
        A = binascii.hexlify(A)
        req_data = {"I": I, "A": A, "CSRFtoken": token}

        # First stage auth request
        authURL = baseurl + "authenticate"
        response = sess.post(authURL, data=req_data)
        # Parse response and process challenge
        j = response.json()
        s, B = j["s"], j["B"]
        s = binascii.unhexlify(s)
        B = binascii.unhexlify(B)
        M = srp_user.process_challenge(s, B)
        M = binascii.hexlify(M)
        req_data = {"M": M, "CSRFtoken": token}

        # Second stage auth request
        response = sess.post(authURL, data=req_data)
        j = response.json()
        if "error" in j:
            print("Authentication error. Wrong password? (%s)" % j["error"])
            sys.exit()

        return sess

    session = login(baseURL, user, passwd)

    if reboot:
        # get new CSRF token
        if version == "17.1":
            restartURL = baseURL + "modals/restart.lp"
        else:
            restartURL = baseURL + "modals/status-support/restart.lp"
        response = session.get(restartURL).text
        token = re.search(
            r'CSRFtoken",.\s+value : "([^"]+)', response, re.DOTALL
        ).group(1)
        reqdata = {"system_reboot": "GUI", "CSRFtoken": token}
        response = session.post(restartURL, data=reqdata).text
        print("Rebooting...")
        return

    if version == "17.1":
        response = session.get(baseURL + "modals/status.lp").text
    else:
        response = session.get(baseURL + "modals/status-support/status.lp").text
    serial = re.search(r"status-lbl-gwser.>([^<]+)", response).group(1)
    firmware = re.search(r"status-lbl-gwver.>([^<]+)", response).group(1)
    print("SerialNumber:\t" + serial)
    print("Firmware\t" + firmware)
    return


def connectHG659(baseURL, user, passwd, reboot):
    # Huawei HG659
    # HG659 doesn't require auth for the info we need, only for the reboot
    # Reboot code from https://www.matthuisman.nz/2017/07/hg659-python-reboot-code.html
    def parseJSON(content):
        # Extract data from the JSON reponse and return as dictionary
        # strip the surrounding crud (starts with "while(1); /*" and ends with "*/")
        content = content[12:-2]
        return json.loads(content)

    def login_data(username, password, csrf_token, csrf_param):
        # Return JSON string with login details including hashed password
        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        password_hash = base64.b64encode(password_hash.encode()).decode()
        # Combine with username and CSRF bits and hash
        password_hash = username + password_hash + csrf_param + csrf_token
        password_hash = hashlib.sha256(password_hash.encode()).hexdigest()
        return {
            "csrf": {"csrf_param": csrf_param, "csrf_token": csrf_token},
            "data": {"UserName": username, "Password": password_hash},
        }

    def login(baseurl, username, password):
        # Login and update headers with cookie and token
        s = requests.Session()
        response = s.get(baseurl + "html/index.html").text
        # Get CSRF token and parameter
        token = re.search(r'csrf_token" content="([^"]+)', response).group(1)
        param = re.search(r'csrf_param" content="([^"]+)', response).group(1)
        # Get login data with hash
        data = login_data(username, password, token, param)
        # Login and update CSRF bits
        response = s.post(
            baseurl + "api/system/user_login",
            data=json.dumps(data, separators=(",", ":")),
        )
        data = parseJSON(response.text)
        token = data["csrf_token"]
        param = data["csrf_param"]
        return s, {"csrf": {"csrf_param": param, "csrf_token": token}}

    session, data = login(baseURL, user, passwd)

    if reboot:
        response = session.post(
            baseURL + "api/service/reboot.cgi",
            data=json.dumps(data, separators=(",", ":")),
        )
        print("Rebooting...")
        return

    response = session.get(baseURL + "api/system/deviceinfo", timeout=5).text
    # output example:
    # while(1); /*{"DeviceName":"HG659","SerialNumber":"S3G7N16112001088","ManufacturerOUI":"00E0FC","UpTime":1053638,"SoftwareVersion":"V100R001C206B026","HardwareVersion":"VER.B"}*/
    data = parseJSON(response)
    print("SerialNumber:\t" + data["SerialNumber"])
    print("Firmware:\t" + data["SoftwareVersion"])

    response = session.get(baseURL + "api/system/diagnose_internet", timeout=5).text
    # output example:
    # while(1); /*{"WANAccessType":"VDSL","DownMaxBitRate":50.407,"ConnectionStatus":"Connected","X_IPv6Address":"2407:7000:f008:0:deee:6ff:fe38:1931/128","LinkStatus":"Up","ModulationType":"VDSL","ErrReason":"Success","X_IPv6Enable":true,"X_IPv6DNSServers":"2407:7000:2100:5300::1,2407:7000:ff00:5300::1","X_IPv6PrefixList":"2407:7000:884a:1300::/56","HasInternetWan":true,"StatusCode":"Connected","X_IPv4Enable":true,"DNSServers":"203.109.191.1,203.118.191.1","ExternalIPAddress":"27.252.253.189","X_IPv6PrefixLength":128,"MACAddress":"dc:ee:06:38:19:31","X_IPv6ConnectionStatus":"Connected","Uptime":1144410,"X_IPv6AddressingType":"DHCP","UpMaxBitRate":8.677,"X_IPv6DefaultGateway":"fe80::220b:c7ff:fe2a:e66b","Status":"Connected","DefaultGateway":"27.252.255.254"}*/
    data = parseJSON(response)
    print("DownRate(Mbps):\t" + str(data["DownMaxBitRate"]))
    print("UpRate(Mbps):\t" + str(data["UpMaxBitRate"]))
    return


def connectStation(baseURL, reboot):
    # Vodafone Station (Vox1.5 / Sercomm SHG1500)
    # Need to get cookies first, then SOAP to grab data
    response = requests.get(baseURL + "main.cgi?page=settings.html")
    # Parse for cookies
    cookie = re.search(
        r"wbm_cookie_session_id=([A-F0-9]+)", response.headers["Set-Cookie"]
    ).group(1)
    dmcookie = re.search(r"dm_cookie='([0-9]+)'", response.text).group(1)
    # Craft SOAP request
    soapdata = (
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        "<soapenv:Header><DMCookie>" + dmcookie + "</DMCookie></soapenv:Header>"
        '<soapenv:Body><cwmp:GetParameterValues xmlns=""><ParameterNames>'
        "<string>InternetGatewayDevice.DeviceInfo.SerialNumber</string>"
        "<string>InternetGatewayDevice.DeviceInfo.SoftwareVersion</string>"
        "<string>InternetGatewayDevice.WANDevice.7.WANConnectionDevice.13.WANPPPConnection.13.ExternalIPAddress</string>"
        # "<string>InternetGatewayDevice.WANDevice.7.WANConnectionDevice.13.WANPPPConnection.13.DefaultGateway</string>"
        "<string>InternetGatewayDevice.WANDevice.7.WANDSLInterfaceConfig.DownstreamCurrRate</string>"
        "<string>InternetGatewayDevice.WANDevice.7.WANDSLInterfaceConfig.UpstreamCurrRate</string>"
        "</ParameterNames></cwmp:GetParameterValues></soapenv:Body></soapenv:Envelope>"
    )
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "SOAPAction": "cwmp:GetParameterValues",
        "Cookie": "wbm_cookie_session_id=" + cookie,
    }
    # Post SOAP request and parse the XML response
    response = requests.post(baseURL + "data_model.cgi", data=soapdata, headers=headers)
    root = ET.fromstring(response.text)
    for parameter in root.iter("ParameterValueStruct"):
        name = parameter.find("Name").text
        value = parameter.find("Value").text
        print(name.rpartition(".")[2] + ": " + value)
    return


def connectB315(baseURL, user, passwd, reboot):
    # Huawei B315
    # Google Huawei B315 API for examples, some of this taken from here:
    # https://blog.hqcodeshop.fi/archives/259-Huawei-E5186-AJAX-API.html
    # Requires authentication in order to return the IMSI

    def parseXML(content):
        # Pretty up the XML reponse
        # remove the header line
        content = content.split("\n", 2)[2]
        # remove the closing tags and tag markers
        content = re.sub("</\w+>", "", content).replace("<", "").replace(">", ": ")
        return content

    def login_data(username, password, csrf_token):
        # Hash credentials for logging in
        def encrypt(text):
            hash = hashlib.sha256(text.encode()).hexdigest()
            return base64.b64encode(hash.encode()).decode()

        password_hash = encrypt(username + encrypt(password) + csrf_token)
        return (
            '<?xml version="1.0" encoding="UTF-8"?><request>\r\n<Username>'
            + username
            + "</Username>\r\n<password_type>4</password_type>\r\n<Password>"
            + password_hash
            + "</Password>\r\n</request>"
        )

    def login(baseurl, username, password):
        # Login and update headers with cookie and token
        s = requests.Session()
        response = s.get(baseurl + "html/index.html")
        # Get CSRF token and add to headers
        token = re.search(r'csrf_token" content="([^"]+)', response.text).group(1)
        s.headers.update({"__RequestVerificationToken": token})

        data = login_data(username, password, token)
        response = s.post(baseurl + "api/user/login", data=data)
        if "error" in response.text:
            print("Failed to login")
        else:
            # Get new request token and update headers
            token = response.headers["__RequestVerificationTokenone"]
            s.headers.update({"__RequestVerificationToken": token})

        return s

    session = login(baseURL, user, passwd)

    if reboot:
        data = (
            '<?xml version: "1.0" encoding="UTF-8"?>'
            + "<request><Control>1</Control></request>"
        )
        response = session.post(baseURL + "api/device/control", data=data)
        if "error" in response.text:
            print("Error attempting reboot")
        else:
            print("Rebooting...")
        return

    # Device info
    response = session.get(baseURL + "api/device/information", timeout=5).text
    # devicename, serialnumber, imei, imsi, iccid, msisdn, hardwareversion, softwareversion, webuiversion, macaddress1, macaddress2, productfamily, classify, supportmode, workmode
    response = parseXML(response)
    # only keep some details
    for line in response.splitlines():
        if re.search("(Serial|Imsi|SoftwareVersion|IPAddr)", line):
            print(line)

    # IP addresses and DNS
    response = session.get(baseURL + "api/monitoring/status", timeout=5).text
    # connectionstatus, wificonnectionstatus, signalstrength, signalicon, currentnetworktype, currentservicedomain, roamingstatus, batterystatus, batterylevel, batterypercent, simlockstatus, wanipaddress, wanipv6address, primarydns, secondarydns, primaryipv6dns, secondaryipv6dns, currentwifiuser, totalwifiuser, currenttotalwifiuser, servicestatus, simstatus, wifistatus, currentnetworktypeex, maxsignal, wifiindooronly, wififrequence, classify, flymode, cellroam, voice_busy
    response = parseXML(response)
    for line in response.splitlines():
        if re.search("(IPAddr|aryDns)", line):
            print(line)

    # Mobile network signal info
    response = session.get(baseURL + "api/device/signal", timeout=5).text
    # pci, sc, cell_id, rsrq, rsrp, rssi, sinr, rscp, ecio, mode, wdlfreq, lteulfreq, band
    response = parseXML(response)
    print(response)

    # APN info
    response = session.get(baseURL + "api/dialup/profiles", timeout=5).text
    # CurrentProfile, Profiles, Profile, Index, IsValid, Name, ApnIsStatic, ApnName, DialupNum, Username, Password, AuthMode, IpIsStatic, IpAddress, Ipv6Address, DnsIsStatic, PrimaryDns, SecondaryDns, PrimaryIpv6Dns, SecondaryIpv6Dns, ReadOnly, iptype
    response = parseXML(response)
    apns = {}
    for line in response.splitlines():
        if line.startswith("CurrentProfile"):
            current = int(line.split()[1])
        elif line.startswith("Index"):
            index = int(line.split()[1])
        elif line.startswith("Name"):
            name = line.split()[1]
        elif line.startswith("ApnName"):
            apn = line.split(":")[1].strip()
            apns[index] = [name, apn]
    print("APN list")
    for index, apn in apns.items():
        active = "* Active *" if index == current else ""
        print("{}: {:25s} {:30s} {}".format(index, apn[0], "(" + apn[1] + ")", active))

    return


# Determine gateway IP and check if proxy
gateways = netifaces.gateways()
GWIP = gateways["default"][netifaces.AF_INET][0]
try:
    proxy = os.environ["http_proxy"]
except:
    proxy = ""

# Exit if not likely behind a RGW
if not ip_address(GWIP).is_private:
    # Has a public or CGNAT IP
    print("No RGW connected, default gateway is " + GWIP)
    sys.exit()
elif proxy:
    proxyIP = re.search(r"([0-9a-z\.:]+)\/?$", proxy).group(1)  # strip user/pass
    print("Connected via proxy ({}), default gateway is {}".format(proxyIP, GWIP))
    sys.exit()

# Detect RGW model
baseURL = "http://" + GWIP + "/"
try:
    response = requests.get(baseURL, timeout=5)
except:
    print("Unable to connect to default gateway (" + baseURL + ")")
    sys.exit()

if response.status_code != requests.codes.ok:
    print("Failed with HTTP error {}".format(response.status_code))
elif "HG659" in response.text:
    print("Huawei HG659 detected")
    if not user:
        user = "vodafone"
    if not passwd:
        passwd = "vodafone"
    connectHG659(baseURL, user, passwd, reboot)
elif "VFH-500" in response.text:
    print("Vodafone Ultra Hub detected")
    if not user:
        user = "vodafone"
    if not passwd:
        # unique passwords on the UH
        print("No credentials provided, unable to proceed")
    else:
        # Different firmware versions (or models?) have different URLs
        if "favicon-new.png" in response.text:
            # Seen on UltraHubPlus with 17.4.0182 firmware
            version = "17.4"
        else:
            # Seen on UltraHub with 17.1.7988 firmware
            version = "17.1"
        connectUltraHub(version, baseURL, user, passwd, reboot)
elif "api/device/basic_information" in response.text:
    print("Huawei B315 detected")
    if not user:
        user = "admin"
    if not passwd:
        passwd = "admin"
    connectB315(baseURL, user, passwd, reboot)
elif "networkmap_be.js" in response.text:
    print("Vodafone Station detected")
    connectStation(baseURL, reboot)
else:
    print("RGW not recognised")
