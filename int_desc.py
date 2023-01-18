#!/usr/bin/env python

'''
   This script will add lldp info to interface descriptions


    File name: int_desct.py
    Version: 1.0
    Author: Nicholas Bogdajewicz
    Date created: 12/20/2022
    Date last modified: 12/4/2022
    Python Version: 3.8.2
    requests version: 2.27.0
'''

import snapshot
import get_token
import logging
from logging.handlers import RotatingFileHandler
import json
import requests
import sys
import re
import time
import socket

#Script will find these keywords in sysdescription of lldp neighbours. Change the keywords to find your specfic devices (node is used for leaf spine connections).
palo = "palo"
nxos = "nx-os"
node = "node"

#Logs into fabric and saves token, url and change number
login = get_token.get_token()
token = login[0]
fabric = login[1]
change = login[2]

timer = time.time()

#Logs to file
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s.%(msecs)03d] [%(levelname)s] [%(filename)s] [%(funcName)s():%(lineno)s] %(message)s', handlers=[RotatingFileHandler('logs/int_desc.log', maxBytes=1000000, backupCount=1)])

#logs to console
console = logging.StreamHandler()
console.setLevel(logging.WARNING)
logging.getLogger('').addHandler(console)
logger = logging.getLogger(__name__)


def main():
    global token, timer

    #takes pre-snapshot
    snapshot.snapshot_pre(change, token, fabric)

    c_timer = time.time()
    d_timer = c_timer - timer
    if d_timer >= 600:
        token = get_token.get_token()
        token = token[0]
        timer = time.time()
    if d_timer >= 540:
        token = get_token.refresh_token(fabric, token)
        timer = time.time()

    url = fabric + "/api/node/class/fabricNode.json"

    headers = {
        "Cookie" : f"APIC-Cookie={token}", 
    }

    requests.packages.urllib3.disable_warnings()
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code != 200:
        logger.error("ERROR! Could not retrieve switch IDs.")
        logger.debug(response)
        sys.exit()

    response_json = json.loads(response.text)

    for item in response_json["imdata"]:
        if item["fabricNode"]["attributes"]["fabricSt"] != "active":
            continue
        elif item["fabricNode"]["attributes"]["role"] != "leaf" and item["fabricNode"]["attributes"]["role"] != "spine":
            continue
        else:
            reg = re.findall('(?<=pod-).*$', item["fabricNode"]["attributes"]["dn"])[0]
            podid = str(reg).split("/")[0]
            nodeid = re.findall('(?<=node-).*$', item["fabricNode"]["attributes"]["dn"])[0]
        
        role = item["fabricNode"]["attributes"]["role"]

        c_timer = time.time()
        d_timer = c_timer - timer
        if d_timer >= 600:
            token = get_token.get_token()
            token = token[0]
            timer = time.time()
        if d_timer >= 540:
            token = get_token.refresh_token(fabric, token)
            timer = time.time()

        url = fabric + "/api/node/class/topology/pod-" + podid + "/node-" + nodeid + "/lldpIf.json?rsp-subtree=children&rsp-subtree-class=lldpIf,lldpAdjEp&rsp-subtree-include=required"
        headers = {
            "Cookie" : f"APIC-Cookie={token}", 
        }

        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, headers=headers, verify=False)

        if response.status_code != 200:
            logger.error("ERROR! Could not retrieve LLDP neighbours for node " + nodeid + ".")
            logger.debug(response)
            continue

        response_json = json.loads(response.text)

        for item in response_json["imdata"]:
            interface = item["lldpIf"]["attributes"]["id"]
            sysname = item["lldpIf"]["children"][0]["lldpAdjEp"]["attributes"]["sysName"]
            mgmtip = item["lldpIf"]["children"][0]["lldpAdjEp"]["attributes"]["mgmtIp"]
            sysdesc = item["lldpIf"]["children"][0]["lldpAdjEp"]["attributes"]["sysDesc"]

            if palo in sysdesc.lower() or nxos in sysdesc.lower() or node in sysdesc.lower():
                if mgmtip != "unspecified":
                    try:
                        hostname = socket.gethostbyaddr(mgmtip)[0]
                    except socket.herror:
                        if sysname != "":
                            hostname = sysname
                        else:
                            continue
                elif sysname != "":
                    hostname = sysname
                else:
                    continue

                ether = interface.replace("/", "_")

                c_timer = time.time()
                d_timer = c_timer - timer
                if d_timer >= 600:
                    token = get_token.get_token()
                    token = token[0]
                    timer = time.time()
                if d_timer >= 540:
                    token = get_token.refresh_token(fabric, token)
                    timer = time.time()

                if role == "leaf":
                    infrapath = "infraHPathS"
                    hpath = "hpaths-"
                    infrarpath = "infraRsHPathAtt"
                    rpath = "rsHPathAtt"
                else:
                    infrapath = "infraSHPathS"
                    hpath = "shpaths-"
                    infrarpath = "infraRsSHPathAtt"
                    rpath = "rsSHPathAtt"

                url = fabric + "/api/node/mo/uni/infra/" + hpath + nodeid + "_" + ether + ".json"
                headers = {
                    "Cookie" : f"APIC-Cookie={token}", 
                }

                hostname = "* VRT * " + hostname

                payload = {infrapath:{"attributes":{"rn":hpath + nodeid + "_" + ether ,"dn":"uni/infra/" + hpath + nodeid + "_" + ether ,"descr": hostname ,"name": nodeid + "_" + ether},"children":[{infrarpath:{"attributes":{"dn":"uni/infra/" + hpath + nodeid + "_" + ether + "/" + rpath + "-[topology/pod-" + podid + "/paths-" + nodeid + "/pathep-[" + interface + "]]","tDn":"topology/pod-" + podid + "/paths-" + nodeid + "/pathep-[" + interface + "]"}}}]}}

                data = json.dumps(payload)
                requests.packages.urllib3.disable_warnings()
                response = requests.post(url, data=data, headers=headers, verify=False)

                if response.status_code != 200:
                    logger.error("ERROR! Could not add interface description for node " + nodeid + " interface " + interface + ".")
                    logger.debug(response)
                    continue
                else:
                    print("Successfully added description " + hostname + " to node " + nodeid + " interface " + interface)
                    response_json = json.loads(response.text)
                    logger.debug(response_json)

    snapshot.snapshot_post(change, token, fabric)
    sys.exit()

            
if __name__ == '__main__':
    main()
