#!/usr/bin/env python

'''
   This script will modify a port (add, remove ect.)


    File name: modify_ports.py
    Version: 1.0
    Author: Nicholas Bogdajewicz
    Date created: 7/6/2022
    Date last modified: 7/11/2022
'''

import snapshot
import get_token
import logging
from logging.handlers import RotatingFileHandler
import json
import requests
import sys
import re

#Logs into fabric and saves token, url and change number
login = get_token.get_token()
token = login[0]
fabric = login[1]
change = login[2]

#Logs to file
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s.%(msecs)03d] [%(levelname)s] [%(filename)s] [%(funcName)s():%(lineno)s] %(message)s', handlers=[RotatingFileHandler('logs/modify_ports.log', maxBytes=1000000, backupCount=1)])

#logs to console
console = logging.StreamHandler()
console.setLevel(logging.WARNING)
logging.getLogger('').addHandler(console)
logger = logging.getLogger(__name__)


#configures interface profile block
def access_policy(details):
    node = details["node"]
    interface = details["interface"]

    #grabs even and odd nodes
    if int(node) % 2 != 0:
        details["odd"] = str(node)
        odd = details["odd"]
        details["even"] = str(int(node) + 1)
        even = details["even"]
    if int(node) % 2 == 0:
        details["odd"] = str(int(node) - 1)
        odd = details["odd"]
        details["even"] = node
        even = details["even"]

    for inter in interface:
        port = inter.replace('eth1/', '')
        details["physical"] = inter
        if len(port) == 1:
            port = "0" + port

        #creates the policy group name
        if details["type"] == "access":
            if details["speed"] == "100m":
                details["policy_group"] = "AccessPort_100Mbps_Auto"
                policy_group = details["policy_group"]
            elif details["speed"] == "1g":
                details["policy_group"] = "AccessPort_1Gbps_Auto"
                policy_group = details["policy_group"]
            elif details["speed"] == "10g":
                details["policy_group"] = "AccessPort_10Gbps_Auto"
                policy_group = details["policy_group"]
            elif details["speed"] == "25g":
                details["policy_group"] = "AccessPort_25Gbps_Auto"
                policy_group = details["policy_group"]
            else:
                print("Unable to detect policy group.")
                continue
        else:
            if details["speed"] == "1g" and details["type"] == "vpc-lacp":
                details["policy_group"] = "Port" + port + "_Intf_PolicyGrp-1Gbps-VPC"
                policy_group = details["policy_group"]
            elif details["speed"] == "10g" and details["type"] == "vpc-lacp":
                details["policy_group"] = "Port" + port + "_Intf_PolicyGrp-VPC"
                policy_group = details["policy_group"]
            elif details["speed"] == "10g" and details["type"] == "vpc-macpinning":
                details["policy_group"] = "Port" + port + "_Intf_PolicyGrp_MacPinning-10Gbps-VPC"
                policy_group = details["policy_group"]
            elif details["speed"] == "25g" and details["type"] == "vpc-lacp":
                details["policy_group"] = "Port" + port + "_Intf_PolicyGrp_25Gbps-VPC"
                policy_group = details["policy_group"]
            elif details["speed"] == "25g" and details["type"] == "vpc-macpinning":
                details["policy_group"] = "Port" + port + "_Intf_PolicyGrp_MacPinning-VPC"
                policy_group = details["policy_group"]
            elif details["speed"] == "40g" and details["type"] == "vpc-lacp":
                details["policy_group"] = "Port" + port + "_Intf_PolicyGrp_40Gbps-VPC"
                policy_group = details["policy_group"]
            else:
                print("Unable to detect policy group.")
                continue

        ##checks if interface selector exists in odd profile
        url = fabric + "/api/node/mo/uni/infra/accportprof-LEAF" + odd + "_IntfProfile/hports-Port-" + port + "-typ-range.json"
        headers = {
            "Cookie" : f"APIC-Cookie={token}", 
        }

        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, headers=headers, verify=False)

        #checks if successful response
        if response.status_code != 200:
            logger.error("ERROR! could not verify if port " + inter + " is in LEAF" + odd + "_IntProfile.")
            logger.debug(response)
            continue

        #logs if it exists
        response_json = json.loads(response.text)
        logger.debug(response_json)
        if details["type"] == "access" and int(node) % 2 != 0 and response_json["imdata"] != []:
            print("\nInterface selector Port-" + port + " already exists in LEAF" + odd + "_IntfProfile")
            config_port(details)
            continue
        elif details["type"] != "access" and response_json["imdata"] != []:
            print("\nInterface selector Port-" + port + " already exists in unexpected LEAF" + odd + "_IntfProfile")
            continue
            
        ##checks if interface seclector exists in even profile
        url = fabric + "/api/node/mo/uni/infra/accportprof-LEAF" + even + "_IntfProfile/hports-Port-" + port + "-typ-range.json"
        headers = {
            "Cookie" : f"APIC-Cookie={token}", 
        }

        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, headers=headers, verify=False)

        #checks if successful response
        if response.status_code != 200:
            logger.error("ERROR! could not verify if port " + inter + " is in LEAF" + even + "_IntProfile.")
            logger.debug(response)
            continue

        #logs if it exists
        response_json = json.loads(response.text)
        logger.debug(response_json)
        if details["type"] == "access" and int(node) % 2 == 0 and response_json["imdata"] != []:
            print("\nInterface selector Port-" + port + " already exists in LEAF" + even + "_IntfProfile")
            config_port(details)
            continue
        elif details["type"] != "access" and response_json["imdata"] != []:
            print("\nInterface selector Port-" + port + " already exists in unexpected LEAF" + even + "_IntfProfile")
            continue

        ##checks if interface seclector exists in vpc profile
        url = fabric + "/api/node/mo/uni/infra/accportprof-LEAF" + odd + "_LEAF" + even + "_IntfProfile/hports-Port-" + port + "-typ-range.json"
        headers = {
            "Cookie" : f"APIC-Cookie={token}", 
        }

        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, headers=headers, verify=False)

        #checks if successful response
        if response.status_code != 200:
            logger.error("ERROR! could not verify if port " + inter + " is in LEAF" + odd + "_LEAF" + even + "_IntProfile.")
            logger.debug(response)
            continue

        #logs if it exists
        response_json = json.loads(response.text)
        logger.debug(response_json)
        if details["type"] == "access" and int(node) % 2 == 0 and response_json["imdata"] != []:
            print("\nInterface selector Port-" + port + " already exists in unexpected LEAF" + odd + "_LEAF" + even + "_IntfProfile")
            continue
        elif details["type"] == "access" and int(node) % 2 != 0 and response_json["imdata"] != []:
            print("\nInterface selector Port-" + port + " already exists in unexpected LEAF" + odd + "_LEAF" + even + "_IntfProfile")
            continue
        elif details["type"] != "access" and response_json["imdata"] != []:
            print("\nInterface selector Port-" + port + " already exists in LEAF" + odd + "_LEAF" + even + "_IntfProfile")
            config_port(details)
            continue

        #creates interface selectors
        if details["type"] != "access":
            node1 = odd + "_LEAF" + even
            bundle = "accbundle-"
        else:
            node1 = details["node"]
            bundle = "accportgrp-"

        while True:
            ans = input("\nAre you sure you want to add Port-" + port + " with policy group " + policy_group + " to LEAF" + node1 + "_IntfProfile. (y or n): ")
            ans_low = ans.lower()
            if ans_low != "y" and ans_low != "n":
                print("Please enter y or n.")
                continue
            else:
                break
        if ans_low == "n":
            continue

        #request to add interface selector to leaf interface profile
        url = fabric + "/api/node/mo/uni/infra/accportprof-LEAF" + node1 + "_IntfProfile/hports-Port-" + port + "-typ-range.json"

        payload = {
            "infraHPortS": {
                "attributes": {
                    "dn": "uni/infra/accportprof-LEAF" + node1 + "_IntfProfile/hports-Port-" + port + "-typ-range",
                    "name": "Port-" + port,
                    "rn": "hports-Port-" + port + "-typ-range",
                    "status": "created,modified"
                },
                "children": [
                {
                    "infraPortBlk": {
                        "attributes": {
                            "dn": "uni/infra/accportprof-LEAF" + node1 + "_IntfProfile/hports-Port-" + port + "-typ-range/portblk-block2",
                            "fromPort": port,
                            "toPort": port,
                            "name": "block2",
                            "rn": "portblk-block2",
                            "status": "created,modified"
                        },
                        "children": []
                    }
                },
                {
                    "infraRsAccBaseGrp": {
                        "attributes": {
                            "tDn": "uni/infra/funcprof/" + bundle + policy_group,
                            "status": "created,modified"
                        },
                        "children": []
                    }
                }
                ]
            }
        }

        headers = {
            "Cookie" : f"APIC-Cookie={token}", 
        }

        data = json.dumps(payload)
        requests.packages.urllib3.disable_warnings()
        response = requests.post(url, data=data, headers=headers, verify=False)
        logger.info(data)

        #logs if request is unsuccessful
        if response.status_code != 200:
            logger.error("ERROR! could not deploy " + inter + " on LEAF" + odd + "_IntProfile.")
            logger.debug(response)
            return

        #logs if interface selector is created
        response_json = json.loads(response.text)
        logger.warning("Successfully added Port-" + port + " with policy group " + policy_group + " to LEAF" + node + "_IntfProfile")
        logger.info(response_json)
        config_port(details)

#configures access static ports
def config_port(details):

    #formats for vpc or access
    if details["type"] == "access":
        node = details["node"]
        paths = "paths-"
        interface = details["physical"]
    elif details["type"] == "vpc-lacp" or details["type"] == "vpc-macpinning":
        node = details["odd"] + "-" + details["even"]
        paths = "protpaths-"
        interface = details["policy_group"]


    while True:
        ans = input("\nAre you sure you want to add " + interface +  " to leaf" + node + " on " + str(len(details["vlan"])) + " vlans? (y or n): ")
        ans_low = ans.lower()
        if ans_low != "y" and ans_low != "n":
            print("Please enter y or n.")
            continue
        else:
            break
    if ans_low == "n":
        return
    for vlan in details["vlan"]:
        vlan = str(vlan)

        #checks what epg the vlan is deployed on
        url = fabric + "/api/node/class/fvIfConn.json?query-target-filter=and(eq(fvIfConn.encap,\"vlan-" + vlan + "\"))"

        headers = {
            "Cookie" : f"APIC-Cookie={token}", 
        }

        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, headers=headers, verify=False)
        logger.debug(response)

        #checks if successful response
        if response.status_code != 200:
            logger.error("ERROR requesting EPG info for vlan " + vlan)
            continue

        response_json = json.loads(response.text)
        logger.info(response_json)
        logger.debug(response_json)

        #logs if vlan hasnt been deployed yet
        if response_json["imdata"] == []:
            logger.warning("VLAN " + vlan + " is not deployed on any EPG. Please manually add static port.")
            continue

        #Grabs each EPG the vlan is deployed on
        vlan_list = []
        for vlan2 in response_json["imdata"]:
            path1 = re.findall('(?<=\[).+?(?=\])', vlan2["fvIfConn"]["attributes"]["dn"])[0]
            vlan_list.append(path1)
        vlan_list = list(set(vlan_list))

        if len(vlan_list) > 1:
            while True:
                print("\nMultiple EPGs use this vlan:")
                for i in vlan_list:
                    print(i)
                path = input("Please select the EPG you want to use: ")
                if path not in vlan_list:
                    print("Please enter one of the following epgs.")
                    continue
                else:
                    break
        else:
            path = str(vlan_list[0])

        #grabs interface mode
        if details["mode"] == "802.1p":
            mode = "native"
        elif details["mode"]  == "trunk":
            mode = "regular"
        else:
            logger.warning("Unknown interface mode (" + details["mode"] + ").")
            continue

        #checks if vlan is already deployed on the EPG for that interface
        url = fabric + "/api/node/mo/" + path + "/rspathAtt-[topology/pod-1/" + paths + node + "/pathep-[" + interface + "]].json"

        headers = {
            "Cookie" : f"APIC-Cookie={token}", 
        }

        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, headers=headers, verify=False)
        logger.debug(response)  

        #checks if successful response
        if response.status_code != 200:
            logger.error("ERROR checking if vlan " + vlan + " is deployed on node " + node + " interface " + interface)
            continue

        response_json = json.loads(response.text)

        #logs if vlan is already on the interface
        if response_json["imdata"] != []:
            logger.warning("Static port " + interface + " already deployed for vlan " + vlan + " on node " + node + " in EPG " + path)
            continue
        
        #deploys static port on epg
        url = fabric + "/api/node/mo/" + path + "/rspathAtt-[topology/pod-1/" + paths + node + "/pathep-[" + interface + "]].json"

        payload = {
            "fvRsPathAtt": {
                "attributes": {
                    "dn": path + "/rspathAtt-[topology/pod-1/" + paths + node + "/pathep-[" + interface + "]]",
                    "encap": "vlan-" + vlan,
                    "tDn": "topology/pod-1/" + paths + node + "/pathep-[" + interface + "]",
                    "rn": "rspathAtt-[topology/pod-1/" + paths + node + "/pathep-[" + interface + "]]",
                    "status": "created",
                    "mode": mode
                },
                "children": []
            }
        }

        headers = {
            "Cookie" : f"APIC-Cookie={token}", 
        }

        data = json.dumps(payload)
        requests.packages.urllib3.disable_warnings()
        response = requests.post(url, data=data, headers=headers, verify=False)
        logger.info(data)
        logger.info(response)

        #logs unsuccessful request
        if response.status_code != 200:
            logger.error("Could not deploy static port " + interface + " for vlan " + vlan + " on node " + node + " in EPG " + path)
            continue
        #logs successful request
        response_json = json.loads(response.text)
        logger.warning("Static port " + interface + " deployed for vlan " + vlan + " on node " + node + " in EPG " + path)
        logger.debug(response_json)


#Checks if the interface is an access, port channel or VPC
def decom_check(details):
    node = details["node"]
    interface = details["interface"]

    for inter in interface:
        details["interface"] = inter
        #checks if interface is in a port-channel
        url = fabric + "/api/node/mo/topology/pod-1/node-" + node + "/sys/phys-[" + inter + "].json?query-target=children&target-subtree-class=relnFrom"
        headers = {
            "Cookie" : f"APIC-Cookie={token}", 
        }
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, headers=headers, verify=False)

        #If not status code 200, skip request
        if response.status_code != 200:
            logging.error("ERROR! Could not complete request for node " + node + " interface " + inter + ".")
            logging.info(response)
            continue

        response_json = json.loads(response.text)
        logging.info(response_json)
        child_obj = response_json["imdata"]

        #Checks if interface is in port-channel. Call port-channel function if so.
        if any("l1RtMbrIfs" in d for d in child_obj):
            #gets the policy group name
            url = fabric + "/api/node/mo/topology/pod-1/node-" + node + "/sys/phys-[" + inter + "].json?rsp-subtree-include=relations"
            headers = {
                "Cookie" : f"APIC-Cookie={token}", 
            }
            requests.packages.urllib3.disable_warnings()
            response = requests.get(url, headers=headers, verify=False)

            #If not status code 200, skip request
            if response.status_code != 200:
                logging.error("ERROR! Could not complete request for node " + node + " interface " + inter+ ".")
                logging.info(response)
                return

            response_json = json.loads(response.text)
            logging.info(response_json)

            #Gets po id and policy group
            obj = response_json["imdata"]
            if any("pcAggrIf" in d for d in obj):
                for ele in obj:
                    for key, value in ele.items():
                        if key == "pcAggrIf":
                            details["po_pg"] = value["attributes"]["name"]
                            details["po_id"] = value["attributes"]["id"]

            #checks if po is in VPC
            url = fabric + "/api/node/mo/topology/pod-1/node-" + node + "/sys/aggr-[" + details["po_id"] + "].json?query-target=children&target-subtree-class=relnFrom"
            headers = {
                "Cookie" : f"APIC-Cookie={token}", 
            }
            requests.packages.urllib3.disable_warnings()
            response = requests.get(url, headers=headers, verify=False)

            #If not status code 200, skip request
            if response.status_code != 200:
                logging.error("ERROR! Could not complete request for node " + node + " interface " + inter + ".")
                logging.info(response)
                return

            response_json = json.loads(response.text)
            logging.info(response_json)
            child_obj = response_json["imdata"]

            if any("pcRtVpcConf" in d for d in child_obj):
                decom_vpc(details)
                continue
            else:
                decom_po(details)
                continue
        else:
            decom_access(details)
            continue


#Decoms access ports
def decom_access(details):
    node = details["node"]
    interface = details["interface"]

    #gets all EPGs for interface
    url = fabric + "/api/node/mo/topology/pod-1/node-" + node + "/sys/phys-[" + interface + "].json?rsp-subtree-include=full-deployment&target-node=all&target-path=l1EthIfToEPg"
    headers = {
        "Cookie" : f"APIC-Cookie={token}", 
    }
    requests.packages.urllib3.disable_warnings()
    response = requests.get(url, headers=headers, verify=False)

    #If not status code 200, skip request
    if response.status_code != 200:
        logging.error("ERROR! Could not complete request for node " + node + " interface " + interface + ".")
        logging.info(response)
        return

    response_json = json.loads(response.text)
    logging.info(response_json)

    obj = response_json["imdata"][0]["l1PhysIf"]

    #checks if any epgs exist
    if any("children" in d for d in obj):
        child_obj = response_json["imdata"][0]["l1PhysIf"]["children"][0]["pconsCtrlrDeployCtx"]["children"]
    else:
        print("\nNo EPGs found for " + interface + " on node " + node)
        return

    #loops through epgs and appends to list
    list1 = []
    for dic in child_obj:
        for val in dic.values():
            if not isinstance(val, dict):
                print(val)
        else:
            for val2 in val.values():
                list1.append(val2["ctxDn"])

    #confirms user wants to remove static ports from epgs
    while True:
        ans = input("\nConfirm you want to remove " + interface + " on node " + node + " from " + str(len(list1)) + " EPG(s)? (y or n): ")
        ans_low = ans.lower()
        if ans_low != "y" and ans_low != "n":
            print("Please enter y or n.")
            continue
        else:
            break
    if ans_low == "n":
        return

    #loops through epgs and removes static port
    for epg in list1:

        url = fabric + "/api/node/mo/" + epg + "/rspathAtt-[topology/pod-1/paths-" + node + "/pathep-[" + interface + "]].json"

        headers = {
            "Cookie" : f"APIC-Cookie={token}", 
        }

        payload = {"fvRsPathAtt":{"attributes":{"dn": epg + "/rspathAtt-[topology/pod-1/paths-" + node + "/pathep-[" + interface + "]]","status":"deleted"},"children":[]}}

        data = json.dumps(payload)
        requests.packages.urllib3.disable_warnings()
        response = requests.post(url, data=data, headers=headers, verify=False)
        logging.info(payload)

        #If not status code 200, skip request
        if response.status_code != 200:
            logging.error("ERROR! Could not complete request for node " + node + " interface " + interface + ".")
            logging.info(response)
            return

        response_json = json.loads(response.text)
        logging.info(response_json)

        if response.status_code == 200:
            print("Node " + node + " Interface " + interface + " removed from " + epg)


#Decoms port channel ports
def decom_po(details):
    node = details["node"]
    interface = details["interface"]
    po_pg = details["po_pg"]
    po_id = details["po_id"]
    
    #gets all epgs for the po
    url = fabric + "/api/node/mo/topology/pod-1/node-" + node + "/sys/aggr-" + po_id + ".json?rsp-subtree-include=full-deployment&target-node=all&target-path=l1EthIfToEPg"
    headers = {
        "Cookie" : f"APIC-Cookie={token}", 
    }
    requests.packages.urllib3.disable_warnings()
    response = requests.get(url, headers=headers, verify=False)
    #If not status code 200, skip request
    if response.status_code != 200:
        logging.error("ERROR! Could not complete request for node " + node + " interface " + interface + ".")
        logging.info(response)
        return

    response_json = json.loads(response.text)
    logging.info(response_json)

    obj = response_json["imdata"][0]["pcAggrIf"]

    #checks if any epgs are deployed on the interface
    if any("children" in d for d in obj):
        child_obj = response_json["imdata"][0]["pcAggrIf"]["children"][0]["pconsCtrlrDeployCtx"]["children"]
    else: 
        print("\nNo EPGs found for " + po_pg + " on node " + node)
        return

    #loops through epgs and appends to list
    list1 = []
    for dic in child_obj:
        for val in dic.values():
            if not isinstance(val, dict):
                print(val)
        else:
            for val2 in val.values():
                list1.append(val2["ctxDn"])

    #confirms if user wants to remove static port from epgs
    while True:
        ans = input("\nConfirm you want to remove " + po_pg + " on node " + node + " from " + str(len(list1)) + " EPG(s)? (y or n): ")
        ans_low = ans.lower()
        if ans_low != "y" and ans_low != "n":
            print("Please enter y or n.")
            continue
        else:
            break
    if ans_low == "n":
        return

    #loops through epgs and removes static port
    for epg in list1:

        url = fabric + "/api/node/mo/" + epg + "/rspathAtt-[topology/pod-1/paths-" + node + "/pathep-[" + po_pg + "]].json"

        headers = {
            "Cookie" : f"APIC-Cookie={token}", 
        }

        payload = {"fvRsPathAtt":{"attributes":{"dn": epg + "/rspathAtt-[topology/pod-1/paths-" + node + "/pathep-[" + po_pg + "]]","status":"deleted"},"children":[]}}

        data = json.dumps(payload)
        requests.packages.urllib3.disable_warnings()
        response = requests.post(url, data=data, headers=headers, verify=False)
        logging.info(payload)

        #If not status code 200, skip request
        if response.status_code != 200:
            logging.error("ERROR! Could not complete request for node " + node + " interface " + interface + ".")
            logging.info(response)
            return

        response_json = json.loads(response.text)
        logging.info(response_json)

        if response.status_code == 200:
            print("Node " + node + " Interface " + po_pg + " removed from " + epg)


#Decoms VPC ports
def decom_vpc(details):
    node = details["node"]
    interface = details["interface"]
    vpc_pg = details["po_pg"]
    po_id = details["po_id"]

    #grabs even and odd nodes
    if int(node) % 2 != 0:
        odd = str(node)
        even = str(int(node) + 1)
    if int(node) % 2 == 0:
        odd = str(int(node) - 1)
        even = node

    #gets all epgs for the vpc
    url = fabric + "/api/node/mo/topology/pod-1/node-" + node + "/sys/aggr-" + po_id + ".json?rsp-subtree-include=full-deployment&target-node=all&target-path=l1EthIfToEPg"
    headers = {
        "Cookie" : f"APIC-Cookie={token}", 
    }
    requests.packages.urllib3.disable_warnings()
    response = requests.get(url, headers=headers, verify=False)
    #If not status code 200, skip request
    if response.status_code != 200:
        logging.error("ERROR! Could not complete request for node " + odd + " and " + even + " interface " + interface + ".")
        logging.info(response)
        return

    response_json = json.loads(response.text)
    logging.info(response_json)

    obj = response_json["imdata"][0]["pcAggrIf"]

    if any("children" in d for d in obj):
        child_obj = response_json["imdata"][0]["pcAggrIf"]["children"][0]["pconsCtrlrDeployCtx"]["children"]
    else: 
        print("\nNo EPGs found for " + interface + " on node " + odd + " and " + even)
        return

    list1 = []
    for dic in child_obj:
        for val in dic.values():
            if not isinstance(val, dict):
                print(val)
        else:
            for val2 in val.values():
                list1.append(val2["ctxDn"])

    while True:
        ans = input("\nConfirm you want to remove " + vpc_pg + " on node " + odd + "-" + even + " from " + str(len(list1)) + " EPG(s)? (y or n): ")
        ans_low = ans.lower()
        if ans_low != "y" and ans_low != "n":
            print("Please enter y or n.")
            continue
        else:
            break
    if ans_low == "n":
        return

    for item in list1:

        url = fabric + "/api/node/mo/" + item + "/rspathAtt-[topology/pod-1/protpaths-" + odd + "-" + even + "/pathep-[" + vpc_pg + "]].json"

        headers = {
            "Cookie" : f"APIC-Cookie={token}", 
        }

        payload = {"fvRsPathAtt":{"attributes":{"dn": item + "/rspathAtt-[topology/pod-1/protpaths-" + odd + "-" + even + "/pathep-[" + vpc_pg + "]]","status":"deleted"},"children":[]}}

        data = json.dumps(payload)
        requests.packages.urllib3.disable_warnings()
        response = requests.post(url, data=data, headers=headers, verify=False)

        #If not status code 200, skip request
        if response.status_code != 200:
            logging.error("ERROR! Could not complete request for node " + odd + " and " + even + " interface " + interface + ".")
            logging.info(response)
            return

        response_json = json.loads(response.text)
        logging.info(response_json)

        if response.status_code == 200:
            print("Node " + odd + "-" + even + " Interface " + vpc_pg + " removed from " + item)


def main():

    #takes pre-snapshot
    snapshot.snapshot_pre(change, token, fabric)

    #Loops through to get action, node and port info
    while True:
        details = {}
        print("\nLeave blank to exit script")
        #Loop to ask for config or decom
        while True:
            modify1 = input("Are you configuring or decommissioning ports? (config or decom): ")
            modify = modify1.lower()
            if modify == "":
                sys.exit()
            if modify != "config" and modify != "decom":
                print("Please enter config or decom.")
                continue
            else:
                ans = input("You selected " + modify + ". Is this correct? (y or n): ")
                ans_low = ans.lower()
                if ans_low != "y" and ans_low != "n":
                    print("Please enter y or n.")
                    continue
                elif ans_low == "y":
                    details["modify"] = modify
                    logging.debug(modify)
                    break
                else:
                    continue

        #Loops to ask for single node ID
        while True:
            node = input("\nEnter a single node id (VPC peer is automatically detected): ")
            if node.isdigit() == False or len(node) != 3 or int(node) < 100 or int(node) > 999:
                print("Please enter a node id between 100 and 999.")
                continue
            else:
                ans = input("You entered " + str(node) + " is this correct? (y or n): ")
                ans_low = ans.lower()
                if ans_low != "y" and ans_low != "n":
                    print("Please enter y or n.")
                    continue
                elif ans_low == "y":
                    details["node"] = node
                    logging.debug(node)
                    break
                else:
                    continue

        #Loops to get interfaces
        while True:
            inter1 = input("\nExamples:\nSingle port: 1/21\nlist of ports: 1/21,1/25,1/29\nrange of ports: 1/21-1/29\nEnter interfaces: ")
            split_int = re.split(',|-',inter1)
            for item in split_int:
                check = item.split("/")
                if "/" not in item or len(check[0]) != 1 or (len(check[1]) != 1 and len(check[1]) != 2) or check[0].isdigit() == False or check[1].isdigit() == False:
                    print("Please enter a valid interface (see examples).")
                    check = 'failed'
                    break
            if check == 'failed':
                continue

            interface = []
            if "-" in inter1:
                inter2 = inter1.split('-')
                inter4 = []
                for item in inter2:
                    inter3 = item.replace('1/', '')
                    inter4.append(int(inter3))
                num1 = inter4[0]
                num2 = inter4[1]
                range1 = list(range(num1, num2+1))
                for item in range1:
                    interface.append("eth1/" + str(item))
            elif "," in inter1:
                inter = inter1.split(',')
                for item in inter:
                    interface.append("eth" + item)
            else:
                interface.append("eth" + inter1)

            ans = input("You entered " + str(inter1) + " is this correct? (y or n): ")
            ans_low = ans.lower()
            if ans_low != "y" and ans_low != "n":
                print("Please enter y or n.")
                continue
            elif ans_low == "y":
                details["interface"] = interface
                logging.debug(inter1)
                logging.debug(interface)
                break
            else:
                continue

        if modify == "config":

            #Gets the interface type
            while True:
                int_type1 = input("\nChoices:\naccess\nvpc-macpinning\nvpc-lacp\nSelect the interface type: ")
                int_type = int_type1.lower()
                if int_type != "access" and int_type != "vpc-macpinning" and int_type != "vpc-lacp":
                    print("Please enter a supported interface type.")
                    continue
                else:
                    ans = input("You entered " + int_type1 + " is this correct? (y or n): ")
                    ans_low = ans.lower()
                    if ans_low != "y" and ans_low != "n":
                        print("Please enter y or n.")
                        continue
                    elif ans_low == "y":
                        details["type"] = int_type
                        logging.debug(int_type)
                        break
                    else:
                        continue

            #Gets interface mode:
            while True:
                int_mode1 = input("\nSelect the interface mode (802.1p or trunk): ")
                int_mode = int_mode1.lower()
                if int_mode != "802.1p" and int_mode != "trunk":
                    print("Please enter a supported interface mode.")
                    continue
                else:
                    ans = input("You entered " + int_mode1 + " is this correct? (y or n): ")
                    ans_low = ans.lower()
                    if ans_low != "y" and ans_low != "n":
                        print("Please enter y or n.")
                        continue
                    elif ans_low == "y":
                        details["mode"] = int_mode
                        logging.debug(int_mode)
                        break
                    else:
                        continue    

            #Gets the interface speed
            while True:
                speed1 = input("\nEnter an interface speed (100M, 1G, 10G, 25G, 40G or 100G): ")
                speed = speed1.lower()
                if speed != "100m" and speed != "1g" and speed != "10g" and speed != "25g" and speed != "40g" and speed != "100g":
                    print("Please enter a supported speed.")
                    continue
                else:
                    ans = input("You entered " + speed1 + " is this correct? (y or n): ")
                    ans_low = ans.lower()
                    if ans_low != "y" and ans_low != "n":
                        print("Please enter y or n.")
                        continue
                    elif ans_low == "y":
                        details["speed"] = speed
                        logging.debug(speed)
                        break
                    else:
                        continue

            #Gets the vlans
            while True:
                vlan1 = input("\nExamples:\nSingle vlan: 100\nlist of vlans: 100,105,198\nrange of vlans: 100-250\nEnter vlans(s): ")
                split_vlan = re.split(',|-',vlan1)
                for item in split_vlan:
                    if item.isdigit() == False or int(item) < 1 or int(item) > 4094:
                        print("Please enter a valid vlan (see examples).")
                        check = 'failed'
                        break
                if check == 'failed':
                    continue

                vlan = []
                if "-" in vlan1:
                    vlan2 = vlan1.split('-')
                    num1 = int(vlan2[0])
                    num2 = int(vlan2[1])
                    range2 = (list(range(num1, num2+1)))
                    for item in range2:
                        vlan.append(item)
                elif "," in vlan1:
                    vlan_split = (vlan1.split(','))
                    for item in vlan_split:
                        vlan.append(item)
                else:
                    vlan.append(vlan1)

                ans = input("You entered " + str(vlan1) + " is this correct? (y or n): ")
                ans_low = ans.lower()
                if ans_low != "y" and ans_low != "n":
                    print("Please enter y or n.")
                    continue
                elif ans_low == "y":
                    details["vlan"] = vlan
                    logging.debug(vlan1)
                    logging.debug(vlan)
                    break
                else:
                    continue


        #Calls function to configure ports
        if modify == "config":
            access_policy(details)

        #Calls function to decom ports
        if modify == "decom":
            decom_check(details)


    #takes post-snapshot
    snapshot.snapshot_post(change, token, fabric)

if __name__ == '__main__':
    main()
