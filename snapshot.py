#!/usr/bin/env python

'''
   The purpose of this script is to create a snapshot before and after a change.


    File name: snapshot.py
    Author: Nicholas Bogdajewicz
    Date created: 1/20/2022
    Date last modified: 2/09/2022
    Python Version: 3.8.2
    requests version: 2.27.0
'''

import requests
import json
import time


def snapshot_pre(change, token, fabric):


    url = fabric + "/api/node/mo/uni/fabric/configexp-defaultOneTime.json"

    payload = {
    "configExportP": {
      "attributes": {
        "dn": "uni/fabric/configexp-defaultOneTime",
        "name": "defaultOneTime",
        "snapshot": "true",
        "targetDn": "",
        "adminSt": "triggered",
        "rn": "configexp-defaultOneTime",
        "status": "created,modified",
        "descr": change + "_pre_change"
      },
      "children": []
      }
    }


    headers = {
      "Cookie" : f"APIC-Cookie={token}", 
    }

    data = json.dumps(payload)

    requests.packages.urllib3.disable_warnings()
    response = requests.post(url, headers=headers, data=data, verify=False)
    time.sleep(15)


def snapshot_post(change, token, fabric):


    url = fabric + "/api/node/mo/uni/fabric/configexp-defaultOneTime.json"

    payload = {
    "configExportP": {
      "attributes": {
        "dn": "uni/fabric/configexp-defaultOneTime",
        "name": "defaultOneTime",
        "snapshot": "true",
        "targetDn": "",
        "adminSt": "triggered",
        "rn": "configexp-defaultOneTime",
        "status": "created,modified",
        "descr": change + "_post_change"
      },
      "children": []
      }
    }


    headers = {
      "Cookie" : f"APIC-Cookie={token}", 
    }

    data = json.dumps(payload)

    requests.packages.urllib3.disable_warnings()
    response = requests.post(url, headers=headers, data=data, verify=False)
