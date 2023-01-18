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

import get_token
import requests
import json
import time
import sys

def snapshot_pre(change, token, fabric):

  while True:
      ans = input("\nDo you want to take a pre-change snapshot? ")
      ans_low = ans.lower()
      if ans_low != "y" and ans_low != "n":
          print("Please enter y or n.")
          continue
      if ans_low == "n":
          return
      else:
          break

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
  if response.status_code != 200:
    sys.exit("Error: Could not complete the snapshot")
  response_json = json.loads(response.text)

  print("Please wait while pre-change snapshot is in progress.")
  time.sleep(15)
  print("Pre-change snapshot Successful")


def snapshot_post(change, token, fabric):

  while True:
      ans = input("\nDo you want to take a post-change snapshot? ")
      ans_low = ans.lower()
      if ans_low != "y" and ans_low != "n":
          print("Please enter y or n.")
          continue
      if ans_low == "n":
          return
      else:
          break

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
  if response.status_code != 200:
    sys.exit("Error: Could not complete the snapshot")
  response_json = json.loads(response.text)

  print("\nPost-change snapshot Successful")


def main():
  #Logs into fabric and saves token, url and change number
  login = get_token.get_token()
  token = login[0]
  fabric = login[1]
  change = login[2]
  while True:
    answer = input("Is the a pre or post change snapshot? (pre or post): ")
    if answer.lower() == "pre":
      snapshot_pre(change, token, fabric)
      break
    elif answer.lower() == "post":
      snapshot_post(change, token, fabric)
      break
    else:
      print("Please select pre or post.")
      continue

if __name__ == '__main__':
    main()
