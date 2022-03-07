#!/usr/bin/env python

'''
   This script will login to a specific ACI Fabric and generate a token.


    File name: get_token.py
    Author: Nicholas Bogdajewicz
    Date created: 1/20/2022
    Date last modified: 2/09/2022
    Python Version: 3.8.2
    requests version: 2.27.0
'''

import requests
import json
import sys
import logging
from logging.handlers import RotatingFileHandler
from getpass import getpass
import argparse


#Logs to file
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s.%(msecs)03d] [%(levelname)s] [%(filename)s] [%(funcName)s():%(lineno)s] %(message)s', handlers=[RotatingFileHandler('logs/get_token.log', maxBytes=100000, backupCount=1)])

#logs to console
console = logging.StreamHandler()
console.setLevel(logging.WARNING)
logging.getLogger('').addHandler(console)
logger = logging.getLogger(__name__)


'''
This function takes the name/pwd input to log into the APIC and stores the token as a variable
'''
def get_token():


    #takes fabric argument and store the corresponding url
    parser = argparse.ArgumentParser(description= "Example: python3 script_name.py --fabric lab --user admin --pass 'cisco!23' --chg CHG12345")
    parser.add_argument("--fabric", dest="fabric", metavar='', type=str, help='Choose Fabric: lab, prod')
    parser.add_argument("--user", dest="name", metavar='', type=str, help='Enter username within sinle quotes')
    parser.add_argument("--pass", dest="pwd", metavar='', type=str, help='Enter password within single quotes')
    parser.add_argument("--chg", dest="chg", metavar='', type=str, help='Enter change number:')
    args = parser.parse_args()
    site = args.fabric
    name = args.name
    pwd = args.pwd
    change = str(args.chg)
    fabric = ""

    while True:
        if (site == "LAB") or ( site == "lab"):
            fabric = "https://sandboxapicdc.cisco.com"
            break
        elif (site == "PROD") or (site == "prod"):
            fabric = "https://prod"
            break
        else:
            print("Default fabric is lab")
            fabric = "https://sandboxapicdc.cisco.com"
            break




    url = fabric + "/api/aaaLogin.json"

    payload = {
       "aaaUser": {
          "attributes": {
             "name":name,
             "pwd":pwd
          }
       }
    }

    data = json.dumps(payload)

    requests.packages.urllib3.disable_warnings()
    response = requests.post(url,data=data, verify=False)
    logger.debug(response)

    #checks API response
    if response.status_code == 401:
        logger.debug("TACACS+ Server Authentication DENIED")
        sys.exit("TACACS+ Server Authentication DENIED")
    elif response.status_code != 200:
         logger.error("ERROR! Could not log in.")
         sys.exit()
    else:
        logger.info("Login successful")
        print("\nLogin successful")
   
    response_json = json.loads(response.text)

    token = response_json["imdata"][0]["aaaLogin"]["attributes"]["token"]
    return(token, fabric, change)
