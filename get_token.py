#!/usr/bin/env python

'''
   This script will login to the specific ACI Fabric and generate a token.


    File name: get_token.py
    Author: Nicholas Bogdajewicz
    Date created: 1/20/2022
    Date last modified: 1/18/2023
    Python Version: 3.8.2
    requests version: 2.27.0
'''

import requests
import json
import sys
from getpass import getpass
import argparse

#change to desired fabric names and URL 
dc1 = "dc1"
dc1url = "https://"
dc2 = "dc2"
dc2url = "https://"
dc3 = "dc3"
dc3url = "https://"
dc4 = "dc4"
dc4url = "https://"


'''
This function takes the name/pwd input to log into the APIC and stores the token as a variable
'''
def get_token():


    #takes fabric argument and store the corresponding url
    parser = argparse.ArgumentParser(description='Example: python3 port_config.py --fabric dc1 --user admin --pass \'cisco!23\' --chg CHG12345')
    parser.add_argument("--fabric", dest="fabric", metavar='', type=str, help='Choose Fabric: ' + dc1 + ", " + dc2 + ", " + dc3 + ", " + dc4)
    parser.add_argument("--user", dest="name", metavar='', type=str, help='Enter username within sinle quotes')
    parser.add_argument("--pass", dest="pwd", metavar='', type=str, help='Enter password within single quotes')
    parser.add_argument("--chg", dest="chg", metavar='', type=str, help='Enter change number:')
    args = parser.parse_args()
    site = args.fabric
    name = args.name
    pwd = args.pwd
    change = str(args.chg)
    fabric = ""

    if site == None:
        while True:
            site = input("Input fabric (" + dc1 + ", " + dc2 + ", " + dc3 + ", " + dc4 + "): ")
            if site.lower() == dc1 or site.lower() == dc2 or site.lower() == dc3 or site.lower() == dc4:
                answer = input("Are you sure you want to select " + site + "? (y or n): ")
                if answer.lower() == "y":
                    break
                else:
                    continue
            else:
                print("\nPlease input a valid fabric (" + dc1 + ", " + dc2 + ", " + dc3 + ", " + dc4 + "): ")
                continue
    
    if name == None:
        while True:
            name = input("Input username: ")
            answer = input("Is this the correct username? " + name + " (y or n): ")
            if answer.lower() == "y":
                break
            else:
                continue

    if pwd == None:
        while True:
            pwd = getpass("Input password: ")
            answer = input("Would you like to re-type your password? (y or n): ")
            if answer.lower() == "n":
                break
            else:
                continue

    if change == "None":
        while True:
            change = input("Input change number: ")
            answer = input("Is this the correct change number? " + change + " (y or n): ")
            if answer.lower() == "y":
                break
            else:
                continue

    while True:
        if (site.lower() == dc1):
            fabric = dc1url
            break
        elif (site.lower() == dc2):
            fabric = dc2url
            break
        elif (site.lower() == dc3):
            fabric = dc3url
            break
        elif (site.lower() == dc4):
            fabric = dc4url
            break
        else:
            print("Default fabric is " + dc1)
            fabric = dc1url
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

    if response.status_code == 401:
        sys.exit("TACACS+ Server Authentication DENIED")
    elif response.status_code != 200:
        sys.exit("Error: Could not log into APIC")
    else:
        print("\nLogin successful")
   
    response_json = json.loads(response.text)

    token = response_json["imdata"][0]["aaaLogin"]["attributes"]["token"]
    return(token, fabric, change)



def refresh_token(fabric, token):
    url = fabric + "/api/aaaRefresh.json"

    headers = {
        "Cookie" : f"APIC-Cookie={token}", 
    }

    requests.packages.urllib3.disable_warnings()
    response = requests.get(url, headers=headers, verify=False)
    response_json = json.loads(response.text)

    token2 = response_json["imdata"][0]["aaaLogin"]["attributes"]["token"]
    return(token2)
