#!/usr/bin/env python

'''
   This script will login to the specific ACI Fabric and generate a token.


    File name: get_token.py
    Author: Nicholas Bogdajewicz
    Date created: 1/20/2022
    Date last modified: 6/21/2022
    Python Version: 3.8.2
    requests version: 2.27.0
'''

import requests
import json
import sys
from getpass import getpass
import argparse


'''
This function takes the name/pwd input to log into the APIC and stores the token as a variable
'''
def get_token():


    #takes fabric argument and store the corresponding url
    parser = argparse.ArgumentParser(description='Example: python3 script_name.py --fabric lab --user admin --pass \'cisco!23\' --chg CHG12345')
    parser.add_argument("--fabric", dest="fabric", metavar='', type=str, help='Choose Fabric: lab, prod1 or prod2')
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
            site = input("Input fabric (lab, prod1 or prod2): ")
            if site.lower() == "lab" or site.lower() == "prod1" or site.lower() == "prod2":
                answer = input("Are you sure you want to select " + site + "? (y or n): ")
                if answer.lower() == "y":
                    break
                else:
                    continue
            else:
                print("\nPlease input a valid fabric (lab, prod1 or prod2): ")
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
        if (site == "lab") or ( site == "lab"):
            fabric = ""
            break
        elif (site == "prod1") or (site == "prod1"):
            fabric = ""
            break
        elif (site == "prod2") or (site == "prod2"):
            fabric = ""
            break
        else:
            print("Default fabric is lab")
            fabric = ""
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

