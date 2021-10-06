#!/usr/bin/env python

import json
import requests
import pathlib

# 7/1/2021
# Read the tokens from a WTI device
# Post data looks like {"rights": "0"}'
# Ask if you want to use a token, if yes will see if there is already a saved token, otherise will exit.
# If not token method, ask for username and password and save the administrator token

# 10/5/2021
# added more menu selections for SITE_NAME, URI, etc

# supress Unverified HTTPS request, only do this in a verified environment
#from requests.packages.urllib3.exceptions import InsecureRequestWarning
#requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# this is the hard coded Administrator token
TOKEN = ""

# Address of the WTI device
URI = "https://"
SITE_NAME = "192.168.0.236"

BASE_PATH_PW    = "/api/v2/status/gettoken"
BASE_PATH_TOKEN = "/api/v2/token/status/status"

# put in the username and password to your WTI device here
USERNAME = "super"
PASSWORD = "super"

# Do not verifiy key on https calls (for testing only)
VERIFY = False

iMethod = 1	#0 = Token API method, 1 = username/password API method

print("\n\n\nWTI API Token demo 1.0\n")
print("A program to demonstrate the use of key tokens to avoid")
print("using a username/passwordwhen using WTI API call.\n")

cszTemp = "Site Name: [%s] " % (SITE_NAME)
cszTemp = input(cszTemp)
if (len(cszTemp) > 0):
	SITE_NAME = cszTemp

cszTemp = "Secure (https): [Y] "
cszTemp = input(cszTemp)
if ((cszTemp.upper() == "N") | (cszTemp.upper() == "NO")):
    URI = "http://"

file = pathlib.Path("tokenadmin.txt")
if file.exists ():
    with open("tokenadmin.txt", 'r') as file_object:
        TOKEN = file_object.read()
        iMethod = 0

cszTemp = input("Use Token/Header Method: [%s] " % ("Y" if iMethod == 0 else "N"))

if ((cszTemp.upper() == "Y") | (cszTemp.upper() == "YES") | ((len(cszTemp) == 0) & (iMethod == 0))):
    # Is there an existing token?
    if len(TOKEN):
        print ("Using token from saved file.")
        BASE_PATH = BASE_PATH_TOKEN
        iMethod = 0
    else:
        print("No saved token exists.")
        exit(1)
else:
	cszTemp = "Username: [%s] " % (USERNAME)
	cszTemp = input(cszTemp)
	if (len(cszTemp) > 0):
		USERNAME = cszTemp

	cszTemp = "Password: [%s] " % (PASSWORD)
	cszTemp = input(cszTemp)
	if (len(cszTemp) > 0):
		PASSWORD = cszTemp

	BASE_PATH = BASE_PATH_PW
	iMethod = 1

try:
    print(URI+SITE_NAME+BASE_PATH)

    if (iMethod == 1):
        r = requests.get(URI+SITE_NAME+BASE_PATH, auth=(USERNAME, PASSWORD), verify=VERIFY)
    else:
        custom_header = {'X-WTI-API-Key': '%s' % (TOKEN)}
        r = requests.get(URI+SITE_NAME+BASE_PATH, headers=custom_header, verify=VERIFY)

    if (r.status_code == 200):
        parsed_json = r.json()

        statuscode = parsed_json["status"]["code"]
 
        if (int(statuscode) != 0):
            print("Status Code: %s" % statuscode)
            print(parsed_json)
            exit(1)

#	Uncomment to see the JSON return by the unit
#        print(parsed_json)
        if (iMethod == 1):
            try:
                viewonlytoken = parsed_json['0']
                print("\nView Only:     %s" % (viewonlytoken))
            except:
                print("No View Only Token")

            try:
                usertoken = parsed_json['1']
                print("User:          %s" % (usertoken))
            except:
                print("No User Token")

            try:
                superusertoken = parsed_json['2']
                print("Super User:    %s" % (superusertoken))
            except:
                print("No Super User Token")

            try:
                administrator = parsed_json['3']
                print("Administrator: %s\n" % (administrator))

                if (len(administrator) > 0):
                    with open("tokenadmin.txt", 'w') as file_object:
                        file_object.write(administrator)
                        print("Saving Administrator token [%s]\n" % (administrator))
            except:
                print("No Administrator Token")

        else:
            print("\nProduct:     %s" % ( parsed_json['product']))
            print("Version:     %s" % ( parsed_json['softwareversion']))
            print("Site ID:     %s" % ( parsed_json['siteid']))
            print("Uptime :     %s" % ( parsed_json['uptime']))
            print("SSL Ver:     %s" % ( parsed_json['opensslversion']))
            print("SSH Ver:     %s" % ( parsed_json['opensshversion']))
            print("Web Ver:     %s\n" % ( parsed_json['apacheversion']))

    elif (r.status_code == 403):
        print("\nThe Token %s was bad.\n\n" % (TOKEN))
    else:
        print("Error: %s\n" % (r.status_code))

except requests.exceptions.RequestException as e:
    print (e)
