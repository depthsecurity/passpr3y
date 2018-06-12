#!/usr/bin/python

import requests
import pprint
import json


# Parse request file
requestsFile = open('request.txt', 'r')
lineList = requestsFile.readlines()
endPoint = lineList[0].split(' ')[1].strip()
headerDict = dict(item.split(': ') for item in map(str.strip, lineList[1:-2]))
dataDict = dict(item.split('=') for item in map(str.strip, lineList[-1].split('&')))
requestsFile.close()

r = requests.post("http://" + headerDict["Host"] + '/' + endPoint, \
        headers=headerDict, data=dataDict, verify=False)

print len(r.content)


