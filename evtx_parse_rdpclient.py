#!/usr/bin/python
#
# helper for parsing important events in Windows EventLog
# Microsoft-Windows-TerminalServices-RDPClient/Operational
# for tracking outgoing RDP connections
#

import Evtx.Evtx as evtx
from hashlib import sha1
from base64 import b64encode
from datetime import datetime, timezone
import sys

LOG = sys.argv[1]
#LOG = "winevt/Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx"
#USERS = ["administrator", "helpdesk"]
USERS = list(map(lambda s: s.strip(), open('users.txt', 'r').readlines()))

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

def hashtable(userlist):
    t = {}
    for u in userlist:
        t[b64encode(sha1(u.encode("utf-16le")).digest()).decode()] = u
    return t

def lookupuser(h, ht):
    r = lambda x: ht[x] if x in ht else x
    return '-'.join(map(r, h.split('-')))

def parse(root, ht={}):
    eventid = int(root.find("e:System/e:EventID", ns).text)
    timecreated = datetime.strptime(root.find("e:System/e:TimeCreated", ns).attrib["SystemTime"], '%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc).astimezone(tz=None).strftime('%Y-%m-%d %H:%M:%S.%f')
    pid = int(root.find("e:System/e:Execution", ns).attrib["ProcessID"])
    head = "{}, EventID={}, PID={}".format(timecreated, eventid, pid)
    if eventid == 1024:
        return "{}, RDP ClientActiveX is trying to connect to the server ({})".format(head, root.find("e:EventData/e:Data[@Name='Value']", ns).text)
    if eventid == 1029:
        return "{}, Logon with UserName {}".format(head, lookupuser(root.find("e:EventData/e:Data[@Name='TraceMessage']", ns).text, ht))
    if eventid == 1102:
        return "{}, The client has initiated a multi-transport connection to the server {}".format(head, root.find("e:EventData/e:Data[@Name='Value']", ns).text)
    if eventid == 1025:
        return "{}, RDP ClientActiveX has connected to the server".format(head)
    if eventid == 1027:
        return "{}, Connected to domain ({}) with SessionId {}.".format(head, root.find("e:EventData/e:Data[@Name='DomainName']", ns).text, root.find("e:EventData/e:Data[@Name='SessionId']", ns).text)
    if eventid == 1026:
        return "{}, RDP ClientActiveX has been disconnected (Reason={})".format(head, root.find("e:EventData/e:Data[@Name='Value']", ns).text)
    
with evtx.Evtx(LOG) as log:
    ht = hashtable(USERS)
    for record in log.records():
        #print(record.xml())
        r = parse(record.lxml(), ht)
        if r:
            print(r)

