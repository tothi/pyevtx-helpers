#!/usr/bin/python
#
# helper for parsing Windows EventLog Security
# for tracking (mostly) incoming logons

import Evtx.Evtx as evtx
from datetime import datetime, timezone
import sys

LOG = sys.argv[1]
#LOG = "winevt/Security.evtx"

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

def parse(root):
    eventid = int(root.find("e:System/e:EventID", ns).text)
    timecreated = datetime.strptime(root.find("e:System/e:TimeCreated", ns).attrib["SystemTime"], '%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc).astimezone(tz=None).strftime('%Y-%m-%d %H:%M:%S.%f')
    if eventid == 4625:
        return "{}, EventID={}, An account failed to log on: TargetUserName={} LogonType={} SubStatus={} WorkstationName={} IpAddress={}".format(timecreated, eventid, root.find("e:EventData/e:Data[@Name='TargetUserName']", ns).text, root.find("e:EventData/e:Data[@Name='LogonType']", ns).text, root.find("e:EventData/e:Data[@Name='SubStatus']", ns).text, root.find("e:EventData/e:Data[@Name='WorkstationName']", ns).text, root.find("e:EventData/e:Data[@Name='IpAddress']", ns).text,)
    if eventid == 4624:
        return "{}, EventID={}, An account was successfully logged on: TargetUserName={} TargetDomainName={} LogonType={} WorkstationName={} IpAddress={}".format(timecreated, eventid, root.find("e:EventData/e:Data[@Name='TargetUserName']", ns).text, root.find("e:EventData/e:Data[@Name='TargetDomainName']", ns).text, root.find("e:EventData/e:Data[@Name='LogonType']", ns).text, root.find("e:EventData/e:Data[@Name='WorkstationName']", ns).text, root.find("e:EventData/e:Data[@Name='IpAddress']", ns).text)
    if eventid == 4634:
        return "{}, EventID={}, An account was logged off: TargetUserName={} TargetDomainName={} LogonType={}".format(timecreated, eventid, root.find("e:EventData/e:Data[@Name='TargetUserName']", ns).text, root.find("e:EventData/e:Data[@Name='TargetDomainName']", ns).text, root.find("e:EventData/e:Data[@Name='LogonType']", ns).text)
    
with evtx.Evtx(LOG) as log:
    for record in log.records():
        #print(record.xml())
        r = parse(record.lxml())
        if r:
            print(r)

