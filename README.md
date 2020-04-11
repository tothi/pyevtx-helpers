# pyevtx-helpers
Some useful parsers for Windows EventLog (evtx) files using pyevtx

During hunting for attacker traces in a Windows Active Directory
environment, it was useful to implement some Windows EventLog
parsing.

Using pyevtx from the [libevtx](https://github.com/libyal/libevtx) project.

## Tools

* [evtx_parse_rdpclient.py]([evtx_parse_rdpclient.py): parse
Microsoft-Windows-TerminalServices-RDPClient/Operational for
outgoing RDP connections

* [evtx_parse_security.py](evtx_parse_security.py): parse
Security log for (important) incoming logon activity

