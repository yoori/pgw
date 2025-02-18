#!/bin/bash

#cat radius_request.txt | tr '\n' ',' | sed -r 's/,$//' | /opt/tel-gateway/bin/radclient localhost:1813 acct sbtel
/opt/tel-gateway/bin/radclient -f radius_request.txt localhost:1813 acct sbtel
