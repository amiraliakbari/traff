#!/bin/bash

interface=${1:-wlp1s0}

tshark -i $interface -l -T fields -E separator=, -e frame.time_epoch -e frame.len -e frame.protocols -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e icmp.type -e udp.srcport -e udp.dstport -e dns.qry.name -e http.host -e http.request.full_uri | python -u manage.py import_traffic
