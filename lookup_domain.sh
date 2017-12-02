#!/bin/sh

DOMAIN=$1
DNSRECON=../dnsrecon/dnsrecon.py
WORDLIST=../dnsrecon/subdomains-top1mil.txt

if [ -z "$DOMAIN" ] ; then
   echo "Usage: $0 <domain>"
else
    #$DNSRECON -d ${DOMAIN} --xml ${DOMAIN}.xml -D ${WORDLIST} --threads 20 -t brt
    $DNSRECON -d ${DOMAIN} --xml ${DOMAIN}.xml --threads 30
fi
    
