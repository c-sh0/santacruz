#!/usr/bin/env python3
#=====================================
# Do ASN lookup
#
# > yum install python3-devel
# > pip3 install aslookup
#
# :- https://github.com/dspruell/aslookup
#
# [/csh:]> date "+%D"
# 05/08/22
# https://github.com/c-sh0
#=====================================
import time
import json
import argparse
import re
from aslookup.exceptions import LookupError
from aslookup import get_as_data

def main():
     parser = argparse.ArgumentParser(description='-: ASN Lookup :-', epilog="Python client for IP to ASN lookup services\n", formatter_class=argparse.RawTextHelpFormatter)
     parser.add_argument('-a','--addr',    help='[ip_addr]\t:- IP address', dest='addr', metavar='', required=True)
     parser.add_argument('-s','--service', help='[shadowserver,cymru]\t:- service to query (default: cymru)', default="cymru", dest='service', metavar='', action='store')
     parser.add_argument('-o','--output',  help='[format]\t:- Output format [csv,json]', default="txt", dest='output', metavar='', action='store')

     opt_args = parser.parse_args()
     addr = opt_args.addr.strip()
     d = {}

     try:
        obj = get_as_data(addr, service=opt_args.service)
        #print(obj)

        d['cc']          = obj.cc
        d['asn']         = obj.asn
        d['prefix']      = obj.prefix
        d['handle']      = obj.handle
        d['as_name']     = re.sub('[,]', '', obj.as_name)
        d['data_source'] = obj.data_source

        if opt_args.output == 'json':
           print(json.dumps(d))
           return 1

        if opt_args.output == 'csv':
           print(f"handle,asn,prefix,as_name,cc,data_source")
           print(f"{d['handle']},{d['asn']},{d['prefix']},{d['as_name']},{d['cc']},{d['data_source']}")
           return 1

        print ("{:<8} {:<8} {:<15} {:<40} {:<8} {:<8}".format('Handle','ASN','Prefix','Name','CC','Source'))
        print ("{:<8} {:<8} {:<15} {:<40} {:<8} {:<8}".format(d['handle'],d['asn'],d['prefix'],d['as_name'],d['cc'],d['data_source']))

     except LookupError as e:
        print('%-15s  %s' % (addr, e))

if __name__ == "__main__":
        main()

