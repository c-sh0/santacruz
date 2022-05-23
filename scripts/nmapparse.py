#!/usr/bin/env python3
#
# Maybe one day nmap will add support for json output?
# Untill that happens? ¯\_(ツ)_/¯
#
# [/csh:]> date "+%D"
# 05/12/22
#
import sys
import argparse
import re
import xml.etree.ElementTree as xml

def do_parse(xml,args):
    port_summary = {}
    num_hosts = 0

    for h in xml.iter('host'):
        data = {}
        data['ports'] = []

        if h.tag == 'host':
            for host in h.getchildren():

                if host.tag == 'address':
                   if host.attrib['addr']:
                       data['ip_addr'] = host.attrib['addr']

                elif host.tag == 'ports':
                     for port in host.getchildren():
                         if port.tag == 'port':
                             for p in port.getchildren():

                                 # open ports
                                 if p.tag == 'state':
                                    if p.attrib['state'] == 'open':
                                        data['ports'].append(port.attrib['portid'])
        # count hosts
        num_hosts += 1

        # host open port count
        host_pcnt = len(data['ports'])

        # print hosts
        if args.output == 'ip':
                print(f"{data['ip_addr']}")

        # httpx
        elif args.output == 'httpx':
                if args.skip_gt:
                    if host_pcnt >= args.skip_gt:
                       continue

                # http(s)
                for port in data['ports']:
                    if port == '443':
                       print(f"https://{data['ip_addr']}")
                    elif port == '80':
                       print(f"http://{data['ip_addr']}")
                    else:
                       print(f"http://{data['ip_addr']}:{port}")
                       print(f"https://{data['ip_addr']}:{port}")

                #ports_list = ",".join(data['ports'])
                #print(f"-p {ports_list} <<< {data['ip_addr']}")

        elif args.output == 'pcount':
                # print hosts where open port count is >= [num]
                if args.gt_num:
                    if host_pcnt >= args.gt_num:
                        print(f"{host_pcnt},{data['ip_addr']}")

                # print hosts where open port count is <= [num]
                elif args.lt_num:
                    if host_pcnt <= args.lt_num:
                        print(f"{host_pcnt},{data['ip_addr']}")

                # print hosts + open ports count
                else:
                    print(f"{port_count},{data['ip_addr']}")

        # build summarized discovered ports list
        elif args.output == 'plist':
                if args.skip_gt:
                    if host_pcnt >= args.skip_gt:
                       continue

                for port in data['ports']:
                    if port in port_summary:
                       port_summary[port] += 1
                    else:
                       port_summary[port] = 1

    # print ports (plist)
    if len(port_summary) > 0:
       for port in port_summary:
           print(f"{port}")

    return 1

def main():
    parser = argparse.ArgumentParser(description='-: Simple Nmap XML Parser :-')
    parser.add_argument('-f','--file', help='[file]\t:- Path to Nmap XML report file', dest='file', metavar='', type=argparse.FileType('r'), required=True)
    parser.add_argument('-o','--output', help='[type]\t:- Output data type [ip,pcount,plist,httpx]', dest='output', metavar='', required=True)
    parser.add_argument('-gt','--greater-than', help='[num]\t:- List hosts where open port count is >= [num]', default=False, dest='gt_num', metavar='', type=int)
    parser.add_argument('-lt','--less-than', help='[num]\t:- List hosts where open port count is <= [num]', default=False, dest='lt_num', metavar='', type=int)
    parser.add_argument('--skip-gt', help='[num]\t:- For use with [plist,httpx] output, Skip hosts where open port count is >= [num]', default=False, dest='skip_gt', metavar='', type=int)
    opt_args = parser.parse_args()

    xml_tree = xml.parse(opt_args.file)
    xml_root = xml_tree.getroot()
    opt_args.file.close()

    do_parse(xml_root,opt_args)
    #sys.exit(1)

if __name__ == "__main__":
        main()
