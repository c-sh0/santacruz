#!/usr/bin/env python3
#
# Maybe one day nmap will add support for json output?
# Untill that happens? ¯\_(ツ)_/¯
#
import argparse
import re
import xml.etree.ElementTree as xml

def do_parse(xml,args):
    data = {}
    for h in xml.iter('host'):
        if h.tag == 'host':
            for host in h.getchildren():

                if host.tag == 'address':
                   if host.attrib['addr']:
                       data['ip_addr'] = host.attrib['addr']

                elif host.tag == 'ports':
                     for port in host.getchildren():
                         if port.tag == 'port':
                             for p in port.getchildren():
                                 if p.tag == 'script':

                                    # Clean up script output (httpx)
                                    if args.datatype == 'httpx':
                                        if p.attrib['id'] == args.datatype:
                                            if  p.attrib['output']:
                                                s0  = p.attrib['output'].replace('\n','')
                                                s1  = s0.replace('[]','').lstrip()
                                                httpx = s1.split()
                                                print(httpx[0])
        if args.datatype == 'ip':
           print(f"{data['ip_addr']}")

    return 1

def main():
    parser = argparse.ArgumentParser(description='-: Simple Nmap XML Parser :-')
    parser.add_argument('--file', help='[file]\t:- Path to Nmap XML report file', dest='file', metavar='', type=argparse.FileType('r'), required=True)
    parser.add_argument('--data-type', help='[data-type]\t:- Output data-type [ip,httpx]', dest='datatype', metavar='', required=True)
    opt_args = parser.parse_args()

    xml_tree = xml.parse(opt_args.file)
    xml_root = xml_tree.getroot()
    opt_args.file.close()

    do_parse(xml_root,opt_args)

if __name__ == "__main__":
        main()
