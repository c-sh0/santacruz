#!/usr/bin/env python3
# ========================================================================================
# Read nmap XML output, send to ES
#
# [/csh:]> date "+%D"
# 04/11/22
# https://github.com/c-sh0
#
# nmap has yet to add a json output feature
# https://github.com/nmap/nmap/issues/635
# ========================================================================================
import sys
import json
import time
import argparse
import requests
import base64
import hashlib
import uuid
import yaml
import re
import xml.etree.ElementTree as xml
from urllib.parse import urlparse
###
#import logging
#logging.basicConfig(filename='nmap2es.log', level=logging.DEBUG)
###
# ================================================================================================================
# * Send ip, hostname, script output, and open port info to ES
# * Service detection information is not sent. (let's be honest, it's not useful and often unreliable by default)
#
# Original version of the parser can be found here:
# https://raw.githubusercontent.com/ChrisRimondi/VulntoES/master/VulntoES.py
# alt veriosn: https://github.com/marco-lancini/docker_offensive_elk/blob/master/extensions/ingestor/VulntoES.py
#
# ================================================================================================================
def sendToEs(xml_root,ES_session,api_url,verbose):
    for h in xml_root.iter('host'):
       dict_item = {}
       dict_item['scanner'] = 'nmap'

       if h.tag == 'host':
           if 'endtime' in h.attrib and h.attrib['endtime']:
               dict_item['time'] = time.strftime('%Y/%m/%d %H:%M:%S', time.gmtime(float(h.attrib['endtime'])))

       for c in h:
           if c.tag == 'address':
              if c.attrib['addr']:
                 dict_item['ip'] = c.attrib['addr']

           elif c.tag == 'hostnames':
               for names in c.getchildren():
                   if names.attrib['name']:
                       dict_item['hostname'] = names.attrib['name']

           elif c.tag == 'ports':
               for port in c.getchildren():
                   if port.tag == 'port':
                       dict_item['port'] = port.attrib['portid']
                       dict_item['protocol'] = port.attrib['protocol']
                       dict_item['script'] = ''
                       dict_item['script_output'] = ''

                       for p in port.getchildren():
                           if p.tag == 'state':
                               dict_item['state'] = p.attrib['state']

                           elif p.tag == 'script':
                               if p.attrib['id']:
                                  if p.attrib['output']:
                                     dict_item['script'] = p.attrib['id']
                                     s  = p.attrib['output'].replace('\n','')
                                     dict_item['script_output'] = re.sub('\\\\x00', '', s)

                       if dict_item['state'] == 'open':
                          ## fill in some empty values
                          if not 'hostname' in dict_item:
                             dict_item['hostname'] = "unknwon"

                          # Gererate a uniq index ID (prevent duplicate documents with the same timestamps)
                          # https://www.elastic.co/blog/efficient-duplicate-prevention-for-event-based-data-in-elasticsearch
                          # https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html
                          index_uuid = uuid_from_string(json.dumps(dict_item))
                          document_url = api_url + "/" + index_uuid + "?op_type=create"
                          print(f"[INFO]: ES create: {document_url}")

                          if verbose == 1:
                             print(f"[VERBOSE]: {document_url}:\n[VERBOSE]: {json.dumps(dict_item)}")

                          # Only send document to ES if the port is open
                          r = ES_session.put(document_url, data=json.dumps(dict_item), verify=False)
                          if r.status_code == 409:
                             print(f"\033[33m[WARN]: Document UUID: {index_uuid} already exists\033[0m\n{json.dumps(dict_item)}")

                          if verbose == 1:
                             print(f"[VERBOSE]: Response Code: [{r.status_code}]\n[VERBOSE]: {r.content}\n")

def uuid_from_string(string):
    md5_hash = hashlib.md5()
    md5_hash.update(string.encode("utf-8"))
    md5_hex_str = md5_hash.hexdigest()

    return str(uuid.UUID(md5_hex_str))

def init_ESSession(user,passwd,api_URL,verbose):
    print(f"[INFO]: Connecting to Elasticsearch: {api_URL}")

    session = requests.Session()
    ctype_header = {"Content-Type": "application/json"}
    session.headers.update(ctype_header)

    if user:
        userpass = user + ':' + passwd
        encoded_u = base64.b64encode(userpass.encode()).decode()
        auth_header = {"Authorization" : "Basic %s" % encoded_u}
        session.headers.update(auth_header)

    # ES connection
    r = session.get(api_URL, headers=session.headers, verify=False)
    if r.status_code != 200:
       print(f"[ERROR]: Connection failed, got {r.status_code} response!")
       return sys.exit(-1)

    return session

def main():
    parser = argparse.ArgumentParser(description='Import nmap XML output into Elasticsearch')
    parser.add_argument('-c', '--config', help='Path to santacruz.yml configuration file', dest='config', metavar='[config]', type=argparse.FileType('r'), required=True)
    parser.add_argument('-f', '--file', help='Path to nmap XML input file', dest='file', metavar='[file]', type=argparse.FileType('r'), required=True)
    parser.add_argument('-i', '--index', help='Elasticsearch index (default: nmap)', default="nmap", dest='index', metavar='[index]', action='store')
    parser.add_argument('-v', '--verbose', help='Verbose', action="store_true")
    opt_args = parser.parse_args()

    conf = yaml.safe_load(opt_args.config)
    if conf['elasticsearch']['ssl']:
       es_host = 'https://' + conf['elasticsearch']['ip']
    else:
       es_host = 'http://' + conf['elasticsearch']['ip']

    es_host += ':' + str(conf['elasticsearch']['port'])
    es_user  = conf['elasticsearch']['username']
    es_pass  = conf['elasticsearch']['password']

    xml_tree = xml.parse(opt_args.file)
    xml_root = xml_tree.getroot()
    opt_args.file.close()

    if opt_args.index:
       es_index = opt_args.index.lower()

    # build index URL
    index_URL = es_host + '/' + es_index + '/_doc'

    # ES Session
    es_session = init_ESSession(es_user,es_pass,es_host,opt_args.verbose)
    sendToEs(xml_root,es_session,index_URL,opt_args.verbose)

    print(f"[INFO]: Completed.")

if __name__ == "__main__":
        main()

