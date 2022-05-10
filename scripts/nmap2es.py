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
from aslookup.exceptions import LookupError
from aslookup import get_as_data
from urllib.parse import urlparse
###
#import logging
#logging.basicConfig(filename='nmap2es.log', level=logging.DEBUG)
###
# ================================================================================================================
# Original version of the parser can be found here:
#    https://raw.githubusercontent.com/ChrisRimondi/VulntoES/master/VulntoES.py
# Alt Version:
#    https://github.com/marco-lancini/docker_offensive_elk/blob/master/extensions/ingestor/VulntoES.py
# Note:
# Service detection information is not sent. (let's be honest, it's not useful and often unreliable by default)
#
# ================================================================================================================
def set_dict(name,sev,tags):
    d = {}
    d['event'] = {}
    d['event']['info']  = {}
    d['event']['meta']  = {}
    d['event']['info']['name'] = name
    d['event']['info']['tags'] = tags
    d['event']['info']['severity'] = sev

    return d

def discovery_ScanToEs(xml_root,ES_session,api_url,verbose):
    # Get time from runstats
    for r in xml_root.iter('runstats'):
        for stats in r.getchildren():
            if stats.tag == 'finished':
               scan_time = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(float(stats.attrib['time'])))

    for h in xml_root.iter('host'):
       es_data = set_dict('Nmap Discovery Scan','info',['nmap','discovery','network'])
       es_data['@timestamp'] = scan_time

       if h.tag == 'host':
          for host in h.getchildren():

              if host.tag == 'address':
                 if host.attrib['addr']:
                    es_data['event']['ip'] = host.attrib['addr']
                    es_data['event']['host'] = host.attrib['addr']
                    es_data['event']['meta']['hostname'] = ''

              elif host.tag == 'status':
                   es_data['event']['state'] = host.attrib['state']

       # Only send document to ES if the host is up
       if es_data['event']['state'] == 'up':
          as_data = asLookup(es_data['event']['ip'])
          es_data['event'] = merge_two_dicts(es_data['event'], as_data)

          # Gererate a uniq index ID (prevent duplicate documents with the same timestamps)
          # https://www.elastic.co/blog/efficient-duplicate-prevention-for-event-based-data-in-elasticsearch
          # https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html
          index_uuid = uuid_from_string(json.dumps(es_data))
          document_url = api_url + "/" + index_uuid + "?op_type=create"
          print(f"[INFO]: ES create: {document_url}")

          if verbose:
             print(f"[VERBOSE]: {document_url}:\n[VERBOSE]: {json.dumps(es_data)}")

          r = ES_session.put(document_url, data=json.dumps(es_data), verify=False)
          if r.status_code == 409:
             print(f"\033[33m[WARN]: Document UUID: {index_uuid} already exists\033[0m\n{json.dumps(es_data)}")

          if verbose:
             print(f"[VERBOSE]: Response Code: [{r.status_code}]\n[VERBOSE]: {r.content}\n")

          #print(es_data)
          #sys.exit()

def port_ScanToEs(xml_root,ES_session,api_url,verbose):
    for h in xml_root.iter('host'):
       es_data = set_dict('Nmap Port Scan','info',['nmap','portscan','network'])

       if h.tag == 'host':
           if 'endtime' in h.attrib and h.attrib['endtime']:
               es_data['@timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(float(h.attrib['endtime'])))

       for c in h:
           if c.tag == 'address':
              if c.attrib['addr']:
                 es_data['event']['ip'] = c.attrib['addr']
                 es_data['event']['host'] = c.attrib['addr']

           elif c.tag == 'hostnames':
               for names in c.getchildren():
                   if names.attrib['name']:
                       es_data['event']['meta']['hostname'] = names.attrib['name']
                       es_data['event']['hostname'] = names.attrib['name']

           elif c.tag == 'ports':
               for port in c.getchildren():
                   if port.tag == 'port':
                       es_data['event']['port'] = port.attrib['portid']
                       es_data['event']['protocol'] = port.attrib['protocol']
                       es_data['event']['script'] = ''
                       es_data['event']['script_output'] = ''

                       for p in port.getchildren():
                           if p.tag == 'state':
                               es_data['event']['state'] = p.attrib['state']

                           elif p.tag == 'script':
                               if p.attrib['id']:
                                  if p.attrib['output']:
                                     es_data['event']['script'] = p.attrib['id']

                                     s  = p.attrib['output'].replace('\n','')
                                     es_data['event']['script_output'] = re.sub('\\\\x00', '', s)

                       if es_data['event']['state'] == 'open':
                          ## fill in some empty values
                          if not 'hostname' in es_data['event']:
                             es_data['event']['hostname'] = "unknwon"

                          if not 'hostname' in es_data['event']['meta']:
                             es_data['event']['meta']['hostname'] = "unknwon"

                          # Gererate a uniq index ID (prevent duplicate documents with the same timestamps)
                          # https://www.elastic.co/blog/efficient-duplicate-prevention-for-event-based-data-in-elasticsearch
                          # https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html
                          index_uuid = uuid_from_string(json.dumps(es_data))
                          document_url = api_url + "/" + index_uuid + "?op_type=create"
                          print(f"[INFO]: ES create: {document_url}")

                          if verbose:
                             print(f"[VERBOSE]: {document_url}:\n[VERBOSE]: {json.dumps(es_data)}")

                          # Only send document to ES if the port is open
                          r = ES_session.put(document_url, data=json.dumps(es_data), verify=False)
                          if r.status_code == 409:
                             print(f"\033[33m[WARN]: Document UUID: {index_uuid} already exists\033[0m\n{json.dumps(es_data)}")

                          if verbose:
                             print(f"[VERBOSE]: Response Code: [{r.status_code}]\n[VERBOSE]: {r.content}\n")

def merge_two_dicts(x, y):
    z = x.copy()   # start with x's keys and values
    z.update(y)    # modifies z with y's keys and values & returns None
    return z

def uuid_from_string(string):
    md5_hash = hashlib.md5()
    md5_hash.update(string.encode("utf-8"))
    md5_hex_str = md5_hash.hexdigest()

    return str(uuid.UUID(md5_hex_str))

def asLookup(ip_addr):
    # Defaults
    d = {}
    d['asn_cc']      = ''
    d['asn']         = ''
    d['asn_prefix']  = ''
    d['asn_handle']  = ''
    d['asn_name']    = ''
    d['asn_source']  = ''

    services = ['cymru','shadowserver']
    for svc in services:
        try:
           obj = get_as_data(ip_addr, svc)

           d['asn_cc']      = obj.cc
           d['asn']         = obj.asn
           d['asn_prefix']  = obj.prefix
           d['asn_handle']  = obj.handle
           d['asn_name']    = re.sub('[,]', '', obj.as_name)
           d['asn_source']  = obj.data_source

           return d

        except LookupError as e:
           #print('%-15s  %s' % (addr, e))
           continue

    return d

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

    try: # ES connection
        r = session.get(api_URL, headers=session.headers, verify=False)
        if r.status_code != 200:
           print(f"[ERROR]: Connection failed, got {r.status_code} response!")
           return sys.exit(-1)

    except requests.exceptions.RequestException as e:
        raise SystemExit(e)

    return session

def main():
    parser = argparse.ArgumentParser(description='Import nmap XML output into Elasticsearch')
    parser.add_argument('-c','--config', help='[file]\t:- Path to configuration file (santacruz.yml)', dest='config', metavar='', type=argparse.FileType('r'), required=True)
    parser.add_argument('-f','--file', help='[file]\t:- Path to Nmap XML report file', dest='file', metavar='', type=argparse.FileType('r'), required=True)
    parser.add_argument('-t','--type', help='[report type]\t:- Nmap report type [portscan|discovery]', dest='type', metavar='', required=True)
    parser.add_argument('-v','--verbose', help='\t\t:- Verbose output', action='store_true')

    opt_args = parser.parse_args()
    scan_type = opt_args.type.strip()

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

    # Build index URL
    index_URL = es_host + '/nmap_' + scan_type + '/_doc'

    # ES Session
    es_session = init_ESSession(es_user,es_pass,es_host,opt_args.verbose)

    if scan_type == 'portscan':
       port_ScanToEs(xml_root,es_session,index_URL,opt_args.verbose)

    elif scan_type == 'discovery':
       discovery_ScanToEs(xml_root,es_session,index_URL,opt_args.verbose)

    else:
      print(f"[ERROR]: Unknown nmap scan type, {opt_args.type}")
      return -255

    print(f"[INFO]: Completed.")

if __name__ == "__main__":
        main()

