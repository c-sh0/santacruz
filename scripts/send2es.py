#!/usr/bin/env python3
# ========================================================================================
# Read scan logs, send to ES
#
# [/csh:]> date "+%D"
# 04/11/22
# https://github.com/c-sh0
#
# nmap has yet to add a json output feature
# https://github.com/nmap/nmap/issues/635
#-------------
# notes
#-------------
# nmap:
# * Other nmap -> ES parser versions:
#    - https://raw.githubusercontent.com/ChrisRimondi/VulntoES/master/VulntoES.py
#    - https://github.com/marco-lancini/docker_offensive_elk/blob/master/extensions/ingestor/VulntoES.py
# * Default service detection information is not sent. (it's not useful and often wrong)
# ========================================================================================
import os
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
def es_dict(name,desc,sev,tags):
    d = {}
    d['@timestamp']  = ''
    d['ip']          = ''
    d['host']        = ''
    d['asn_cc']      = ''
    d['asn']         = ''
    d['asn_prefix']  = ''
    d['asn_handle']  = ''
    d['asn_name']    = ''
    d['asn_source']  = ''

    d['meta'] = {}
    d['meta']['name'] = name
    d['meta']['tags'] = tags
    d['meta']['description'] = desc

    d['info'] = {}
    d['info']['severity'] = sev

    return d

def send2ES(es_session,es_url,data,verbose):
    # Gererate a uniq index ID (prevent duplicate documents with the same timestamps)
    # https://www.elastic.co/blog/efficient-duplicate-prevention-for-event-based-data-in-elasticsearch
    # https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html
    index_uuid = uuid_from_string(json.dumps(data))
    document_url = es_url + '/_doc/' + index_uuid + '?op_type=create'

    print(f"[INFO]: ES create: {document_url}")

    if verbose:
       print(f"[VERBOSE]: {document_url}:\n[VERBOSE]: {json.dumps(data)}")

    r = es_session.put(document_url, data=json.dumps(data), verify=False)
    if r.status_code == 409:
       print(f"\033[33m[WARN]: Document UUID: {index_uuid} already exists\033[0m")

    if verbose:
       print(f"[VERBOSE]: Response Code: [{r.status_code}]\n[VERBOSE]: {r.content}\n")

    return 1

def discovery_ScanToEs(xml_root,es_session,es_url,verbose):
    # get date/time from runstats
    for r in xml_root.iter('runstats'):
        for stats in r.getchildren():
            if stats.tag == 'finished':
               scan_time = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(float(stats.attrib['time'])))

               # ES index (by date)
               idx_date = time.strftime('%Y%m%d', time.gmtime(float(stats.attrib['time'])))
               idx_url  = es_url + '/nmap_discovery_' + idx_date

    # read file data
    for h in xml_root.iter('host'):
       es_data = es_dict('nmap','Nmap Discovery Scan','info',['nmap','discovery','network'])
       es_data['@timestamp'] = scan_time

       # host data
       if h.tag == 'host':
          for host in h.getchildren():

              if host.tag == 'address':
                 if host.attrib['addr']:
                    es_data['ip'] = host.attrib['addr']

              elif host.tag == 'hostnames':
                 for names in host.getchildren():
                    if names.attrib['name']:
                       es_data['host'] = names.attrib['name']

              elif host.tag == 'status':
                   es_data['info']['state'] = host.attrib['state']

       # send data to ES only if the host is "up"
       if es_data['info']['state'] == 'up':
          # lookup/add ASN info
          as_data = asn_lookup(es_data['ip'])
          if len(as_data):
             es_data = merge_two_dicts(es_data, as_data)

          send2ES(es_session,idx_url,es_data,verbose)

    return 1


def port_ScanToEs(xml_root,es_session,es_url,verbose):
    # read file data
    for h in xml_root.iter('host'):
       es_data = es_dict('nmap','Nmap Port Scan','info',['nmap','portscan','network'])

       if h.tag == 'host':
           # ES index, get date/time from scan 'endtime'
           if 'endtime' in h.attrib and h.attrib['endtime']:
               es_data['@timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(float(h.attrib['endtime'])))
               idx_date = time.strftime('%Y%m%d', time.gmtime(float(h.attrib['endtime'])))
               idx_url  = es_url + '/nmap_portscan_' + idx_date

       for c in h:
           if c.tag == 'address':
              if c.attrib['addr']:
                 es_data['ip'] = c.attrib['addr']

           elif c.tag == 'hostnames':
               for names in c.getchildren():
                   if names.attrib['name']:
                       es_data['host'] = names.attrib['name']

           elif c.tag == 'ports':
               for port in c.getchildren():
                   if port.tag == 'port':
                       es_data['info']['port'] = port.attrib['portid']
                       es_data['info']['protocol'] = port.attrib['protocol']
                       es_data['info']['script'] = ''
                       es_data['info']['script_output'] = ''

                       for p in port.getchildren():
                           if p.tag == 'state':
                               es_data['info']['state'] = p.attrib['state']

                           # save any nse script output
                           elif p.tag == 'script':
                               if p.attrib['id']:
                                  if p.attrib['output']:
                                     es_data['info']['script'] = p.attrib['id']

                                     # clean up script output
                                     s0  = p.attrib['output'].replace('\n','')
                                     s1  = re.sub('\\\\x00', '', s0)
                                     s2  = s1.replace('[]','').lstrip()
                                     es_data['info']['script_output'] = re.sub(' +',' ',s2)

                       # only send document to ES if the port is open
                       if es_data['info']['state'] == 'open':

                          # grab ASN info from ES, nmap discovery scan
                          as_data = asn_ESlookup(es_data['ip'],es_url,es_session,verbose)
                          if(len(as_data)):
                             es_data = merge_two_dicts(es_data,as_data)

                          # send to ES
                          send2ES(es_session,idx_url,es_data,verbose)
    return 1

def nuclei_ScanToEs(json_data,es_session,es_url,verbose):
    # read file
    for jsonl in json_data:
        es_data  = es_dict('nuclei','Nuclei Scanner','info',['nuclei','vulnerability','discovery','network'])
        data     = json.loads(jsonl)

        # ES index (by date)
        idx_date = data['timestamp'].split('T')[0].replace('-','')
        idx_url  = es_url + '/nuclei_' + idx_date

        es_data['@timestamp']   = data['timestamp']
        es_data['info']         = data['info']
        es_data['info']['host']        = data['host']
        es_data['info']['matched-at']  = data['matched-at']
        es_data['info']['template-id'] = data['template-id']

        # make sure the ip address is set, if not, bail and dump
        if not 'ip' in data.keys():
            ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}',data['host'])
            if not len(ip):
               print(f"[FATAL]: nuclei_ScanToEs(), Cannot find an ip address!")
               print(f"json_str:\n{jsonl}")
               sys.exit()
            else:
               es_data['ip'] = ip[0]
        else:
            es_data['ip'] = data['ip']

        # grab ASN info from ES, nmap discovery scan
        as_data = asn_ESlookup(es_data['ip'],es_url,es_session,verbose)
        if(len(as_data)):
           es_data = merge_two_dicts(es_data,as_data)

        # move curl-command into 'info'
        es_data['info']['curl-command'] = ''
        if 'curl-command' in data.keys():
            es_data['info']['curl-command'] = data['curl-command']

        # move extracted-results into 'info'
        es_data['info']['extracted-results'] = ''
        if 'extracted-results' in data.keys():
            es_data['info']['extracted-results'] = data['extracted-results']

        # move matched-line into 'info'
        es_data['info']['matched-line'] = ''
        if 'matched-line' in data.keys():
            es_data['info']['matched-line'] = data['matched-line']

        # make sure a description is set
        if not 'description' in es_data['info'].keys():
            es_data['info']['description'] = data['info']['name']

        # no need to store template author's
        del es_data['info']['author']

        # send to ES
        send2ES(es_session,idx_url,es_data,verbose)

    return 1

def httpx_ScanToEs(json_data,es_session,es_url,verbose):
    # read file
    for jsonl in json_data:
        es_data  = es_dict('httpx','Httpx Discovery Scan','info',['httpx','discovery','network'])
        data     = json.loads(jsonl)

        # ES index (by date)
        idx_date = data['timestamp'].split('T')[0].replace('-','')
        idx_url  = es_url + '/httpx_' + idx_date

        es_data['@timestamp'] = data['timestamp']
        es_data['ip']         = data['host']
        es_data['info']['protocol'] = 'tcp'
        es_data['info']['method']   = data['method']
        es_data['info']['scheme']   = data['scheme']
        es_data['info']['port']  = data['port']
        es_data['info']['path']  = data['path']
        es_data['info']['url']   = data['url']
        es_data['info']['status-code'] = data['status-code']

        # not sure why httpx is not returning asn info for some ip's
        # seems if there is two ASN records returned, it fails? cymru?
        if 'asn' in data.keys():
           es_data['asn']        = data['asn']['as-number'].replace('AS','')
           es_data['asn_cc']     = data['asn']['as-country']
           es_data['asn_name']   = data['asn']['as-name']
           es_data['asn_handle'] = data['asn']['as-number']
           es_data['asn_prefix'] = data['asn']['as-range']
        else:
          # grab ASN info from ES, nmap discovery scan
          as_data = asn_ESlookup(es_data['ip'],es_url,es_session,verbose)
          if(len(as_data)):
             es_data = merge_two_dicts(es_data,as_data)

        # move tls data into 'info'
        es_data['info']['tls'] = {}
        if 'tls-grab' in data.keys():
            es_data['info']['tls'] = data['tls-grab']

        # move technologies data into 'info'
        es_data['info']['technologies'] = []
        if 'technologies' in data.keys():
            es_data['info']['technologies'] = data['technologies']

        # move page title into 'info'
        es_data['info']['page_title'] = ''
        if 'title' in data.keys():
            es_data['info']['page_title'] = data['title']

        # move webserver data into 'info'
        es_data['info']['webserver'] = ''
        if 'webserver' in data.keys():
            es_data['info']['webserver'] = data['webserver']

        # move hash data into 'info'
        es_data['info']['hashes'] = {}
        if 'hashes' in data.keys():
            es_data['info']['hashes'] = data['hashes']

        # move jarm into 'info'
        es_data['info']['jarm'] = ''
        if 'jarm' in data.keys():
            es_data['info']['jarm'] = data['jarm']

        # send to ES
        send2ES(es_session,idx_url,es_data,verbose)

    return 1

def merge_two_dicts(x, y):
    z = x.copy()   # start with x's keys and values
    z.update(y)    # modifies z with y's keys and values & returns None
    return z

def uuid_from_string(string):
    md5_hash = hashlib.md5()
    md5_hash.update(string.encode("utf-8"))
    md5_hex_str = md5_hash.hexdigest()

    return str(uuid.UUID(md5_hex_str))

# do asn lookup
def asn_lookup(ip_addr,verbose):
    d = {}
    services = ['cymru','shadowserver']

    for svc in services:
        try:
           obj = get_as_data(ip_addr, svc)

           d['asn_cc']      = obj.cc
           d['asn']         = obj.asn
           d['asn_prefix']  = obj.prefix
           d['asn_handle']  = obj.handle
           d['asn_name']    = obj.as_name.replace(',','').lstrip()
           d['asn_source']  = obj.data_source

           return d

        except LookupError as e:
           continue

    return d

# do asn ES lookup (namp_discovery_* index)
def asn_ESlookup(ip_addr,es_url,es_session,verbose):
    # wildcard search, get data from last 24h
    idx_uri = es_url + '/nmap_discovery_*/_search?filter_path=hits.hits._source'

    # json query
    es_query = {
            "query": {
                "bool": {
                    "must": [{"match": {"ip": ip_addr}}],
                    "filter": [
                           {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}}
                    ]
                }
            },
            "_source": {
                 "includes": [
                       "host",
                       "asn",
                       "asn_cc",
                       "asn_handle",
                       "asn_name",
                       "asn_prefix",
                       "asn_source",
                 ]
            },
            "size": 1,
            "sort": [{"@timestamp": "desc"}]
    }

    if verbose:
       print(f"[VERBOSE]: Query URI:  {idx_uri}")
       print(f"[VERBOSE]: Elasticsearch Query:  {json.dumps(es_query)}")

    # request
    try:
       r = es_session.post(idx_uri, data=json.dumps(es_query), verify=False)
       if r.status_code != 200:
          print(f"[ERROR]: Response Code: [{r.status_code}]\n {r.content}\n")
          return sys.exit(-255)

    except requests.exceptions.RequestException as e:
          raise SystemExit(e)

    # format, return results
    asn_data = {}
    if len(r.json()):
       asn_data = r.json()['hits']['hits'][0]['_source']
       return asn_data
    else:
       # fallback: lookup/add ASN info
       asn_data = asn_lookup(ip_addr,verbose)
       if len(asn_data):
          return asn_data

    return 0

def init_ESSession(user,passwd,api_URL,verbose):
    if verbose:
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
    parser = argparse.ArgumentParser(description='Send scan logs to Elasticsearch')
    parser.add_argument('-c','--config', help='[file]\t:- Path to ES configuration yml file', dest='config', metavar='', type=argparse.FileType('r'), required=True)
    parser.add_argument('-f','--file', help='[file]\t:- Path to log file', dest='file', metavar='', type=argparse.FileType('r'), required=True)
    parser.add_argument('-t','--type', help='[report type]\t:- Scan type [portscan|discovery|httpx|nuclei]', dest='type', metavar='', required=True)
    parser.add_argument('-v','--verbose', help='\t\t:- Verbose output', action='store_true')
    opt_args = parser.parse_args()

    # read ES configuration
    conf = yaml.safe_load(opt_args.config)
    if conf['elasticsearch']['ssl']:
        es_host = 'https://' + conf['elasticsearch']['ip']
    else:
        es_host = 'http://' + conf['elasticsearch']['ip']

    es_host += ':' + str(conf['elasticsearch']['port'])
    es_user  = conf['elasticsearch']['username']
    es_pass  = conf['elasticsearch']['password']

    # ES session
    es_session = init_ESSession(es_user,es_pass,es_host,opt_args.verbose)

    # read data, determine file type by extention
    f_info = os.path.splitext(opt_args.file.name)
    f_ext  = f_info[1].replace('.','')

    if f_ext == 'json':
        scan_data = opt_args.file.readlines()

    elif f_ext == 'xml':
        xml_tree  = xml.parse(opt_args.file)
        scan_data = xml_tree.getroot()

    else:
        print(f"[ERROR]: file type not supported: {f_ext}")
        return -255

    # close fh
    opt_args.file.close()

    # send data to ES
    if opt_args.type == 'discovery':
        discovery_ScanToEs(scan_data,es_session,es_host,opt_args.verbose)

    elif opt_args.type == 'portscan':
        port_ScanToEs(scan_data,es_session,es_host,opt_args.verbose)

    elif opt_args.type == 'httpx':
        httpx_ScanToEs(scan_data,es_session,es_host,opt_args.verbose)

    elif opt_args.type == 'nuclei':
        nuclei_ScanToEs(scan_data,es_session,es_host,opt_args.verbose)

    else:
        print(f"[ERROR]: unknown scan type, {opt_args.type}")
        return -255

    print(f"[INFO]: {opt_args.type}: import completed.")

    return 1

if __name__ == "__main__":
        main()
