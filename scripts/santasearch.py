#!/usr/bin/env python3
# ========================================================================================
# Sanata Search
#
# Retrieve ES data based on tool (nmap,httpx,nuclei, etc..)
# See: conf/santacruz.yml
# View README.md for additional information
#
# [/csh:]> date "+%D"
# 04/17/22
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
from urllib.parse import urlparse

# nuclei
def nuclei_bldq(es_host,ip_addr,stime,etime,slimit):
    _dict = {}
    _dict['_uri'] = es_host + '/nuclei/_search?filter_path=hits.hits._source'

    _dict['_search'] = {
              "query": {
                   "bool": {
                      "must": [],
                      "filter": [{"range": {"@timestamp": {"gte": stime, "lte": etime}}}]
                   }
              },
              "_source": {
                  "includes": ["@timestamp", "event.ip", "event.info.severity",
                                 "event.info.name", "event.matched-at", "event.template-id",
                                 "event.info.classification.cvss-score", "event.info.description"]
             },
             "sort": [{ "@timestamp": "asc" }],
             "size": slimit
      }

    if ip_addr:
       match_ip = {"match": {"event.ip": ip_addr}}
       _dict['_search']['query']['bool']['must'].append(match_ip)

    return _dict

# nmap
def nmap_bldq(es_host,ip_addr,stime,etime,slimit):
    _dict = {}
    _dict['_uri'] = es_host + '/nmap/_search?filter_path=hits.hits._source'

    _dict['_search'] = {
              "query": {
                   "bool": {
                      "must": [],
                      "filter": [{"range": {"time": {"gte": stime, "lte": etime}}}]
                   }
              },
              "_source": {
                  "includes": ["time","ip","port","protocol","script","script_output"]
             },
             "sort": [{ "time": "asc" }],
             "size": slimit
      }

    if ip_addr:
       match_ip = {"match": {"ip": ip_addr}}
       _dict['_search']['query']['bool']['must'].append(match_ip)

    return _dict

#-----------------------------
# httpx is called from nmap nse (httpx.nse)
# aggregation note:
#-----------------------------
# "aggs": {
#    "script_output": {
#      "terms": {
#        "field": "script_output.keyword"
#      }
#    }
#  },
def httpx_bldq(es_host,ip_addr,stime,etime,slimit):
    _dict = {}
    _dict['_uri'] = es_host + '/nmap/_search?filter_path=hits.hits._source'

    _dict['_search'] = {
              "query": {
                   "bool": {
                      "must": [{"match": {"script": "httpx"}}],
                      "filter": [
                          {"exists": {"field": "script_output"}},
                          {"range": {"time": {"gte": stime, "lte": etime}}}
                      ]
                   }
              },
              "_source": {
                  "includes": ["time","script","script_output"]
             },
             "sort": [{ "time": "asc" }],
             "size": slimit
      }

    if ip_addr:
       match_ip = {"match": {"ip": ip_addr}}
       _dict['_search']['query']['bool']['must'].append(match_ip)

    return _dict

def get_indexes(es_session,es_host,verbose):
    index_URI = es_host + '/_cat/indices?h=index&format=json'
    index_arr = []

    r = es_session.get(index_URI, verify=False)
    if r.status_code != 200:
       print(f"[ERROR]: Connection failed, got {r.status_code} response!")
       return sys.exit(-1)

    idx_json = json.loads(r.text)
    for idx in idx_json:
        if not idx['index'].startswith('.'):
           index_arr.append(idx['index'])

    return index_arr

def init_ESsession(user,passwd,api_URL,verbose):
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

    # ES connection
    r = session.get(api_URL, headers=session.headers, verify=False)
    if r.status_code != 200:
       print(f"[ERROR]: Connection failed, got {r.status_code} response!")
       return sys.exit(-1)

    return session

def init_sc(args):
    opts = {}
    opts['verbose'] = args.verbose

    conf = yaml.safe_load(args.config)
    if conf['elasticsearch']['ssl']:
       opts['es_host'] = 'https://' + conf['elasticsearch']['ip']
    else:
       opts['es_host'] = 'http://' + conf['elasticsearch']['ip']

    opts['es_host'] += ':' + str(conf['elasticsearch']['port'])
    opts['es_user']  = conf['elasticsearch']['username']
    opts['es_pass']  = conf['elasticsearch']['password']

    # ES Session
    opts['es_session'] = init_ESsession(opts['es_user'],opts['es_pass'],opts['es_host'],opts['verbose'])

    if args.tool != 'all':
       if args.tool not in conf['tool_list']:
          print(f"[ERROR]: Unknown tool: \"{args.tool}\", check {args.config.name}")
          return sys.exit(-1)

    # Index uri based on configured tools
    opts['tool']      = args.tool
    opts['tool_list'] = conf['tool_list']

    for tool in opts['tool_list']:
        if tool == 'nmap':
           opts['nmap'] = nmap_bldq(opts['es_host'],args.addr,args.start,args.end,args.limit)

        elif tool == 'httpx':
           opts['httpx'] = httpx_bldq(opts['es_host'],args.addr,args.start,args.end,args.limit)

        elif tool == 'nuclei':
           opts['nuclei'] = nuclei_bldq(opts['es_host'],args.addr,args.start,args.end,args.limit)

    if args.output not in conf['output_fomats']:
       print(f"[ERROR]: Unknown output format: \"{args.output}\", check {args.config.name}")
       return sys.exit(-1)

    opts['oformat'] = args.output

    return opts

def es_nmap(ss):
    r = ss['es_session'].post(ss['nmap']['_uri'], data=json.dumps(ss['nmap']['_search']), verify=False)
    if r.status_code != 200:
       print(f"[ERROR]: Response Code: [{r.status_code}]\n {r.content}\n")
       return sys.exit(-1)

    if not len(r.json()):
       print(f"Num Results: 0")
       return 0

    #print(r.json()['hits']['hits'])
    data = r.json()['hits']['hits']

    if ss['oformat'] == 'json':
       print(json.dumps(data))
       return data

    print(f"\n")
    for j in data:
       for k in j:
          if ss['oformat'] == 'tab':
             print(f"{j[k]['time']}\t{j[k]['ip']}\t{j[k]['port']}\t{j[k]['protocol']}\t{j[k]['script']}\t{j[k]['script_output']}")

          elif ss['oformat'] == 'csv':
             print(f"{j[k]['time']},{j[k]['ip']},{j[k]['port']},{j[k]['protocol']},{j[k]['script']},{j[k]['script_output']}")

    print(f"\n")
    return data

def es_httpx(ss):
    r = ss['es_session'].post(ss['httpx']['_uri'], data=json.dumps(ss['httpx']['_search']), verify=False)
    if r.status_code != 200:
       print(f"[ERROR]: Response Code: [{r.status_code}]\n {r.content}\n")
       return sys.exit(-1)

    if not len(r.json()):
       print(f"Num Results: 0")
       return 0

    #print(r.json()['hits']['hits'])
    data = r.json()['hits']['hits']

    if ss['oformat'] == 'json':
       print(json.dumps(data))
       return data

    print(f"\n")
    for j in data:
       for k in j:
          if ss['oformat'] == 'tab':
             print(f"{j[k]['time']}\t{j[k]['script']}\t{j[k]['script_output']}")

          elif ss['oformat'] == 'csv':
             print(f"{j[k]['time']},{j[k]['script']},{j[k]['script_output']}")

    print(f"\n")
    return data

def es_nuclei(ss):

    r = ss['es_session'].post(ss['nuclei']['_uri'], data=json.dumps(ss['nuclei']['_search']), verify=False)
    if r.status_code != 200:
       print(f"[ERROR]: Response Code: [{r.status_code}]\n {r.content}\n")
       return sys.exit(-1)

    if not len(r.json()):
       print(f"Num Results: 0")
       return 0

    #print(r.json()['hits']['hits'])
    data = r.json()['hits']['hits']

    if ss['oformat'] == 'json':
       print(json.dumps(data))
       return data

    print(f"\n")
    for j in data:
       for k in j:
          if ss['oformat'] == 'tab':
             print(f"{j[k]['@timestamp']}\t{j[k]['event']['ip']}\t{j[k]['event']['matched-at']}\t{j[k]['event']['template-id']}\t{j[k]['event']['info']['severity']}\t{j[k]['event']['info']['name']}")

          elif ss['oformat'] == 'csv':
             print(f"{j[k]['@timestamp']},{j[k]['event']['ip']},{j[k]['event']['matched-at']},{j[k]['event']['template-id']},{j[k]['event']['info']['severity']},{j[k]['event']['info']['name']}")

    print(f"\n")
    return data

def main():
    parser = argparse.ArgumentParser(description='-: Santa Search :-', epilog="View README.md for extented help.\n", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-c', '--config', help='Path to santacruz.yml configuration file', dest='config', metavar='[file]', type=argparse.FileType('r'), required=True)
    parser.add_argument('-a', '--addr',  help='Search for IP address', dest='addr', metavar='[ip address]', action='store')
    parser.add_argument('-s', '--start', help='Search from start time (default: now-24h)', default="now-24h", dest='start', metavar='[date]', action='store')
    parser.add_argument('-e', '--end',   help='Search to end time (default: now)', default="now", dest='end', metavar='[date]', action='store')
    parser.add_argument('-l', '--limit', help='Limit number of results (default: 100)', default=100, dest='limit', metavar='[limit]', action='store', type=int)
    parser.add_argument('-o', '--output', help='Output format (default: tab)', default="tab", dest='output', metavar='[format]', action='store')
    parser.add_argument('-t', '--tool', help='Search for data based on tool name (default: all)', default="all", dest='tool', metavar='[name]', action='store')
    parser.add_argument('-v', '--verbose', help='Verbose output', action="store_true")

    opt_args = parser.parse_args()
    sc_session = init_sc(opt_args)

    if sc_session['tool'] == 'nmap':
       es_nmap(sc_session)

    elif sc_session['tool'] == 'httpx':
       es_httpx(sc_session)

    elif sc_session['tool'] == 'nuclei':
       es_nuclei(sc_session)

    elif sc_session['tool'] == 'all':
       es_nmap(sc_session)
       es_httpx(sc_session)
       es_nuclei(sc_session)


if __name__ == "__main__":
        main()

