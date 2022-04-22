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
import time
import json
import argparse
import requests
import base64
import re
import yaml
from urllib.parse import urlparse

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

def prepare_ss(opt_args):
    sc_data = {}
    tool_data = {}
    sc_data['verbose'] = opt_args.verbose
    sc_data['oformat'] = opt_args.output

    output_formats = ['tab','csv','json']
    if sc_data['oformat'] not in output_formats:
       print(f"[ERROR]: Unknown output format: \"{opt_args.output}\"")
       return sys.exit(-1)

    # convert date/time to epoch or default
    stime = chk_timef(opt_args.start)
    etime = chk_timef(opt_args.end)

    # read config
    yml_conf = yaml.safe_load(opt_args.config)

    if yml_conf['elasticsearch']['ssl']:
       sc_data['es_host'] = 'https://' + yml_conf['elasticsearch']['ip']
    else:
       sc_data['es_host'] = 'http://' + yml_conf['elasticsearch']['ip']

    sc_data['es_host'] += ':' + str(yml_conf['elasticsearch']['port'])
    sc_data['es_user']  = yml_conf['elasticsearch']['username']
    sc_data['es_pass']  = yml_conf['elasticsearch']['password']

    if opt_args.tool != 'all':
       if opt_args.tool not in yml_conf['sc_tools']:
          print(f"[ERROR]: Unknown tool: \"{opt_args.tool}\".")
          return sys.exit(-1)

    sc_data['search'] = {}
    for tool in yml_conf['sc_tools']:
        tool_data[tool] = yml_conf['sc_tools'][tool]
        tool_data[tool]['_esquery']['size'] = opt_args.limit

        if tool == 'nmap':
            tool_data[tool]['_esquery']['query']['bool']['filter'] = [{"range": {"time": {"gte": stime, "lte": etime}}}]

            if opt_args.addr:
               tool_data[tool]['_esquery']['query']['bool']['must'] = [{"match": {"ip": opt_args.addr}}]

        elif tool == 'httpx':
            tool_data[tool]['_esquery']['query']['bool']['filter'].append({"range": {"time": {"gte": stime, "lte": etime}}})

            if opt_args.addr:
               tool_data[tool]['_esquery']['query']['bool']['must'].append({"match": {"ip": opt_args.addr}})

        elif tool == 'nuclei':
            tool_data[tool]['_esquery']['query']['bool']['filter'] = [{"range": {"@timestamp": {"gte": stime, "lte": etime}}}]

            if opt_args.addr:
               tool_data[tool]['_esquery']['query']['bool']['must'] = [{"match": {"event.ip": opt_args.addr}}]

    if opt_args.tool != 'all':
       sc_data['search'][opt_args.tool] = tool_data[opt_args.tool]
    else:
       for tool in yml_conf['sc_tools']:
           sc_data['search'][tool] = tool_data[tool]

    return sc_data

def print_ESdata(tool_name,data,oformat):

    if oformat == 'json':
       print(json.dumps(data))
       return 1

    for j in data:
       for k in j:
           if tool_name == 'nmap':
               if oformat == 'tab':
                  print(f"{j[k]['time']}\t{j[k]['ip']}\t{j[k]['port']}\t{j[k]['protocol']}\t{j[k]['script']}\t{j[k]['script_output']}")
               elif oformat == 'csv':
                  print(f"{j[k]['time']},{j[k]['ip']},{j[k]['port']},{j[k]['protocol']},{j[k]['script']},{j[k]['script_output']}")

           elif tool_name == 'httpx':
               if oformat == 'tab':
                  print(f"{j[k]['time']}\t{j[k]['ip']}\t{j[k]['script_output']}")
               elif oformat == 'csv':
                  print(f"{j[k]['time']},{j[k]['ip']},{j[k]['script_output']}")

           elif tool_name == 'nuclei':
               if oformat == 'tab':
                  print(f"{j[k]['@timestamp']}\t{j[k]['event']['ip']}\t{j[k]['event']['matched-at']}\t{j[k]['event']['template-id']}\t{j[k]['event']['info']['severity']}\t{j[k]['event']['info']['name']}")
               elif oformat == 'csv':
                  print(f"{j[k]['@timestamp']},{j[k]['event']['ip']},{j[k]['event']['matched-at']},{j[k]['event']['template-id']},{j[k]['event']['info']['severity']},{j[k]['event']['info']['name']}")
    return 0

def ESquery(es_conn,es_host,es_data):
    es_uri = es_host + '/' + es_data['_esindex'] + '/_search?filter_path=hits.hits._source'

    r = es_conn.post(es_uri, data=json.dumps(es_data['_esquery']), verify=False)
    if r.status_code != 200:
       print(f"[ERROR]: Response Code: [{r.status_code}]\n {r.content}\n")
       return sys.exit(-1)

    if not len(r.json()):
       return {}

    data = r.json()['hits']['hits']
    return data

# check and/or convert to epoch
def chk_timef(st):
    t = False
    os.environ['TZ'] = 'UTC'
    m1 = re.compile('[0-9]{4}/[0-9]{2}/[0-9]{2}\s[0-9]{2}:[0-9]{2}:[0-9]{2}')
    m2 = re.compile('[0-9]{4}/[0-9]{2}/[0-9]{2}')
    m3 = re.compile('(now$|now-[0-9]+(d|w|m|h|y)$)')

    if m1.match(st):
       p = '%Y/%m/%d %H:%M:%S'
       t = int(time.mktime(time.strptime(st,p)) * 1000.0)
    elif m2.match(st):
       p = '%Y/%m/%d'
       t = int(time.mktime(time.strptime(st,p)) * 1000.0)
    elif m3.match(st):
       return st
    else:
       print(f"[ERROR]: Invalid end datetime format \"{st}\" [YYYY/MM/DD HH:MM:SS || now|now-N(d|w|m|h|y)]")
       return sys.exit(-1)

    return t

def main():
    parser = argparse.ArgumentParser(description='-: Santa Search :-', epilog="View README.md for extented help.\n", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-c','--config', help='[file]\t:- Path to configuration file (santacruz.yml)', dest='config', metavar='', type=argparse.FileType('r'), required=True)
    parser.add_argument('-a','--addr',  help='[ip_addr]\t:- Search for IP address', dest='addr', metavar='', action='store')
    parser.add_argument('-l','--limit', help='[num]\t\t:- Limit number of results (default: 100)', default=100, dest='limit', metavar='', action='store', type=int)
    parser.add_argument('-o','--output', help='[format]\t:- Output format [tab,csv,json] (default: tab)', default="tab", dest='output', metavar='', action='store')
    parser.add_argument('-t','--tool', help='[name]\t:- Search for data based on tool name (default: all)', default="all", dest='tool', metavar='', action='store')
    parser.add_argument('-s','--start', help='[datetime]\t:- Search from start datetime\n\t\t\t[YYYY/MM/DD HH:MM:SS | now|now-N(d|w|m|h|y)] (default: now-24h)', default="now-24h", dest='start', metavar='', action='store')
    parser.add_argument('-e','--end', help='[datetime]\t:- Search to end datetime\n\t\t\t[YYYY/MM/DD HH:MM:SS | now|now-N(d|w|m|h|y)] (default: now)', default="now", dest='end', metavar='', action='store')
    parser.add_argument('-v','--verbose', help='\t\t:- Verbose output', action="store_true")
    opt_args = parser.parse_args()

    # parse main configuration file and options
    ss_data  = prepare_ss(opt_args)

    # ES Session
    es_session = init_ESsession(ss_data['es_user'],ss_data['es_pass'],ss_data['es_host'],ss_data['verbose'])

    for tool in ss_data['search']:
        results = ESquery(es_session,ss_data['es_host'],ss_data['search'][tool])

        if len(results):
            print_ESdata(tool,results,ss_data['oformat'])

if __name__ == "__main__":
        main()

