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

def p_results(es_idx,data,out):

    for a in data:
        d  = json.loads(json.dumps(a['_source']))
        ts    = re.sub("['T','Z']",' ',d['@timestamp']).strip()
        ip    = d['event']['ip']
        sev   = d['event']['info']['severity']
        host  = d['event']['host']
        iname = d['event']['info']['name']

        #print(json.dumps(d))
        if 'nmap_portscan' in es_idx:
                port      = d['event']['port']
                hname     = d['event']['hostname']
                proto     = d['event']['protocol']
                state     = d['event']['state']
                script    = d['event']['script']
                script_op = d['event']['script_output']

                if out =='csv':
                   print(f"{es_idx},{ts},{ip},{hname},{port},{state},{proto},{script},{script_op}")

                elif out == 'httpx':
                   so_tmp = script_op.split()
                   print(f"{so_tmp[0]}")

                else:
                   print(f"{es_idx}: {ts}\t{ip}\t{hname}\t{port}\t{state}\t{proto}\t{script}\t{script_op}")

        elif 'nmap_discovery' in es_idx:
                h_state   = d['event']['state']
                asn       = d['event']['asn']
                as_cc     = d['event']['asn_cc']
                as_handle = d['event']['asn_handle']
                as_name   = d['event']['asn_name']
                as_prefix = d['event']['asn_prefix']
                as_source = d['event']['asn_source']

                if out =='csv':
                   print(f"{es_idx},{ts},{ip},{h_state},{as_prefix},{asn},{as_handle},{as_name},{as_cc},{as_source}")

                else:
                   print(f"{es_idx}: {ts}\t{ip}\t{h_state}\t{as_prefix}\t{asn}\t{as_handle}\t{as_name}\t{as_cc}\t{as_source}")

        elif 'httpx' in es_idx:
                tlsns   = ''
                ts      = ts.split('.', 1)[0] # clean timstamp
                url     = d['event']['url']
                ws      = d['event']['webserver']
                pt      = d['event']['page_title']
                sc      = d['event']['status-code']
                as_name = d['event']['asn_name']

                if 'tls' in d['event']:
                   if 'dns_names' in d['event']['tls']:
                       if len(d['event']['tls']['dns_names']):
                           tlsns = d['event']['tls']['dns_names'][0]

                   if 'version' in d['event']['tls']:
                       tlsv = d['event']['tls']['version']

                if out =='csv':
                   print(f"{es_idx},{ts},{sev},{url},{sc}{tlsv},{ws},{tlsns},{as_name},{pt}")
                else:
                   print(f"{es_idx}: {ts}\t{sev}\t{url}\t{sc}\t{tlsv}\t{ws}\t{tlsns}\t{as_name}\t{pt}")

        elif 'nuclei' in es_idx:
                match_at = d['event']['matched-at']
                tid = d['event']['template-id']

                cve = ''
                if 'classification' in d['event']['info']:
                    if d['event']['info']['classification']['cve-id']:
                        cve = d['event']['info']['classification']['cve-id'][0]

                if out =='csv':
                   print(f"{es_idx},{ts},{sev},{iname},{match_at},{cve},{tid}")

                else:
                   print(f"{es_idx}: {ts}\t{sev}\t\t{iname}\t\t{match_at}\t{cve}")
        else:
                print(f"[ERROR]: Unknown index, ({es_idx})")
                return sys.exit(-255)

    if not out == 'httpx':
       print(f"\n")

    return 1

def do_Search(ctx):
    for idx in ctx['es_indices']:
        idx_uri = ctx['es_host'] + '/' + idx + '/_search?filter_path=hits.hits._source'
        #print(idx_uri)

        try:
            r = ctx['es_session'].post(idx_uri, data=json.dumps(ctx['es_query']), verify=False)
            if r.status_code != 200:
               print(f"[ERROR]: Response Code: [{r.status_code}]\n {r.content}\n")
               return sys.exit(-255)

        except requests.exceptions.RequestException as e:
            raise SystemExit(e)

        if len(r.json()):
           data = r.json()['hits']['hits']

           # json dump
           if ctx['oformat'] == 'json':
              print(json.dumps(data))

           else:
              p_results(idx,data,ctx['oformat'])

    return 1

def bld_ESquery(ctx):
    es_query = {
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                           {"range": {"@timestamp": {"gte": ctx['stime'], "lte": ctx['etime']}}}
                    ]
                }
            },
            "_source": {
                 "includes": [
                       # common (all)
                       "@timestamp",
                       "event.ip",
                       "event.host",
                       "event.port",
                       "event.protocol",
                       "event.info.name",
                       "event.info.severity",
                       # httpx
                       "event.url",
                       "event.status-code",
                       "event.jarm",
                       "event.method",
                       "event.page_title",
                       "event.webserver",
                       "event.tls.version",
                       "event.hashes",
                       "event.tls.dns_names",
                       # nmap port scan
                       "event.hostname",
                       "event.state",
                       "event.script",
                       "event.script_output",
                       # nuclei
                       "event.matched-at",
                       "event.matcher-name",
                       "event.template-id",
                       "event.info.classification.cve-id",
                       "event.info.classification.cvss-score",
                       # common (other)
                       "event.asn",
                       "event.asn_cc",
                       "event.asn_handle",
                       "event.asn_name",
                       "event.asn_prefix",
                       "event.asn_source",
                 ]
            },
            "size": ctx['lsize'],
            "sort": [{"@timestamp": "asc"}]
    }

    if ctx['ip_addr']:
       es_query['query']['bool']['must'] = [{"match": {"event.ip": ctx['ip_addr']}}]

    #es_query['query']['bool']['must'].append({"match": {"event.script": "httpx"}})
    #es_query['query']['bool']['filter'].append({"exists": {"field": "event.script_output"}})

    if ctx['verbose']:
       print(f"[VERBOSE]: Elasticsearch Query:  {json.dumps(es_query)}")

    #print(json.dumps(es_query))
    return es_query

def get_indexes(ctx,do_list):
    index_URI = ctx['es_host'] + '/_cat/indices?h=index&format=json'
    index_arr = []

    if ctx['verbose']:
       print(f"[VERBOSE]: Get Elasticsearch indices: {index_URI}")

    r = ctx['es_session'].get(index_URI, verify=False)
    if r.status_code != 200:
       print(f"[ERROR]: Connection failed, got {r.status_code} response!")
       return sys.exit(-255)

    idx_json = json.loads(r.text)
    if do_list:
       print(f"\nElasticsearch Index List\n----------------------------")

    for idx in idx_json:
        if not idx['index'].startswith('.'):
           index_arr.append(idx['index'])
           if do_list:
              print(f"-: {idx['index']}")

    return index_arr

def init_ESsession(ctx):
    if ctx['verbose']:
       print(f"[VERBOSE]: Connecting to Elasticsearch: {ctx['es_host']}")

    session = requests.Session()
    ctype_header = {"Content-Type": "application/json"}
    session.headers.update(ctype_header)

    if ctx['es_user']:
        userpass = ctx['es_user'] + ':' + ctx['es_pass']
        encoded_u = base64.b64encode(userpass.encode()).decode()
        auth_header = {"Authorization" : "Basic %s" % encoded_u}
        session.headers.update(auth_header)

    # ES connection
    try:
        r = session.get(ctx['es_host'], headers=session.headers, verify=False)
        if r.status_code != 200:
           print(f"[ERROR]: Connection failed, got {r.status_code} response!")
           return sys.exit(-255)

    except requests.exceptions.RequestException as e:
        raise SystemExit(e)

    return session

# Check/convert time to epoch
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
       return sys.exit(-255)

    return t

def main():
    parser = argparse.ArgumentParser(description='-: Santa Search :-', epilog="View doc/README.md for extented help.\n", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-c','--config', help='[file]\t:- Path to configuration file (santacruz.yml)', dest='config', metavar='', type=argparse.FileType('r'), required=True)
    parser.add_argument('-a','--addr',  help='[ip_addr]\t:- Search for IP address', dest='addr', metavar='', action='store')
    parser.add_argument('-i','--index', help='[index name]\t:- Get data from index name (default: all)', default="all", dest='index', metavar='', action='store')
    parser.add_argument('-s','--start', help='[datetime]\t:- Search from start datetime\n\t\t\t[YYYY/MM/DD HH:MM:SS | now|now-N(d|w|m|h|y)] (default: now-24h)', default="now-24h", dest='start', metavar='', action='store')
    parser.add_argument('-e','--end', help='[datetime]\t:- Search to end datetime\n\t\t\t[YYYY/MM/DD HH:MM:SS | now|now-N(d|w|m|h|y)] (default: now)', default="now", dest='end', metavar='', action='store')
    parser.add_argument('-n','--num', help='[num]\t\t:- Limit number of results (default: 100)', default=100, dest='num', metavar='', action='store', type=int)
    parser.add_argument('-o','--output', help='[format]\t:- Output format [tab,csv,json] (default: tab)', default="tab", dest='output', metavar='', action='store')
    parser.add_argument('-l','--list', help='[list]\t:- List Elasticsearch Indices', action='store_true')
    parser.add_argument('-v','--verbose', help='\t\t:- Verbose output', action="store_true")
    cmdargs = parser.parse_args()

    # Read config, build ctx
    ctx = {}
    ctx['verbose'] = cmdargs.verbose
    ctx['oformat'] = cmdargs.output
    ctx['stime']   = chk_timef(cmdargs.start)
    ctx['etime']   = chk_timef(cmdargs.end)
    ctx['lsize']   = cmdargs.num
    ctx['ip_addr'] = cmdargs.addr
    ctx['es_indices'] = [cmdargs.index]

    yml_conf = yaml.safe_load(cmdargs.config)
    if yml_conf['elasticsearch']['ssl']:
       ctx['es_host'] = 'https://' + yml_conf['elasticsearch']['ip']
    else:
       ctx['es_host'] = 'http://' + yml_conf['elasticsearch']['ip']

    ctx['es_host'] += ':' + str(yml_conf['elasticsearch']['port'])
    ctx['es_user']  = yml_conf['elasticsearch']['username']
    ctx['es_pass']  = yml_conf['elasticsearch']['password']
    #print(ctx)

    # ES Session
    ctx['es_session'] = init_ESsession(ctx)

    if cmdargs.index == 'all':
       ctx['es_indices'] = get_indexes(ctx,cmdargs.list)
    else:
       ctx['es_indices'] = [cmdargs.index]

    # List indices, exit
    if cmdargs.list:
       print(f"\n")
       sys.exit(1)

    ctx['es_query'] = bld_ESquery(ctx)
    do_Search(ctx)

if __name__ == "__main__":
        main()

