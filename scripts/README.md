# Scripts
Helper scripts

| Name  | Description|
| :------------- | :------------- |
| nmap2es.py  | Read nmap XML output, convert to json, and send to Elasticsearch |
| santasearch.py  | Retrieves Elasticsearch data based on tool (nmap, httpx, nuclei, etc..) |

## nmap2es.py
A simple script that will convert Nmap's XML scan results into json and then forwards that data into Elasticsearch
```yaml
usage: nmap2es.py [-h] -c [config] -f [file] [-i [index]] [-v]
optional arguments:
-h, --help             :- Show this help message and exit
-c, --config [config]  :- Path to configuration file (santacruz.yml)
-f, --file   [file]    :- Path to nmap XML input file
-i, --index  [index]   :- Elasticsearch index (default: nmap)
-v, --verbose          :- Verbose output
```

## santasearch.py
A simple script to retrieve tool output data from Elasticsearch. Useful for reporting and/or importing data into other tools.
```yaml
usage: santasearch.py [-h] -c  [-a] [-l] [-o] [-t] [-s] [-e] [-v]
optional arguments:
  -h, --help      show this help message and exit
  -c , --config   [file]        :- Path to configuration file (santacruz.yml)
  -a , --addr     [ip_addr]     :- Search for IP address
  -l , --limit    [num]         :- Limit number of results (default: 100)
  -o , --output   [format]      :- Output format [tab,csv,json] (default: tab)
  -t , --tool     [name]        :- Search for data based on tool name (default: all)
  -s , --start    [datetime]    :- Search from start datetime
                                   [YYYY/MM/DD HH:MM:SS | now|now-N(d|w|m|h|y)] (default: now-24h)
  -e , --end      [datetime]    :- Search to end datetime
                                   [YYYY/MM/DD HH:MM:SS | now|now-N(d|w|m|h|y)] (default: now)
  -v, --verbose                 :- Verbose output
```

