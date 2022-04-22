# Santacruz
Elasticsearch and Kibana setup for Penetration testing and reconnaissance.

## Description
Having to write custom shell scripts to parse and keep track of all the data from many different security tools is time consuming and often results in a mountain of text files. Other solutions to this problem often include yet more tools as well as features i'll never use nor care about. I needed something simple, lightweight, customisable, and easy to deploy without all the bloat.

# Getting Started
1. Clone<br> 
   ```git clone https://github.com/c-sh0/santacruz.git```

2. Increase virtual memory for Elasticsearch<br>
   ```sysctl -w vm.max_map_count=262144```<br>
   ```echo 'vm.max_map_count=262144' >> /etc/sysctl.conf```

3. Setup the persistent storage volumes. Permissions need to match the elasticsearch and kibana container users, 1000:1000)<br>
   ```mkdir -p ./data/elasticsearch ./data/kibana```<br>
   ```chown 1000:1000 ./data/elasticsearch ./data/kibana```

## Start Elasticsearch and Kibana containers
The easiest approach when settings passwords is by following the steps below otherwise, your going to end up mucking with the containers and/or composer files later. https://www.elastic.co/guide/en/elasticsearch/reference/current/built-in-users.html  
1. Start Elasticsearch container (&& watch logs to make sure it starts)<br>
   ```docker-compose up -d elasticsearch && docker logs elasticsearch --follow```

2. Change the default passwords for all built-in users, make note of the output.<br>
   ```docker exec elasticsearch /bin/bash -c "bin/elasticsearch-setup-passwords auto --batch"```
   
3. Update the Kibana and Santacruz configuration files with generated password from #2<br>
   ```conf/kibana.yml```<br>
   ```conf/santacruz.yml```

4. Start Kibana container. It will take a min or two to fully start (&& watch logs to make sure it starts)<br>
   ```docker-compose up -d kibana && docker logs kibana --follow```

5. Login into the Kibana dashboard (user: elastic, password from #2)<br>
   ```http://your.ip:5601/```

6. (Optional) Add additional users: **Stack Management** -> **Users**

## Sending data to Elasticsearch

## Nmap
Nmap doesn't support output in json format (Shame!). The log will need to be converted before being sent to Elasticsearch. Run nmap with the `-oX` to save the ouput in XML format and then Import scan data into Elasticsearch using `nmap2es.py` *See: <a href="scripts/README.md" target="_blank">scripts/README.md</a> for more information*
   ```sh
      nmap --open -oX data/nmap/nmap_scan.xml <target>
      nmap2es.py -c conf/santacruz.yml -f data/nmap/nmap_scan.xml
   ```
   
## Nmap + Httpx
Httpx is a great tool for determining if a port is running http(s). Using nmap + `httpx.nse` can save you an extra step during the reconnaissance phase. The script will run httpx on any open tcp ports discovered during the scan. (`nmap2es.py` supports nmap script output)
   ```sh
      nmap --open -script=nmap_nse/httpx.nse --script-args httpx_bin=/path/to/httpx -oX data/nmap/nmap_scan.xml <target>
      nmap2es.py -c conf/santacruz.yml -f data/nmap/nmap_scan.xml
   ```
   
## Nuclei
Nuclei has native support for Elasticsearch  
   ```sh
      nuclei -report-config conf/santacruz.yml -u <target>
   ```

## Viewing and Extracting data
Since your data now lives in Elasticsearch it can be searched, extracted, parsed, and viewed via the Kibana Dashboard or by just about anything that supports http(s) and json. This makes it easy for reporting and/or importing into other tools. `santasearch.py` is a command line tool created for doing just that. *See: <a href="scripts/README.md" target="_blank">scripts/README.md</a> for more information*

## Todo
   * More stuff

## References
Marco Lancini's writeup: <a href="https://www.marcolancini.it/2018/blog-elk-for-nmap/" target="_blank">Offensive ELK: Elasticsearch for Offensive Security</a><br>
Elasticsearch: <a href="https://github.com/elastic/elasticsearch" target="_blank">https://github.com/elastic/elasticsearch</a><br>
Kibana: <a href="https://github.com/elastic/kibana" target="_blank">https://github.com/elastic/kibana</a><br>
Nmap: <a href="https://nmap.org/" target="_blank">https://nmap.org/</a><br>
Project Discovery: <a href="https://github.com/projectdiscovery" target="_blank">https://github.com/projectdiscovery</a><br>


