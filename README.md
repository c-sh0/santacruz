# Santacruz
**Status**: *In Development*

Elasticsearch and Kibana setup for Penetration testing and reconnaissance.
* An Original Idea? Nope.
* My own version? Yep.

## Description
Having to write custom shell scripts to parse and keep track of all the data from many different security tools is time consuming and often results in a mountain of text files. Other solutions to this problem often include yet more tools, often times a license, and features that are never used. I needed something simple, lightweight, customisable, portable, and easy to deploy without all the "feature" bloat.
#### For the TL;DR crowd
* Normalize useful tool output
* Team Collaboration

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
The easiest approach when setting passwords is by following the steps below otherwise, your going to end up mucking with the containers and/or composer files later.
1. Start Elasticsearch container (&& watch logs to make sure it starts)<br>
   ```docker-compose up -d elasticsearch && docker logs elasticsearch --follow```

2. Change the default passwords for all built-in users, make note of the output.<br>
   ```docker exec elasticsearch /bin/bash -c "bin/elasticsearch-setup-passwords auto --batch"```

3. Since this is a `single-node` cluster, for all newly created indexes, create an index template that will set `number_of_replicas` to `0`
      ```sh
      curl -X PUT 'http://localhost:9200/_template/template_1' \
      -H 'Content-Type: application/json' \
      -d '{"index_patterns":["*"],"order":0,"settings":{"number_of_shards":1,"number_of_replicas": 0}}' \
      -u elastic:<password from #2>
      ```
      Refer to the documentation for more information and settings.<br>
      https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-templates-v1.html

4. Update the Kibana and Santacruz configuration files with generated password from #2<br>
   ```conf/kibana.yml```<br>
   ```conf/santacruz.yml```

5. Start Kibana container. It will take a min or two to fully start (&& watch logs to make sure it starts)<br>
   ```docker-compose up -d kibana && docker logs kibana --follow```

6. Login into the Kibana dashboard (user: elastic, password from #2)<br>
   ```http://your.ip:5601/```

7. (Optional) Add additional users: **Stack Management** -> **Users**

### Optional
By default, containers will not automaticaly start on system boot. The following commands will start the containers when docker starts
   ```sh
      docker update --restart=always elasticsearch
      docker update --restart=always kibana
   ```
See: https://docs.docker.com/config/containers/start-containers-automatically/

## Documentation
<a href="doc/README.md" target="_blank">doc/README.md</a>

## Todo
   * Documentation
   * Rename this project
   * Single CLI tool
   * Logstash/Filebeat? (Doubtful, no need for it here)
   * Other

## References
Marco Lancini's writeup: <a href="https://www.marcolancini.it/2018/blog-elk-for-nmap/" target="_blank">Offensive ELK: Elasticsearch for Offensive Security</a><br>
Elasticsearch: <a href="https://github.com/elastic/elasticsearch" target="_blank">https://github.com/elastic/elasticsearch</a><br>
Kibana: <a href="https://github.com/elastic/kibana" target="_blank">https://github.com/elastic/kibana</a><br>
Nmap: <a href="https://nmap.org/" target="_blank">https://nmap.org/</a><br>
Project Discovery: <a href="https://github.com/projectdiscovery" target="_blank">https://github.com/projectdiscovery</a><br>


