# Scanpan
Elasticsearch and Kibana setup for Penetration testing and reconnaissance.

## Description
Having to write custom shell scripts to parse and keep track of all the data from many different security tools is time consuming and often results in a mountain of text files. Other solutions to this problem often include yet more tools as well as features i'll never use nor care about. I needed something simple, lightweight, customisable, and easy to deploy without all the bloat.

## Getting Started
Start Elasticsearch and Kibana containers. The easiest approach when settings passwords is by following the steps below otherwise, your going to end up mucking with the containers and/or composer files later.
1. Start Elasticsearch container (&& watch logs to make sure it starts)<br>
  ```docker-compose up -d elasticsearch && docker logs elasticsearch --follow```

2. Generate passwords for all Reserved users, make note of the output.<br>
   ```docker exec elasticsearch /bin/bash -c "bin/elasticsearch-setup-passwords auto --batch"```

3. Update Kibana configuration with generated password from #2<br>
   ```conf/kibana.yml```

4. Start Kibana container (&& watch logs to make sure it starts)<br>
   ```docker-compose up -d kibana && docker logs kibana --follow```

5. Login into the Kibana dashboard (user: elastic)<br>
   ```http://your.ip:5601/```

6. (Optional) Add additional users: **Stack Management** -> **Users**

** *Work in Progress* **

## References
Marco Lancini's writeup: <a href="https://www.marcolancini.it/2018/blog-elk-for-nmap/" target="_blank">Offensive ELK: Elasticsearch for Offensive Security</a><br>
Elasticsearch: <a href="https://github.com/elastic/elasticsearch" target="_blank">https://github.com/elastic/elasticsearch</a><br>
Kibana: <a href="https://github.com/elastic/kibana" target="_blank">https://github.com/elastic/kibana</a><br>
Nmap: <a href="https://nmap.org/" target="_blank">https://nmap.org/</a><br>
Project Discovery: <a href="https://github.com/projectdiscovery" target="_blank">https://github.com/projectdiscovery</a><br>

