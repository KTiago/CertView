# CertView
## Introduction
Platform that collects TLS certificates from active scans and certificate transparency logs and allows modules to perform analysis and provide tags.

## Project structure
```bash
.
├── analyzer            # Python program that analyzes new certificates from Kafka and publishes analysis tags back to Kafka.
├── frontend		# Node.js webserver that exposes certificates and analysis tags stored in ElasticSearch.
├── helpers		# Set of helper functions.
├── persistence         # Python program that subscribes to Kafka and persists new certificates and analysis tags to ElasticSearch.
└── scanner		# Scanners scan various sources for new certificates and publish them to Kafka.
    ├── ct	        # Scanner from Certificate Transparency logs (code adapted from https://github.com/CaliDog/certstream-server-python).
    └── ipv4     	# Active IPv4 scanner using Zmap/Zgrab.
```
## Setup commands (not exhaustive)
### Kafka
```bash
gcloud compute ssh kafka
sudo apt-get install default-jdk
wget http://mirror.easyname.ch/apache/kafka/2.5.0/kafka_2.12-2.5.0.tgz
tar -xzf kafka_2.12-2.5.0.tgz
rm kafka_2.12-2.5.0.tgz
cd cd kafka_2.12-2.5.0/
bin/zookeeper-server-start.sh config/zookeeper.properties
# Add internal IP address
bin/kafka-server-start.sh config/server.properties
```
### Persistence
```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt-get install apt-transport-https
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list
sudo apt-get update && sudo apt-get install elasticsearch && sudo apt-get install kibana

sudo nano /etc/elasticsearch/elasticsearch.yml
# Add the following
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
network.host: <IP ADDRESS>
discovery.seed_hosts: ["<IP ADDRESS>"]

sudo systemctl start elasticsearch
cd /usr/share/elasticsearch/
sudo bin/elasticsearch-setup-passwords interactive
sudo systemctl restart elasticsearch

sudo nano /etc/kibana/kibana.yml
# Add the following
elasticsearch.username: "kibana"
elasticsearch.password: "<PASSWORD>"
server.port: 5601
server.host: "<IP_ADDRESS>"
elasticsearch.hosts: ["http://<IP_ADDRESS>:9200"]
sudo systemctl start kibana
```
### Analyzer
```bash

sudo apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev wget
wget https://www.python.org/ftp/python/3.8.2/Python-3.8.2.tgz
tar xvf Python-3.8.2.tgz
cd Python-3.8.2
./configure --enable-optimizations --enable-shared --with-ensurepip=install
make -j8
sudo make altinstall
sudo ln -s -f /usr/local/bin/python3.8 /usr/local/bin/python

sudo apt-get update
sudo apt-get install git
git clone https://github.com/KTiago/CertWatch.git
cd CertWatch/analyzer
python main.py --datadir=/home/user/CertWatch/analyzer/data -A main worker --web-port=6066
```
### Frontend
```bash

sudo apt-get install git
sudo apt-get install nodejs
sudo apt-get install npm
git clone https://github.com/KTiago/CertView.git
cd CertView/frontend/
npm install
sudo su
export PORT=80
export ELASTIC_CLIENT="elastic"
export ELASTIC_PASSWORD="<password>"
npm start
```