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
### Scan
CPU : n1-standard-2
Memory : 100Gb
```bash
# Install python3.8
sudo apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev wget
wget https://www.python.org/ftp/python/3.8.2/Python-3.8.2.tgz
tar xvf Python-3.8.2.tgz
cd Python-3.8.2
./configure --enable-optimizations --enable-shared --with-ensurepip=install
make -j8
sudo make altinstall
sudo ln -s -f /usr/local/bin/python3.8 /usr/local/bin/python
sudo ldconfig
cd ~
# optional
sudo apt-get install bmon
# required
sudo apt-get update
sudo apt-get install virtualenv
sudo apt-get install zmap
sudo apt-get install git
git clone https://github.com/KTiago/CertView.git
cd CertView
# ipv4 scan needs to be run as superuser to access eth0
sudo su
virtualenv venv -p python3.8
source venv/bin/activate
pip3 install -r requirements.txt
cd scanner/ipv4/webserver
nohup python -m http.server 80 &
cd ../../../
# edit config/config.yaml
export PYTHONPATH="."
python scanner/ipv4/main.py
```
### Kafka
CPU : g1-small
Memory : 100Gb
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
CPU : n1-standard-1
Memory : 500Gb
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
CPU : f1-micro
Memory : 10Gb
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
CPU : f1-micro
Memory : 10Gb
```bash
sudo apt-get install git
sudo apt-get install nodejs
sudo apt-get install npm
sudo apt-get install nginx
git clone https://github.com/KTiago/CertView.git
cd CertView/frontend/
npm install
sudo su
export PORT=80
export ELASTIC_CLIENT="elastic"
export ELASTIC_PASSWORD="<password>"
npm start
```