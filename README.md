# CertView
## Introduction
Platform that collects TLS certificates from active scans and certificate transparency logs and allows modules to perform real-time analysis and provide tags.

This documents describes the commands required to setup and deploy the CertView platform. Be aware that IPv4 scanning might have a negative impact on scanned hosts. Therefore, limit the scanning speed to the strict necessary and proceed ethically.
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
## Computing infrastructure
To run the CertView platform, we opted for a cloud deployment on the compute engine of the Google Cloud Platform (GCP). We deployed CertView on 5 VMs, but the platform may be deployed on more machines or entirely on one machine. Each VM runs Debian-9.

The following hardware configuration is given as an example that supports continuously run 48h long IPv4 scans and Certificate Transparency logs. For faster scanning speeds, a more robust configuration might be required.
1. Scan, 6 vCPUs, 5.5 GB RAM, 100 GB HDD
2. Kafka, 1 vCPU, 3.75 GB RAM, 100 GB HDD
3. Analyzer, 1 vCPU, 3.75 GB RAM, 100 GB HDD
4. Persistence, 2 vCPUs, 13 GB RAM, 500 GB HDD
5. Frontend, 1 VCPU, 0.6 GB RAM, 10 GB HDD

## VM Setup commands
The following describes some of the commands we used to setup the VMs on Debian-9. Depending on your configuration, more commands might be required. This guide is probably not exhaustive.
### Scan VM
Install python 3.8, 
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

# Required installs
sudo apt-get update
sudo apt-get install virtualenv
sudo apt-get install zmap
sudo apt-get install git

# Clone repository 
git clone https://github.com/KTiago/CertView.git
cd CertView

# Setup virtualenv
virtualenv venv -p python3.8
source venv/bin/activate
pip3 install -r requirements.txt

# Start webserver on scanning host to inform that the scan is benign and propose blacklisting.
sudo su
cd scanner/ipv4/webserver
nohup python -m http.server 80 &
cd ../../../

# Edit config/config.yaml 

# Run IPv4 scan
export PYTHONPATH="."
nohup python scanner/ipv4/main.py &

# Run CT logs scan
export PYTHONPATH="."
nohup python scanner/ipv4/main.py &
```
### Kafka VM
```bash
# Install Kafka
sudo apt-get install default-jdk
wget http://mirror.easyname.ch/apache/kafka/2.5.0/kafka_2.12-2.5.0.tgz
tar -xzf kafka_2.12-2.5.0.tgz
rm kafka_2.12-2.5.0.tgz

# Run Zookeeper and Kafka server (edit configuration files first)
cd cd kafka_2.12-2.5.0/
nohup bin/zookeeper-server-start.sh config/zookeeper.properties &
nohup bin/kafka-server-start.sh config/server.properties &
```
### Analyzer VM
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

# Required installs
sudo apt-get update
sudo apt-get install virtualenv
sudo apt-get install git

# Clone repository 
git clone https://github.com/KTiago/CertView.git
cd CertView

# Edit config/config.yaml 

# Setup virtualenv
virtualenv venv -p python3.8
source venv/bin/activate
pip3 install -r requirements.txt


# Run analysis modules
cd CertWatch
export PYTHONPATH="."
nohup python analyzer/main.py &
```
### Persistence VM
```bash
# Install python3.8
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt-get install apt-transport-https
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list
sudo apt-get update && sudo apt-get install elasticsearch && sudo apt-get install kibana

sudo nano /etc/elasticsearch/elasticsearch.yml
# Add the following
# xpack.security.enabled: true
# xpack.security.transport.ssl.enabled: true
# network.host: <IP ADDRESS>
# discovery.seed_hosts: ["<IP ADDRESS>"]

# Start Elasticsearch and setup password
sudo systemctl start elasticsearch
cd /usr/share/elasticsearch/
sudo bin/elasticsearch-setup-passwords interactive
sudo systemctl restart elasticsearch

sudo nano /etc/kibana/kibana.yml
# Add the following
#elasticsearch.username: "kibana"
#elasticsearch.password: "<PASSWORD>"
#server.port: 5601
#server.host: "<IP_ADDRESS>"
#elasticsearch.hosts: ["http://<IP_ADDRESS>:9200"]

# Start kibana
sudo systemctl start kibana

# Required installs
sudo apt-get update
sudo apt-get install virtualenv
sudo apt-get install git

# Clone repository 
git clone https://github.com/KTiago/CertView.git
cd CertView

# Edit config/config.yaml 

# Setup virtualenv
virtualenv venv -p python3.8
source venv/bin/activate
pip3 install -r requirements.txt

# Run analysis modules
cd CertWatch
export PYTHONPATH="."
nohup python persistence/main.py &
```

### Frontend VM
```bash
# Required installs
sudo apt-get install git
sudo apt-get install nodejs
sudo apt-get install npm
sudo apt-get install nginx

# Clone repository 
git clone https://github.com/KTiago/CertView.git
cd CertView/frontend/

# Start webserver
npm install
sudo su
export PORT=80
export ELASTIC_CLIENT="elastic"
export ELASTIC_PASSWORD="<password>"
npm start
```