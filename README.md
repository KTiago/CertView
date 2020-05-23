# CertView
## Introduction
Platform that collects TLS certificates from active scans and certificate transparency logs and allows modules to perform analysis and provide tags.

## Project structure
```bash
.
├── analyzer            # Python program that analyzes new certificates from Kafka and published analysis tags back to Kafka
├── frontend		# Node.js webserver that exposes certificates and analysis tags stored in ElasticSearch
├── helpers		# Set of helper functions
├── persistence         # Python program that subscribes to Kafka and persists new certificates and analysis tags to ElasticSearch
└── scanner		# Scanners scan various sources for new certificates and publish them to Kafka
    ├── ct	        # Scanner from Certificate Transparency logs (code adapted from https://github.com/CaliDog/certstream-server-python)
    └── ipv4     	# Active IPv4 scanner using Zmap/Zgrab
```
