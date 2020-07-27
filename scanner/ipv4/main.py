import sys
import time
import yaml
import asyncio
import json
import datetime
import subprocess
import logging

from helpers.utils import AsyncProducer, deep_get, LoggerWriter, CSHash

async def scan(producer):
    while True:  # Continuously run new full IPv4 range scans
        logging.info('New scan started')
        proc = subprocess.Popen(
            "zmap -q --log-file=zmap.log -r 10000 --blacklist-file=config/blacklist.conf --sender-threads=1 --cores=0 -p 443 -n 100% -o - | ztee hosts.txt | ./bin/zgrab2 tls -o - --gomaxprocs=1 --senders=1000",
            shell=True,
            stdout=subprocess.PIPE)

        while True:  # Continuously poll new certificates from scan
            raw = proc.stdout.readline()
            if raw == b'' and proc.poll() is not None:
                break
            if raw: # Handle new output line from zgrab
                date = datetime.datetime.now().strftime("%Y-%m-%d")
                try:
                    data = json.loads(raw)
                    sha1 = deep_get(data,
                                    'data.tls.result.handshake_log.server_certificates.certificate.parsed.fingerprint_sha1',
                                    None)
                    if sha1: # Send certificate and metadata to Kafka
                        body = {"date": date, "data": data, "sha1": sha1}
                        asyncio.create_task(producer.produce("scan", body))
                except Exception as e:
                    logging.error(e)
                    continue

        logging.info('Scan ended')
        time.sleep(600)


def main(bootstrap_servers):
    # Logger setup
    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename='ipv4-scan.log',
                        level=logging.DEBUG)
    sys.stderr = LoggerWriter(logging.getLogger(), logging.ERROR)
    logging.info('Starting ipv4 scanning program')

    # Kafka producer setup
    config = {'bootstrap.servers': bootstrap_servers,
              'group.id': "ipv4-scan",
              'session.timeout.ms': 30000,
              'auto.offset.reset': 'earliest'}
    loop = asyncio.get_event_loop()
    producer = AsyncProducer(config, loop)

    # Start scan
    loop.run_until_complete(scan(producer))

    # Cleanup
    loop.close()
    producer.close()
    logging.info('Close Kafka producer')


if __name__ == "__main__":
    with open("config/config.yml", "r") as configFile:
        cfg = yaml.safe_load(configFile)
        main(cfg['kafka']['bootstrap_servers'])
