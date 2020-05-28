import yaml
import asyncio
import json
import datetime
import subprocess
import time
from http.client import HTTPException
from multiprocessing import Process, Pipe
from confluent_kafka.cimpl import KafkaException
from helpers.utils import AsyncProducer, deep_get

async def read(producer, child_conn):
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    with open('certificates.txt', 'r') as f:
        while True:
            raw = f.readline()
            if raw:
                try:
                    data = json.loads(raw)
                    sha1 = \
                    data['data']['tls']['result']['handshake_log']['server_certificates']['certificate']['parsed'][
                        'fingerprint_sha1']
                    body = {"date": date, "data": data, "sha1": sha1}
                    asyncio.create_task(producer.produce("scan", body))
                except Exception as e:
                    print(e)
                    continue
            else:
                if child_conn.poll():  # Scan is done, and no new line to read
                    break
                await asyncio.sleep(0.5)


def run_producer(bootstrap_servers, child_conn):
    print("Start producing")
    print(bootstrap_servers)
    config = {"bootstrap.servers": bootstrap_servers}
    loop = asyncio.get_event_loop()
    producer = AsyncProducer(config, loop)
    loop.run_until_complete(read(producer, child_conn))
    time.sleep(60)
    loop.close()
    producer.close()
    print("Done producing")


def main(bootstrap_servers):
    while True:
        print("Scan started")
        proc = subprocess.Popen(
           "zmap -r 10000 --blacklist-file=config/blacklist.conf --sender-threads=1 --cores=0 -p 443 -n 100% -o - | ztee hosts.txt | ./bin/zgrab2 tls -o certificates.txt --gomaxprocs=1 --senders=1000",
            shell=True)
        #proc = subprocess.Popen("./bin/zgrab2 tls -f hosts.txt -o certificates.txt --gomaxprocs=1 --senders=1000",shell=True) # For testing only

        parent_conn, child_conn = Pipe()
        p = Process(target=run_producer, args=(bootstrap_servers, child_conn,))
        time.sleep(5)
        p.start()
        proc.wait()
        parent_conn.send("done")
        p.join()
        print("Scan ended")


if __name__ == "__main__":
    with open("config/config.yml", "r") as configFile:
        cfg = yaml.safe_load(configFile)
        main(cfg['kafka']['bootstrap_servers'])