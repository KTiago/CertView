import argparse
import asyncio
import json
import datetime
import subprocess
import time
from http.client import HTTPException
from multiprocessing import Process, Pipe
from confluent_kafka.cimpl import KafkaException
from helpers.producer import KafkaProducer


async def computation(producer, raw, date):
    try:
        data = json.loads(raw)
        sha1 = data['data']['tls']['result']['handshake_log']['server_certificates']['certificate']['parsed']['fingerprint_sha1']
        result = await producer.produce("scan", {"date": date, "data": data, "sha1": sha1})
        return {"timestamp": result.timestamp()}
    except Exception:
        pass
        # raise HTTPException(status_code=500, detail=ex.args[0].str())


async def read(producer, child_conn):
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    with open('/home/user/Project/CertView/certificates.txt') as f:
        while True:
            raw = f.readline()
            if raw:
                asyncio.create_task(computation(producer, raw, date))
            else:
                if child_conn.poll():  # Scan is done, and no new line to read
                    break
                await asyncio.sleep(0.5)


def run_producer(bootstrap_servers, child_conn):
    print("Start producing")
    print(bootstrap_servers)
    config = {"bootstrap.servers": bootstrap_servers}
    loop = asyncio.get_event_loop()
    producer = KafkaProducer(config, loop)
    loop.run_until_complete(read(producer, child_conn))
    time.sleep(60)
    loop.close()
    producer.close()
    print("Done producing")


def main(bootstrap_servers):
    while True:
        print("Scan started")
        #proc = subprocess.Popen(
        #    "zmap -r 20000 --blacklist-file=scanner/ipv4/blacklist.conf --sender-threads=3 --cores=0 -p 443 -n 100% -o - | ztee hosts.txt | ./zgrab2 tls -o certificates.txt --gomaxprocs=1 --senders=1000",
        #    shell=True)
        proc = subprocess.Popen("./zgrab2 tls -f hosts.txt -o certificates.txt --gomaxprocs=1 --senders=1000",shell=True) # For testing only

        parent_conn, child_conn = Pipe()
        p = Process(target=run_producer, args=(bootstrap_servers, child_conn,))
        p.start()
        proc.wait()
        parent_conn.send("done")
        p.join()
        print("Scan ended")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='IPv4 scanner which pushes certificates to Kafka')
    parser.add_argument('--bootstrap_servers', default="localhost:9092", help='Comma separated list of brokers')
    args = parser.parse_args()

    main(args.bootstrap_servers)