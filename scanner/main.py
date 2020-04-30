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
        certificate = data['data']['tls']['result']['handshake_log']['server_certificates']['certificate']['raw']
        result = await producer.produce("scan", {"date":date, "data":data})
        return { "timestamp": result.timestamp() }
    except Exception:
        pass
        #raise HTTPException(status_code=500, detail=ex.args[0].str())

async def read(producer, child_conn):
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    with open('/home/user/Project/scan/certificates.txt') as f:
        while True:
            raw = f.readline()
            if raw:
               asyncio.create_task(computation(producer, raw, date))
            else:
                if child_conn.poll(): # Scan is done, and no new line to read
                    break
                await asyncio.sleep(0.5)

def run_producer(child_conn):
    print("Start producing")
    config = {"bootstrap.servers": "localhost:9092"}
    loop = asyncio.get_event_loop()
    producer = KafkaProducer(config, loop)
    loop.run_until_complete(read(producer, child_conn))
    time.sleep(60)
    loop.close()
    producer.close()
    print("Done producing")

def main():
    while True:
        print("Scan started")
        proc = subprocess.Popen("zmap -r 50000 --sender-threads=3 --cores=0,1,2 -p 443 -n 100% -o - | ztee hosts.txt | ./zgrab2 tls -o certificates.txt --gomaxprocs=4 --senders=4000", shell=True)
        parent_conn, child_conn = Pipe()
        p = Process(target=run_producer, args=(child_conn,))
        p.start()
        proc.wait()
        parent_conn.send("done")
        p.join()
        print("Scan ended")


if __name__ == "__main__":
    main()
