import asyncio
import json
import datetime
from helpers.producer import KafkaProducer

async def computation(producer, raw, date):
    try:
        data = json.loads(raw)
        certificate = data['data']['tls']['result']['handshake_log']['server_certificates']['certificate']['raw']
        #print(certificate)
        result = await producer.produce("scan", {"date":date, "data":data})
        print("result ", result.result())
    except Exception:
        pass

async def read(producer):
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    with open('/home/user/Project/scan/certificates.txt') as f:
        while True:
            raw = f.readline()
            if raw:
               asyncio.create_task(computation(producer, raw, date))
            else:
                await asyncio.sleep(0.5)

def main():
    config = {"bootstrap.servers": "localhost:9092"}
    loop = asyncio.get_event_loop()
    producer = KafkaProducer(config, loop)
    loop.run_until_complete(loop.run_until_complete(read(producer)))


if __name__ == "__main__":
    main()

# Some commands
# cd /home/user/Project/scan
# zmap -B 10K -p 443 -n 0.01% -o - | ztee hosts.txt | ./zgrab2 tls -o certificates.txt
# python3 /home/user/Project/certwatch/main.py