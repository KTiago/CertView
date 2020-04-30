from functools import reduce
from http.client import HTTPException
import confluent_kafka
from confluent_kafka.cimpl import KafkaException
from helpers.producer import KafkaProducer
import asyncio
import sys
import json

async def computation(producer, body):
    try:
        result = await producer.produce("tags", body)
        return { "timestamp": result.timestamp() }
    except KafkaException as ex:
        raise HTTPException(status_code=500, detail=ex.args[0].str())

async def receive(consumer, producer):
    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                raise confluent_kafka.KafkaException(msg.error())
            else:
                value = json.loads(msg.value())
                data = value['data']
                date = value['date']

                sha1 = deep_get(data,
                                'data.tls.result.handshake_log.server_certificates.certificate.parsed.fingerprint_sha1')
                issuer_common_name = deep_get(data,
                                              'data.tls.result.handshake_log.server_certificates.certificate.parsed.issuer.common_name')
                if issuer_common_name:
                    issuer_common_name = issuer_common_name[0]
                else:
                    continue
                subject_common_name = deep_get(data,
                                               'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.common_name')
                if subject_common_name:
                    subject_common_name = subject_common_name[0]
                else:
                    continue

                upper = False
                lower = False
                prefix_length = 0
                dot = False
                for i in range(len(subject_common_name)):
                    if subject_common_name[i] == '.':
                        dot = True
                        prefix_length = i
                        break
                    elif subject_common_name[i].isupper():
                        upper = True
                    elif subject_common_name[i].islower():
                        lower = True
                correct_pattern = upper and lower and dot and prefix_length == 10

                validity = deep_get(data,
                                    'data.tls.result.handshake_log.server_certificates.certificate.parsed.validity.length')
                key_length = deep_get(data,
                                      'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject_key_info.rsa_public_key.length')

                if correct_pattern \
                        and issuer_common_name == subject_common_name \
                        and validity == 31536000 \
                        and key_length == 2048:
                    body = {
                        "date": date,
                        "sha1": sha1,
                        "tag": "icedid",
                        "comment": "cluster-2"
                    }
                    asyncio.create_task(computation(producer, body))
    except KeyboardInterrupt:
        sys.stderr.write('%% Aborted by user\n')

    finally:
        consumer.close()

def deep_get(dictionary, keys, default=None):
    return reduce(lambda d, key: d.get(key, default) if isinstance(d, dict) else default, keys.split("."), dictionary)

def main():
    conf_producer = {"bootstrap.servers": "localhost:9092"}
    loop = asyncio.get_event_loop()
    producer = KafkaProducer(conf_producer, loop)

    conf_consumer = {'bootstrap.servers': "localhost:9092", 'group.id': "analyzer-1", 'session.timeout.ms': 6000,
                     'auto.offset.reset': 'earliest'}
    consumer = confluent_kafka.Consumer(conf_consumer)
    consumer.subscribe(["scan"])

    loop.run_until_complete(receive(consumer, producer))

if __name__ == "__main__":
    main()
