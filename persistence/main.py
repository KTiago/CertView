import argparse

import confluent_kafka
from elasticsearch import Elasticsearch
import json
import sys
def main(bootstrap_servers):
    conf_consumer = {'bootstrap.servers': bootstrap_servers, 'group.id': "elasticsearch", 'session.timeout.ms': 6000,
            'auto.offset.reset': 'earliest'}
    consumer = confluent_kafka.Consumer(conf_consumer)
    consumer.subscribe(["scan", "tags"])

    # Elasticsearch configuration
    es = Elasticsearch([{'host': 'localhost', 'port': 9200}])

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                raise confluent_kafka.KafkaException(msg.error())
            else:
                topic = msg.topic()
                if topic == "scan" or topic == "ct":
                    value = json.loads(msg.value())
                    data = value['data']
                    date = value['date']

                    try:
                        sha1 = data['data']['tls']['result']['handshake_log']['server_certificates']['certificate']['parsed'][
                                'fingerprint_sha1']
                    except KeyError:
                        continue

                    raw = data['data']['tls']['result']['handshake_log']['server_certificates']['certificate']['raw']

                    try:
                        issuer_common_name = data['data']['tls']['result']['handshake_log']['server_certificates']['certificate']['parsed'][
                            'issuer']['common_name']
                    except KeyError:
                        issuer_common_name = ""

                    try:
                        subject_common_name = data['data']['tls']['result']['handshake_log']['server_certificates']['certificate']['parsed'][
                        'subject']['common_name']
                    except KeyError:
                        subject_common_name = ""

                    tls_version = data['data']['tls']['result']['handshake_log']['server_hello']['version']['value']
                    tls_cipher_suite = data['data']['tls']['result']['handshake_log']['server_hello']['cipher_suite']['hex']


                    id =  sha1
                    body = {
                        "date" : date,
                        "sha1" : sha1,
                        "issuer_common_name": issuer_common_name,
                        "subject_common_name" : subject_common_name,
                        "raw" : raw,
                        "tls_version" : tls_version,
                        "tls_cipher_suite": tls_cipher_suite,
                        "scan" : topic == "scan",
                        "ct" : topic == "ct"
                    }

                    res = es.index(index="certificates", id=id, body=body)

                    body = {
                        "ip": data['ip'],
                        "date": data['data']['tls']['timestamp'],
                        "md5":
                            data['data']['tls']['result']['handshake_log']['server_certificates']['certificate']['parsed'][
                                'fingerprint_md5'],
                        "sha1":
                            data['data']['tls']['result']['handshake_log']['server_certificates']['certificate']['parsed'][
                                'fingerprint_sha1'],
                        "sha256": data['data']['tls']['result']['handshake_log']['server_certificates']['certificate']['parsed'][
                                'fingerprint_sha256'],
                    }
                    res = es.index(index="hosts_{date}".format(date=date), id=id, body=body)
                elif msg.topic() == "tags":
                    body = json.loads(msg.value())
                    res = es.index(index="tags", body=body)

    except KeyboardInterrupt:
        sys.stderr.write('%% Aborted by user\n')

    finally:
        consumer.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Kafka consumer which persists certificates to Elasticsearch')
    parser.add_argument('--bootstrap_servers', default="localhost:9092", help='Comma separated list of brokers')
    args = parser.parse_args()

    main(args.bootstrap_servers)
