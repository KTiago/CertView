import argparse

import confluent_kafka
from elasticsearch import Elasticsearch
import json
import sys


def main(bootstrap_servers, host, port, user, password):
    consumerConfiguration = {'bootstrap.servers': bootstrap_servers,
                             'group.id': "elasticsearch",
                             'session.timeout.ms': 6000,
                             'auto.offset.reset': 'earliest'}
    consumer = confluent_kafka.Consumer(consumerConfiguration)
    consumer.subscribe(["scan", "ct", "tags"])

    # Elasticsearch configuration
    if user and password:
        es = Elasticsearch([{'host': host, 'port': port}], http_auth=(user, password))
    else:
        es = Elasticsearch([{'host': host, 'port': port}])

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:  # no message received yet
                continue
            if msg.error():
                raise confluent_kafka.KafkaException(msg.error())
            else:
                topic = msg.topic()
                if topic == "scan":
                    message = json.loads(msg.value())
                    data = message['data']
                    date = message['date']
                    sha1 = message['sha1']

                    raw = data['data']['tls']['result']['handshake_log']['server_certificates']['certificate']['raw']

                    try:
                        issuer_common_name = \
                            data['data']['tls']['result']['handshake_log']['server_certificates']['certificate'][
                                'parsed'][
                                'issuer']['common_name']
                    except KeyError:
                        issuer_common_name = ""

                    try:
                        subject_common_name = \
                            data['data']['tls']['result']['handshake_log']['server_certificates']['certificate'][
                                'parsed'][
                                'subject']['common_name']
                    except KeyError:
                        subject_common_name = ""

                    tls_version = data['data']['tls']['result']['handshake_log']['server_hello']['version']['value']
                    tls_cipher_suite = data['data']['tls']['result']['handshake_log']['server_hello']['cipher_suite'][
                        'hex']

                    body = {
                        "date": date,
                        "sha1": sha1,
                        "issuer_common_name": issuer_common_name,
                        "subject_common_name": subject_common_name,
                        "raw": raw,
                        "tls_version": tls_version,
                        "tls_cipher_suite": tls_cipher_suite,
                        "scan": True,
                    }
                    try:
                        res = es.index(index="certificates", id=sha1, body=body)
                    except Exception as e:
                        print(e)

                    body = {
                        "ip": data['ip'],
                        "date": data['data']['tls']['timestamp'],
                        "md5":
                            data['data']['tls']['result']['handshake_log']['server_certificates']['certificate'][
                                'parsed'][
                                'fingerprint_md5'],
                        "sha1":
                            data['data']['tls']['result']['handshake_log']['server_certificates']['certificate'][
                                'parsed'][
                                'fingerprint_sha1'],
                        "sha256": data['data']['tls']['result']['handshake_log']['server_certificates']['certificate'][
                            'parsed'][
                            'fingerprint_sha256'],
                    }
                    try:
                        res = es.index(index="hosts_{date}".format(date=date), body=body)
                    except Exception as e:
                        print(e)
                elif topic == "ct":
                    message = json.loads(msg.value())
                    data = message['data']
                    date = message['date']
                    sha1 = message['sha1']

                    body = {
                        "date": date,
                        "sha1": sha1,
                        "issuer_common_name": data["chain"][0]["subject"]["CN"],
                        "subject_common_name": data["leaf_cert"]["subject"]["CN"],
                        "raw": data["leaf_cert"]["as_der"],
                        "ct": True,
                    }
                    try:
                        res = es.index(index="certificates", id=sha1, body=body)
                    except Exception as e:
                        print(e)
                elif msg.topic() == "tags":
                    body = json.loads(msg.value())
                    try:
                        res = es.index(index="tags", body=body)
                    except Exception as e:
                        print(e)

    except KeyboardInterrupt:
        sys.stderr.write('Aborted by user\n')

    finally:
        consumer.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Kafka consumer which persists certificates to Elasticsearch')
    parser.add_argument('--bootstrap_servers', default="localhost:9092", help='Comma separated list of Kafka brokers')
    parser.add_argument('--host', default='localhost', help='Elasticsearch server host address')
    parser.add_argument('--port', default=9200, help='Elasticsearch server port')
    parser.add_argument('--user', help='Elasticsearch server user')
    parser.add_argument('--password', help='Elasticsearch server password')
    args = parser.parse_args()

    main(args.bootstrap_servers, args.host, args.port, args.user, args.password)
