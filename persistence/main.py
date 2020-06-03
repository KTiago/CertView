import yaml
import confluent_kafka
import json
import sys
import logging

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from helpers.utils import deep_get, LoggerWriter
from collections import deque

def main(bootstrap_servers, host, port, user, password):
    consumerConfiguration = {'bootstrap.servers': bootstrap_servers,
                             'group.id': "elasticsearch",
                             'session.timeout.ms': 30000,
                             'auto.offset.reset': 'earliest'}
    consumer = confluent_kafka.Consumer(consumerConfiguration)
    consumer.subscribe(["scan", "ct", "tags"])

    # Elasticsearch configuration
    es = Elasticsearch([{'host': host, 'port': port}], http_auth=(user, password))

    actions = []
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

                    raw = deep_get(data,
                                   'data.tls.result.handshake_log.server_certificates.certificate.raw',
                                   "")

                    issuer_common_name = deep_get(data,
                                                  'data.tls.result.handshake_log.server_certificates.certificate.parsed.issuer.common_name',
                                                  "")

                    subject_common_name = deep_get(data,
                                                   'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.common_name',
                                                   "")

                    tls_version = deep_get(data,
                                           'data.tls.result.handshake_log.server_hello.version.value',
                                           "")

                    tls_cipher_suite = deep_get(data,
                                                'data.tls.result.handshake_log.server_hello.cipher_suite.hex',
                                                "")


                    actions.append(
                        {
                            "_index": "certificates",
                            "_id": sha1,
                            "date": date,
                            "sha1": sha1,
                            "issuer_common_name": issuer_common_name,
                            "subject_common_name": subject_common_name,
                            "raw": raw,
                            "scan": True,
                        }
                    )

                    ip = deep_get(data,
                                  'ip',
                                  "")
                    md5 = deep_get(data,
                                   'data.tls.result.handshake_log.server_certificates.certificate.parsed.fingerprint_md5',
                                   "")
                    sha256 = deep_get(data,
                                      'data.tls.result.handshake_log.server_certificates.certificate.parsed.fingerprint_sha256',
                                      "")

                    actions.append(
                        {
                            "_index" : "hosts_{date}".format(date=date),
                            "ip": ip,
                            "date": date,
                            "md5": md5,
                            "sha1": sha1,
                            "sha256": sha256,
                            "tls_version": tls_version,
                            "tls_cipher_suite": tls_cipher_suite,
                        }
                    )

                elif topic == "ct":
                    message = json.loads(msg.value())
                    data = message['data']
                    date = message['date']
                    sha1 = message['sha1']

                    try:
                        issuer_common_name = data["chain"][0]["subject"]["CN"]
                    except KeyError or IndexError:
                        issuer_common_name = ""

                    subject_common_name = deep_get(data,
                                                   'leaf_cert.subject.CN',
                                                   "")
                    raw = deep_get(data,
                                   'leaf_cert.as_der',
                                   "")

                    actions.append(
                        {
                            "_index": "certificates",
                            "_id": sha1,
                            "date": date,
                            "sha1": sha1,
                            "issuer_common_name": issuer_common_name,
                            "subject_common_name": subject_common_name,
                            "raw": raw,
                            "ct": True,
                        }
                    )

                elif msg.topic() == "tags":
                    message = json.loads(msg.value())
                    date = message['date']
                    sha1 = message['sha1']
                    tag = message['tag']
                    comment = message['comment']
                    actions.append(
                        {
                            "_index": "tags",
                            "date": date,
                            "sha1": sha1,
                            "tag": tag,
                            "comment": comment,
                        }
                    )
                if len(actions) > 1000:
                    bulk(es, iter(actions))
                    actions = []

    except KeyboardInterrupt:
        sys.stderr.write('Aborted by user\n')

    finally:
        consumer.close()


if __name__ == "__main__":
    # Logger setup
    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename='persistence.log',
                        level=logging.WARNING)
    sys.stderr = LoggerWriter(logging.getLogger(), logging.ERROR)
    logging.info('Starting ipv4 scanning program')

    with open("config/config.yml", "r") as configFile:
        cfg = yaml.safe_load(configFile)
        main(cfg['kafka']['bootstrap_servers'],
             cfg['elasticsearch']['host'],
             cfg['elasticsearch']['port'],
             cfg['elasticsearch']['user'],
             cfg['elasticsearch']['password'])
