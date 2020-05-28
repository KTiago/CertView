import yaml
import confluent_kafka
import json
import sys

from elasticsearch import Elasticsearch
from helpers.utils import deep_get


def main(bootstrap_servers, host, port, user, password):
    consumerConfiguration = {'bootstrap.servers': bootstrap_servers,
                             'group.id': "elasticsearch",
                             'session.timeout.ms': 30000,
                             'auto.offset.reset': 'earliest'}
    consumer = confluent_kafka.Consumer(consumerConfiguration)
    consumer.subscribe(["scan", "ct", "tags"])

    # Elasticsearch configuration
    es = Elasticsearch([{'host': host, 'port': port}], http_auth=(user, password))

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

                    ip = deep_get(data,
                                  'ip',
                                  "")
                    md5 = deep_get(data,
                                   'data.tls.result.handshake_log.server_certificates.certificate.parsed.fingerprint_md5',
                                   "")
                    sha256 = deep_get(data,
                                      'data.tls.result.handshake_log.server_certificates.certificate.parsed.fingerprint_sha256',
                                      "")
                    body = {
                        "ip": ip,
                        "date": date,
                        "md5": md5,
                        "sha1": sha1,
                        "sha256": sha256,
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
                    body = {
                        "date": date,
                        "sha1": sha1,
                        "issuer_common_name": issuer_common_name,
                        "subject_common_name": subject_common_name,
                        "raw": raw,
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
    with open("config/config.yml", "r") as configFile:
        cfg = yaml.safe_load(configFile)
        main(cfg['kafka']['bootstrap_servers'],
             cfg['elasticsearch']['host'],
             cfg['elasticsearch']['port'],
             cfg['elasticsearch']['user'],
             cfg['elasticsearch']['password'])
