import confluent_kafka
import asyncio
import json
import logging
from helpers.utils import deep_get, CSHash

from helpers.utils import AsyncProducer
from abc import ABC, abstractmethod

class Module(ABC):
    def __init__(self, tag):
        self.tag = tag
        super().__init__()

    @abstractmethod
    def analyze(self, topic, data, cshash):
        pass

class Analyzer:
    def __init__(self,
                 modules,
                 topics,
                 bootstrap_servers="localhost:9092",
                 analyzer_id="default_analyzer"):
        self.modules = modules
        self.topics = topics
        self.loop = asyncio.get_event_loop()
        self.consumer = confluent_kafka.Consumer({
            'bootstrap.servers': bootstrap_servers,
            'group.id': analyzer_id,
            'session.timeout.ms': 6000,
            'auto.offset.reset': 'earliest'
        })
        self.producer = AsyncProducer({'bootstrap.servers': bootstrap_servers}, self.loop)

    async def __analyze(self):
        try:
            while True:
                msg = self.consumer.poll(timeout=1.0)
                if msg is None:
                    continue
                if msg.error():
                    raise confluent_kafka.KafkaException(msg.error())
                else:
                    topic = msg.topic()
                    message = json.loads(msg.value())
                    data = message['data']
                    date = message['date']
                    sha1 = message['sha1']
                    cert = deep_get(data,
                                    'data.tls.result.handshake_log.server_certificates.certificate.raw',
                                    "")

                    for module in self.modules:
                        match, comment = module.analyze(topic, data, cert)
                        if match:
                            body = {
                                "date": date,
                                "sha1": sha1,
                                "tag": module.tag,
                                "comment": comment,
                            }
                            logging.info("Found match :")
                            logging.info(str(body))
                            self.producer.produce("tags", body)
        except Exception as e:
            logging.error(e)
        finally:
            self.consumer.close()

    def start(self):
        logging.info("Starting analyzer")
        self.consumer.subscribe(self.topics)
        try:
            self.loop.run_until_complete(self.__analyze()) # TODO implement graceful shutdown
        except KeyboardInterrupt:
            logging.info("Received exit, exiting")
