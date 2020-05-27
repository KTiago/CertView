import confluent_kafka
import asyncio
import json
import sys

from helpers.producer import AsyncProducer
from abc import ABC, abstractmethod


class Module(ABC):
    def __init__(self, tag):
        self.tag = tag
        super().__init__()

    @abstractmethod
    def analyze(self, topic, data):
        pass

class Analyzer:
    def __init__(self,
                 modules,
                 topics,
                 bootstrap_servers="localhost:9092",
                 analyzer_id="default_analyzer",):
        self.modules = modules
        self.topics = topics
        self.loop = asyncio.get_event_loop()
        self.consumer = confluent_kafka.Consumer({
            'bootstrap.servers': bootstrap_servers,
            'group.id': analyzer_id+"2",
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
                    for module in self.modules:
                        match, comment = module.analyze(topic, data)
                        if match:
                            body = {
                                "date": date,
                                "sha1": sha1,
                                "tag": module.tag,
                                "comment": comment,
                            }
                            asyncio.create_task(self.producer.produce("tags", body))
        except KeyboardInterrupt: # TODO KeyboardInterrupt not great, please implement graceful shutdown
            sys.stderr.write('%% Aborted by user\n')
        finally:
            self.consumer.close()

    def start(self):
        self.consumer.subscribe(self.topics)
        self.loop.run_until_complete(self.__analyze())