import asyncio

import confluent_kafka
from threading import Thread
import json
from functools import reduce

def deep_get(dictionary, keys, default=None):
    return reduce(lambda d, key: d.get(key, default) if isinstance(d, dict) else default, keys.split("."),
                  dictionary)

class LoggerWriter:
    def __init__(self, logger, level):
        self.logger = logger
        self.level = level

    def write(self, message):
        if message != '\n':
            self.logger.log(self.level, message)

class AsyncProducer:
    def __init__(self, configs, loop):
        self._producer = confluent_kafka.Producer(configs)
        self._loop = loop
        self._cancelled = False
        self._poll_thread = Thread(target=self._poll_loop)
        self._poll_thread.start()

    def _poll_loop(self):
        while not self._cancelled:
            self._producer.poll(0.1)

    def close(self):
        self._cancelled = True
        self._poll_thread.join()

    def __produce(self, topic, value):
        result = self._loop.create_future()

        def ack(err, msg):
            if err:
                self._loop.call_soon_threadsafe(result.set_exception, confluent_kafka.KafkaException(err))
            else:
                self._loop.call_soon_threadsafe(result.set_result, msg)

        self._producer.produce(topic, json.dumps(value).encode('utf-8'), on_delivery=ack)
        return result

    async def produce(self, topic, value):
        result = await self.__produce(topic, value)
        return result