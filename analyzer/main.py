import faust
from functools import reduce

app = faust.App('Module-1', broker='kafka://localhost:9092', value_serializer='json')
topic = app.topic('scan')
tag = app.topic('tags')

#python3 main.py --datadir=/home/user/Project/certwatch/analyzer/data -A Main worker --web-port=6066
def deep_get(dictionary, keys, default=None):
    return reduce(lambda d, key: d.get(key, default) if isinstance(d, dict) else default, keys.split("."), dictionary)

@app.agent(topic, sink=[tag])
async def myagent(stream):
    async for event in stream:
        data = event['data']
        date = event['date']

        sha1 = deep_get(data,'data.tls.result.handshake_log.server_certificates.certificate.parsed.fingerprint_sha1')
        key_length = deep_get(data, 'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject_key_info.rsa_public_key.length')
        if key_length == 1024:
            body = {
                "date": date,
                "sha1": sha1,
                "tag": "icedid",
                "comment": "cluster-1"
            }
            yield body

if __name__ == "__main__":
    app.main()