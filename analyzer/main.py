import faust
from functools import reduce

app = faust.App('Module-1', broker='kafka://localhost:9092', value_serializer='json')
topic = app.topic('scan')
tag = app.topic('tags')


# python3 main.py --datadir=/home/user/Project/certwatch/analyzer/data -A Main worker --web-port=6066
def deep_get(dictionary, keys, default=None):
    return reduce(lambda d, key: d.get(key, default) if isinstance(d, dict) else default, keys.split("."), dictionary)


@app.agent(topic, sink=[tag])
async def myagent(stream):
    async for event in stream:
        data = event['data']
        date = event['date']

        sha1 = deep_get(data, 'data.tls.result.handshake_log.server_certificates.certificate.parsed.fingerprint_sha1')
        issuer_common_name = deep_get(data, 'data.tls.result.handshake_log.server_certificates.certificate.parsed.issuer.common_name')
        if issuer_common_name:
            issuer_common_name = issuer_common_name[0]
        else:
            return
        subject_common_name = deep_get(data,
                                      'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.common_name')
        if subject_common_name:
            subject_common_name = subject_common_name[0]
        else:
            return

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
        key_length = deep_get(data, 'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject_key_info.rsa_public_key.length')

        if correct_pattern \
                and issuer_common_name == subject_common_name \
                and validity == 31536000\
                and key_length == 2048:
            body = {
                "date": date,
                "sha1": sha1,
                "tag": "icedid",
                "comment": "cluster-2"
            }
            yield body


if __name__ == "__main__":
    app.main()
