import argparse
from functools import reduce
from analyzer import Analyzer, Module


def deep_get(dictionary, keys, default=None):
    return reduce(lambda d, key: d.get(key, default) if isinstance(d, dict) else default, keys.split("."),
                  dictionary)


class IcedidModule1(Module):

    def analyze(self, topic, data):
        if topic != "scan":
            return False, None

        issuer_common_name = deep_get(data,
                                      'data.tls.result.handshake_log.server_certificates.certificate.parsed.issuer.common_name')
        if issuer_common_name:
            issuer_common_name = issuer_common_name[0]
        else:
            return False, None
        subject_common_name = deep_get(data,
                                       'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.common_name')
        if subject_common_name:
            subject_common_name = subject_common_name[0]
        else:
            return False, None

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
            return True, "cluster-3"
        else:
            return False, None


class IcedidModule2(Module):
    def analyze(self, topic, data):
        if topic != "scan":
            return False, None

        issuer_dn = deep_get(data,'data.tls.result.handshake_log.server_certificates.certificate.parsed.issuer_dn')

        if issuer_dn == "CN=localhost, C=AU, ST=Some-State, O=Internet Widgits Pty Ltd":
            return True, "cluster-4"

        return False, None


def main(bootstrap_servers):
    modules = [IcedidModule1("icedid"), IcedidModule2("icedid")]
    topics = ["scan"]
    malware_analyzer = Analyzer(modules, topics, bootstrap_servers)
    malware_analyzer.start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Certificate Transparency log scanner which pushes new certificates to Kafka')
    parser.add_argument('--bootstrap_servers', default="localhost:9092", help='Comma separated list of brokers')
    args = parser.parse_args()
    main(args.bootstrap_servers)