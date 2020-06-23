import yaml
from analyzer.analysis import Analyzer, Module
from helpers.utils import deep_get, CSHash
import logging
import csv

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
        banned = False
        incorrect = False
        for i in range(len(subject_common_name)):
            if subject_common_name[i] == '.':
                if dot:
                    incorrect = True
                dot = True
                prefix_length = i
            elif subject_common_name[i].isupper() and not dot:
                upper = True
            elif subject_common_name[i].islower() and not dot:
                lower = True
            elif subject_common_name[i] == '-':
                banned = True
        correct_pattern = upper and lower and dot and prefix_length == 10 and not banned and not incorrect

        validity = deep_get(data,
                            'data.tls.result.handshake_log.server_certificates.certificate.parsed.validity.length')
        key_length = deep_get(data,
                              'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject_key_info.rsa_public_key.length')

        if correct_pattern \
                and issuer_common_name == subject_common_name \
                and validity == 31536000 \
                and key_length == 2048:
            cert = deep_get(data,
                            'data.tls.result.handshake_log.server_certificates.certificate.raw',
                            "")
            cshash = CSHash(cert)
            allowed_hashes = {
                "108d4ee4b9f3cd5c0efba8af2dab5009",
            }
            if cshash in allowed_hashes:
                return True, "cluster-3"

        return False, None


class IcedidModule2(Module):
    def analyze(self, topic, data):
        if topic != "scan":
            return False, None

        issuer_dn = deep_get(data,'data.tls.result.handshake_log.server_certificates.certificate.parsed.issuer_dn')

        if issuer_dn == "CN=localhost, C=AU, ST=Some-State, O=Internet Widgits Pty Ltd":
            return True, "cluster-4"

        return False, None

class GoziModule1(Module):
    def analyze(self, topic, data):
        if topic != "scan":
            return False, None

        issuer_dn = deep_get(data,'data.tls.result.handshake_log.server_certificates.certificate.parsed.issuer_dn')

        if issuer_dn == "C=XX, ST=1, L=1, O=1, OU=1, CN=*":
            cert = deep_get(data,
                            'data.tls.result.handshake_log.server_certificates.certificate.raw',
                            "")
            cshash = CSHash(cert)
            allowed_hashes = {
                "108d4ee4b9f3cd5c0efba8af2dab5009",
            }
            if cshash in allowed_hashes:
                return True, "cluster-1"
        return False, None

#
class PhishingModule1(Module):
    THRESHOLD = 10000
    BLACKLIST = {"office.com","health.com", "weather.com"}

    def __init__(self, tag):
        super().__init__(tag)
        self.top_domains = self.__load_alexa()

    def __load_alexa(self):
        top_domains = []
        with open("analyzer/data/alexa.csv", "r") as file:
            reader = csv.reader(file)
            count = 0
            for row in reader:
                domain = row[1]
                if count > self.THRESHOLD:
                    break
                if domain in self.BLACKLIST or len(domain < 8):
                    continue
                top_domains.append(domain)
                count += 1
        return top_domains

    def analyze(self, topic, data):
        subject_common_name = deep_get(data,
                                       'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.common_name',
                                       None)
        if subject_common_name:
            subject_common_name = subject_common_name[0]
            for domain in self.top_domains:
                index = subject_common_name.find(domain)
                if index != -1:
                    suffix = index + len(domain) < len(subject_common_name)
                    prefix = index > 0 and subject_common_name[index - 1] != '.'
                    if suffix or prefix:
                        logging.info("prefix phishing")
                        logging.info(subject_common_name)
                        sha1 = deep_get(data,
                                       'data.tls.result.handshake_log.server_certificates.certificate.parsed.fingerprint_sha1',
                                       "")
                        logging.info(sha1)
        return False, None


def main(bootstrap_servers):
    # Logger setup
    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename='analyzer.log',
                        level=logging.DEBUG)

    modules = [IcedidModule1("icedid"), IcedidModule2("icedid"), GoziModule1("gozi"), PhishingModule1("phishing")]
    topics = ["scan", "ct"]
    malware_analyzer = Analyzer(modules, topics, bootstrap_servers)
    malware_analyzer.start()


if __name__ == "__main__":
    with open("config/config.yml", "r") as configFile:
        cfg = yaml.safe_load(configFile)
        main(cfg['kafka']['bootstrap_servers'])