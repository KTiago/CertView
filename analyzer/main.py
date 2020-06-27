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
                and int(validity) == 31536000 \
                and int(key_length) == 2048:
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
            cert = deep_get(data,
                            'data.tls.result.handshake_log.server_certificates.certificate.raw',
                            "")
            cshash = CSHash(cert)
            allowed_hashes = {
                "3fbc3c90292240b7a5e5ff9a7130d59c",
            }

            if cshash in allowed_hashes:
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
                "b00e2855520f59644754e8bfa6dc1821",
            }
            if cshash in allowed_hashes:
                return True, "cluster-1"
        return False, None

class TrickbotModule1(Module):
    def analyze(self, topic, data):
        if topic != "scan":
            return False, None

        issuer_dn = deep_get(data,'data.tls.result.handshake_log.server_certificates.certificate.parsed.issuer_dn')

        if issuer_dn == "C=GB, ST=London, L=London, O=Global Security, OU=IT Department, CN=example.com":
            cert = deep_get(data,
                            'data.tls.result.handshake_log.server_certificates.certificate.raw',
                            "")
            cshash = CSHash(cert)
            allowed_hashes = {
                "b00e2855520f59644754e8bfa6dc1821",
                "612c9021db95bd4323cbcd3d00fedca7",
            }



            if cshash in allowed_hashes:
                return True, "cluster-1"

        return False, None

class DridexModule1(Module):
    def analyze(self, topic, data):
        if topic != "scan":
            return False, None

        issuer_dn = deep_get(data,'data.tls.result.handshake_log.server_certificates.certificate.parsed.issuer_dn')

        if issuer_dn == "O=FASTVPS, CN=parking":
            cert = deep_get(data,
                            'data.tls.result.handshake_log.server_certificates.certificate.raw',
                            "")
            cshash = CSHash(cert)
            allowed_hashes = {
                "0a8940ab07f7dbfabc238c80edb05426",
            }


            if cshash in allowed_hashes:
                return True, "cluster-1"

        return False, None

class QnodeserviceModule1(Module):
    def analyze(self, topic, data):
        if topic == "scan":
            subject_common_name = deep_get(data,'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.common_name', "")
            if subject_common_name:
                subject_common_name = subject_common_name[0]
            else:
                return False, None
        elif topic == "ct":
            subject_common_name = deep_get(data,
                                           'leaf_cert.subject.CN',
                                           "")
        else:
            subject_common_name = ""

        suffixes = ['.ddns.net', '.spdns.org', '.duckdns.org', '.myddns.com']
        for suffix in suffixes:
            length = len(subject_common_name)
            if len(suffix) < length and subject_common_name[length - len(suffix):] == suffix:
                return True, "cluster-1"

        return False, None

class FindposModule1(Module):

    def analyze(self, topic, data):
        if topic != "scan":
            return False, None
        validity = deep_get(data,
                            'data.tls.result.handshake_log.server_certificates.certificate.parsed.validity.length')
        issuer_dn = deep_get(data, 'data.tls.result.handshake_log.server_certificates.certificate.parsed.issuer_dn')

        if issuer_dn == "C=XX, L=Default City, O=Default Company Ltd" and int(validity) == 172800000:
            cert = deep_get(data,
                            'data.tls.result.handshake_log.server_certificates.certificate.raw',
                            "")
            cshash = CSHash(cert)
            allowed_hashes = {
                "d29c030a2687b4e3364811e73700c523",
            }

            if cshash in allowed_hashes:
                return True, "cluster-1"

        return False, None

class CobaltstrikeModule1(Module):
    def analyze(self, topic, data):
        if topic != "scan":
            return False, None


        C = deep_get(data, 'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.country')
        L = deep_get(data, 'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.locality')
        ST = deep_get(data, 'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.province')
        O = deep_get(data,
                     'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.organization')
        OU = deep_get(data,
                      'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.organizational_unit')

        if (C and C[0]=='') or (L and L[0] == '') or (ST and ST[0] == '') or (O and O[0] == '') or (OU and OU[0] == ''):
            cert = deep_get(data,
                            'data.tls.result.handshake_log.server_certificates.certificate.raw',
                            "")
            cshash = CSHash(cert)
            allowed_hashes = {
                "4f8c042aa2987ce4d06797a84b2f832d",
            }
            if cshash in allowed_hashes:
                serial = deep_get(data,
                                  'data.tls.result.handshake_log.server_certificates.certificate.parsed.serial_number')
                if int(serial) == 146473198:
                    return True, "CobaltStrike Default Certificate"
                else:
                    return True, "CobaltStrike C2"

        return False, None

class MetasploitModule1(Module):
    def analyze(self, topic, data):
        if topic != "scan":
            return False, None


        CN = deep_get(data, 'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.common_name')
        OU = deep_get(data,
                      'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.organizational_unit')
        EMAIL = deep_get(data,
                      'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.email_address')

        if (CN and OU and EMAIL and EMAIL[0] == OU[0] + "@" + CN[0]):
            cert = deep_get(data,
                            'data.tls.result.handshake_log.server_certificates.certificate.raw',
                            "")
            cshash = CSHash(cert)
            allowed_hashes = {
                "b432fd10cb96cd7c0d6d07d8ad2afd73",
            }
            if cshash in allowed_hashes:
                return True, "Metasploit C2"

        return False, None

class EmpireModule1(Module):
    def analyze(self, topic, data):
        if topic != "scan":
            return False, None


        CN = deep_get(data, 'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.common_name')
        C = deep_get(data,
                      'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.country')

        if CN is None and C and C[0] == "US":
            cert = deep_get(data,
                            'data.tls.result.handshake_log.server_certificates.certificate.raw',
                            "")
            cshash = CSHash(cert)
            allowed_hashes = {
                "23468ff8bd0e196cdc4fcff56cf8eb7e",
            }
            if cshash in allowed_hashes:
                return True, "Powershell Empire C2"

        return False, None


class PhishingModule1(Module):
    THRESHOLD = 1000
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
                if domain in self.BLACKLIST or len(domain) < 8:
                    continue
                top_domains.append(domain)
                count += 1
        return top_domains

    def analyze(self, topic, data):
        if topic == "ct":
            subject_common_name = deep_get(data,
                                           'leaf_cert.subject.CN',
                                           "")
            if subject_common_name:
                for domain in self.top_domains:
                    index = subject_common_name.find(domain)
                    if index != -1:
                        suffix = index + len(domain) < len(subject_common_name)
                        prefix = index > 0 and subject_common_name[index - 1] != '.'
                        if suffix or prefix:
                            print("prefix phishing")
                            print(subject_common_name)
                            print(domain)
                            sha1 = deep_get(data,
                                           'data.tls.result.handshake_log.server_certificates.certificate.parsed.fingerprint_sha1',
                                           "")
                            print(sha1)
            return False, None
        else:
            return False, None


def main(bootstrap_servers):
    # Logger setup
    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename='analyzer.log',
                        level=logging.DEBUG)

    modules = [IcedidModule1("icedid"), IcedidModule2("icedid"),
               GoziModule1("gozi"),
               TrickbotModule1("trickbot"),
               #QnodeserviceModule1("qnodeservice"),
               #DridexModule1("dridex"),
               FindposModule1("findpos"),
               CobaltstrikeModule1("cobaltstrike"),
               MetasploitModule1("metasploit"),
               EmpireModule1("empire"),
               ]#, PhishingModule1("phishing")]
    topics = ["scan", "ct"]
    malware_analyzer = Analyzer(modules, topics, bootstrap_servers)
    malware_analyzer.start()


if __name__ == "__main__":
    with open("config/config.yml", "r") as configFile:
        cfg = yaml.safe_load(configFile)
        main(cfg['kafka']['bootstrap_servers'])