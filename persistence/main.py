import argparse

import confluent_kafka
from elasticsearch import Elasticsearch
import json
import sys


def main(bootstrap_servers):
    consumerConfiguration = {'bootstrap.servers': bootstrap_servers,
                             'group.id': "elasticsearch",
                             'session.timeout.ms': 6000,
                             'auto.offset.reset': 'earliest'}
    consumer = confluent_kafka.Consumer(consumerConfiguration)
    consumer.subscribe(["scan", "ct", "tags"])

    # Elasticsearch configuration
    es = Elasticsearch([{'host': 'localhost', 'port': 9200}])

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
                    value = json.loads(msg.value())
                    data = value['data']
                    date = value['date']

                    try:
                        sha1 = \
                            data['data']['tls']['result']['handshake_log']['server_certificates']['certificate'][
                                'parsed'][
                                'fingerprint_sha1']
                    except KeyError:
                        continue

                    raw = data['data']['tls']['result']['handshake_log']['server_certificates']['certificate']['raw']

                    try:
                        issuer_common_name = \
                            data['data']['tls']['result']['handshake_log']['server_certificates']['certificate'][
                                'parsed'][
                                'issuer']['common_name']
                    except KeyError:
                        issuer_common_name = ""

                    try:
                        subject_common_name = \
                            data['data']['tls']['result']['handshake_log']['server_certificates']['certificate'][
                                'parsed'][
                                'subject']['common_name']
                    except KeyError:
                        subject_common_name = ""

                    tls_version = data['data']['tls']['result']['handshake_log']['server_hello']['version']['value']
                    tls_cipher_suite = data['data']['tls']['result']['handshake_log']['server_hello']['cipher_suite'][
                        'hex']

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

                    res = es.index(index="certificates", id=sha1, body=body)

                    body = {
                        "ip": data['ip'],
                        "date": data['data']['tls']['timestamp'],
                        "md5":
                            data['data']['tls']['result']['handshake_log']['server_certificates']['certificate'][
                                'parsed'][
                                'fingerprint_md5'],
                        "sha1":
                            data['data']['tls']['result']['handshake_log']['server_certificates']['certificate'][
                                'parsed'][
                                'fingerprint_sha1'],
                        "sha256": data['data']['tls']['result']['handshake_log']['server_certificates']['certificate'][
                            'parsed'][
                            'fingerprint_sha256'],
                    }
                    res = es.index(index="hosts_{date}".format(date=date), id=id, body=body)
                elif topic == "ct":
                    value = json.loads(msg.value())
                    data = value['data']
                    date = value['date']

                    try:
                        sha1 = data['leaf_cert']['fingerprint'].lower().replace(":", "")
                    except:
                        continue

                    body = {
                        "date": date,
                        "sha1": sha1,
                        "issuer_common_name": data["chain"][0]["subject"]["CN"],
                        "subject_common_name": data["leaf_cert"]["subject"]["CN"],
                        "raw": data["leaf_cert"]["as_der"],
                        "ct": True,
                    }
                    res = es.index(index="certificates", id=sha1, body=body)
                    pass
                elif msg.topic() == "tags":
                    body = json.loads(msg.value())
                    res = es.index(index="tags", body=body)

    except KeyboardInterrupt:
        sys.stderr.write('Aborted by user\n')

    finally:
        consumer.close()


{'update_type': 'X509LogEntry',
 'leaf_cert': {'subject': {
    'aggregated': '/C=NL/L=Petten/O=Nuclear Research and consultancy Group/OU=Information Technology Services/CN=members.nucleairnederland.nl',
    'C': 'NL', 'ST': None, 'L': 'Petten', 'O': 'Nuclear Research and consultancy Group',
    'OU': 'Information Technology Services', 'CN': 'members.nucleairnederland.nl'}, 'extensions': {
    'authorityKeyIdentifier': 'keyid:67:FD:88:20:14:27:98:C7:09:D2:25:19:BB:E9:51:11:63:75:50:62\n',
    'subjectKeyIdentifier': '66:6F:A9:A7:5C:C0:0D:4B:67:07:47:C0:B4:A1:30:AB:E8:F7:7F:FF',
    'subjectAltName': 'DNS:members.nucleairnederland.nl', 'keyUsage': 'Digital Signature, Key Encipherment',
    'extendedKeyUsage': 'TLS Web Server Authentication, TLS Web Client Authentication',
    'crlDistributionPoints': '\nFull Name:\n  URI:http://crl3.digicert.com/TERENASSLCA3.crl\n\nFull Name:\n  URI:http://crl4.digicert.com/TERENASSLCA3.crl\n',
    'certificatePolicies': 'Policy: 2.16.840.1.114412.1.1\n  CPS: https://www.digicert.com/CPS\nPolicy: 2.23.140.1.2.2\n',
    'authorityInfoAccess': 'OCSP - URI:http://ocsp.digicert.com\nCA Issuers - URI:http://cacerts.digicert.com/TERENASSLCA3.crt\n',
    'basicConstraints': 'CA:FALSE',
    'ct_precert_scts': 'Signed Certificate Timestamp:\n    Version   : v1 (0x0)\n    Log ID    : 29:79:BE:F0:9E:39:39:21:F0:56:73:9F:63:A5:77:E5:\n                BE:57:7D:9C:60:0A:F8:F9:4D:5D:26:5C:25:5D:C7:84\n    Timestamp : Apr 23 13:22:02.313 2020 GMT\n    Extensions: none\n    Signature : ecdsa-with-SHA256\n                30:46:02:21:00:8C:54:E2:0A:93:B2:C4:A7:31:34:6E:\n                CB:89:D8:20:80:AC:65:5A:53:D7:B2:0F:EE:10:17:53:\n                6F:61:8B:7A:E3:02:21:00:D5:51:F3:BC:39:F5:09:BC:\n                EB:65:97:C2:0D:C5:D4:4B:DE:0B:1A:71:60:C8:C4:69:\n                FB:71:86:63:B7:EA:A7:7D\nSigned Certificate Timestamp:\n    Version   : v1 (0x0)\n    Log ID    : 22:45:45:07:59:55:24:56:96:3F:A1:2F:F1:F7:6D:86:\n                E0:23:26:63:AD:C0:4B:7F:5D:C6:83:5C:6E:E2:0F:02\n    Timestamp : Apr 23 13:22:02.375 2020 GMT\n    Extensions: none\n    Signature : ecdsa-with-SHA256\n                30:45:02:21:00:ED:82:3A:78:B6:AF:87:13:4D:7A:F8:\n                E8:D7:B5:A6:D0:A1:D8:FB:33:65:86:28:D0:CA:58:AD:\n                B5:CD:02:4F:FA:02:20:04:11:FE:D3:BB:D7:79:4D:82:\n                43:EC:2E:DA:55:B8:4D:EE:A6:0F:45:33:F7:E8:7A:06:\n                98:AA:75:98:E0:BC:22\nSigned Certificate Timestamp:\n    Version   : v1 (0x0)\n    Log ID    : 41:C8:CA:B1:DF:22:46:4A:10:C6:A1:3A:09:42:87:5E:\n                4E:31:8B:1B:03:EB:EB:4B:C7:68:F0:90:62:96:06:F6\n    Timestamp : Apr 23 13:22:02.251 2020 GMT\n    Extensions: none\n    Signature : ecdsa-with-SHA256\n                30:46:02:21:00:B7:EB:39:1D:CF:EE:11:21:05:F9:6B:\n                D4:1B:56:9B:CE:7A:AE:7E:CF:0B:D5:62:4A:A2:1F:1E:\n                C9:DB:D6:EE:68:02:21:00:A4:45:55:B8:25:1D:A7:C6:\n                46:F0:2A:0F:FF:B0:5A:24:00:CE:18:A9:77:7C:8F:5B:\n                FF:E6:4B:7A:09:21:C6:21'},
                                              'not_before': 1587614400.0, 'not_after': 1651161600.0,
                                              'serial_number': 'ea5bd4a372c2aa0d37aa720679ad068',
                                              'fingerprint': '2A:A0:1E:45:6A:19:70:AC:A3:E0:C2:42:D2:D3:35:7D:3C:DC:EF:10',
                                              'as_der': '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',
                                              'all_domains': ['members.nucleairnederland.nl']},
 'chain': [{'subject': {
    'aggregated': '/C=NL/ST=Noord-Holland/L=Amsterdam/O=TERENA/CN=TERENA SSL CA 3', 'C': 'NL', 'ST': 'Noord-Holland',
    'L': 'Amsterdam', 'O': 'TERENA', 'OU': None, 'CN': 'TERENA SSL CA 3'}, 'extensions': {
    'basicConstraints': 'CA:TRUE, pathlen:0', 'keyUsage': 'Digital Signature, Certificate Sign, CRL Sign',
    'authorityInfoAccess': 'OCSP - URI:http://ocsp.digicert.com\nCA Issuers - URI:http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt\n',
    'crlDistributionPoints': '\nFull Name:\n  URI:http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl\n\nFull Name:\n  URI:http://crl4.digicert.com/DigiCertAssuredIDRootCA.crl\n',
    'certificatePolicies': 'Policy: X509v3 Any Policy\n  CPS: https://www.digicert.com/CPS\n',
    'subjectKeyIdentifier': '67:FD:88:20:14:27:98:C7:09:D2:25:19:BB:E9:51:11:63:75:50:62',
    'authorityKeyIdentifier': 'keyid:45:EB:A2:AF:F4:92:CB:82:31:2D:51:8B:A7:A7:21:9D:F3:6D:C8:0F\n'},
                                                                                                           'not_before': 1416330000.0,
                                                                                                           'not_after': 1731949200.0,
                                                                                                           'serial_number': '870bcc5af3fdb959a91cb6aeeefe465',
                                                                                                           'fingerprint': '77:B9:9B:B2:BD:75:22:E1:7E:C0:99:EA:71:77:51:6F:27:78:7C:AD',
                                                                                                           'as_der': 'MIIE+zCCA+OgAwIBAgIQCHC8xa8/25Wakctq7u/kZTANBgkqhkiG9w0BAQsFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMTQxMTE4MTIwMDAwWhcNMjQxMTE4MTIwMDAwWjBkMQswCQYDVQQGEwJOTDEWMBQGA1UECBMNTm9vcmQtSG9sbGFuZDESMBAGA1UEBxMJQW1zdGVyZGFtMQ8wDQYDVQQKEwZURVJFTkExGDAWBgNVBAMTD1RFUkVOQSBTU0wgQ0EgMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMV2Dw/ZQyk7bG3RR63eEL8jwnioSnc18SNb4EweQefCMQC9iDdFdd25AhCAHo/tZCMERaegOTuBTc9jP8JJ/yKeiLDSlrlcinQfkioq8hLIt2hUtVhBgUBoBhpPhSn7tU08D08/QJYbzqjMXjX/ZJj1dd10VAWgNhEEEiRVY++Udy538RV27tOkWUUhn6i+0SftCuirOMo/h9Ha8Y+5Cx9E5+Ct85XCFk3shKM6ktTPxn3mvcsaQE+zVLHzj28NHuO+SaNW5Ae8jafOHbBbV1bRxBz8mGXRzUYvkZS/RYVJ+G1ShxwCVgEnFqtyLvRx5GG1IKD6JmlqCvGrn223zyUCAwEAAaOCAaYwggGiMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MIGBBgNVHR8EejB4MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMB0GA1UdDgQWBBRn/YggFCeYxwnSJRm76VERY3VQYjAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzANBgkqhkiG9w0BAQsFAAOCAQEAqSg1esR71tonHqyYzyc2TxEydHTmQN0dzfJodzWvs4xdxgS/FfQjZ4u5b5cE60adws3J0aSugS7JurHogNAcyTnBVnZZbJx946nw09E02DxJWYsamM6/xvLYMDX/6W9doK867mZTrqqMaci+mqege9iCSzMTyAfzd9fzZM2eY/lCJ1OuEDOJcjcV8b73HjWizsMt8tey5gvHacDlH198aZt+ziYaM0TDuncFO7pdP0GJ+hY77gRuW6xWS++McPJKe1e9GW6LNgdUJi2GCZQfXzer8CM/jyxflp5HcahE3qm5hS+1NGClXwmgmkMd1L8tRNaN2v11y18WoA5hwnA9Ng=='},
  {'subject': {
      'aggregated': '/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Assured ID Root CA',
      'C': 'US',
      'ST': None,
      'L': None,
      'O': 'DigiCert Inc',
      'OU': 'www.digicert.com',
      'CN': 'DigiCert Assured ID Root CA'},
   'extensions': {
       'keyUsage': 'Digital Signature, Certificate Sign, CRL Sign',
       'basicConstraints': 'CA:TRUE',
       'subjectKeyIdentifier': '45:EB:A2:AF:F4:92:CB:82:31:2D:51:8B:A7:A7:21:9D:F3:6D:C8:0F',
       'authorityKeyIdentifier': 'keyid:45:EB:A2:AF:F4:92:CB:82:31:2D:51:8B:A7:A7:21:9D:F3:6D:C8:0F\n'},
   'not_before': 1163134800.0,
   'not_after': 1952053200.0,
   'serial_number': 'ce7e0e517d846fe8fe560fc1bf03039',
   'fingerprint': '05:63:B8:63:0D:62:D7:5A:BB:C8:AB:1E:4B:DF:B5:A8:99:B2:4D:43',
   'as_der': 'MIIDtzCCAp+gAwIBAgIQDOfg5RfYRv6P5WD8G/AwOTANBgkqhkiG9w0BAQUFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMDYxMTEwMDAwMDAwWhcNMzExMTEwMDAwMDAwWjBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtDhXO5EOAXLGH87dg+XESpa7cJpSIqvTO9SA5KFhgDPiA2qkVlTJhPLWxKISKityfCgyDF3qPkKyK53lTXDGEKvYPmDI2dsze3Tyoou9q+yHyUmHfnyDXH+Kx2f4YZNISW1/5WBg1vEfNoTb5a3/UsDg+wRvDjDPZ2C8Y/igPs6eD1sNuRMBhNZYW/lmci3Zt1/GiSw0r/wty2p5g0I6QNcZ4VYcgoc/lbQrISXwxmDNsIumH0DJaoroTghHtORedmTpyoeb6pNnVFzF1roV9Iq4/AUaG9ih5yLHa5FcXxH4cDrC0kqZWs72yl+2qp/C3xag/lRbQ/6GW6whfGHdPAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRF66Kv9JLLgjEtUYunpyGd823IDzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzANBgkqhkiG9w0BAQUFAAOCAQEAog683+Lt8ONyc3pklL/3cmbYMuRCdWKuh+vy1dneVrOfzM4UKLkNl2BcEkxY5NM9g0lFWJc1aRqoR+pWxnmrEthngYTffwk8lOa4JiwgvT2zKIn3X/8i4peEH+ll74fg38FnSbNd67IJKusm7Xi+fT8r87cmNW1fiQG2SVufAQWbqz0lwcy2f8Lxb4bG+mRo64EtlOtCt/qMHt1i8b5QZ7dsvfPxH2sMNgcWfzd8qVttevESRmCD1ycEvkvOl77DZypoEd+A5wwzZr8TDRRu838fYxAe+o0bJW1sj6W3YQGx0qMmoRBxna3iw/nDmVG3KwcIzi7mULKn+gpFL6Lw8g=='}],
 'cert_index': 13759504, 'seen': 1589440840.6499486,
 'source': {'url': 'ct.googleapis.com/submariner', 'name': "Google 'Submariner' log"}}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Kafka consumer which persists certificates to Elasticsearch')
    parser.add_argument('--bootstrap_servers', default="localhost:9092", help='Comma separated list of brokers')
    args = parser.parse_args()

    main(args.bootstrap_servers)
