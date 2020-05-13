# MIT License
# Copyright (c) 2020 Tiago Kieliger
# Copyright (c) 2017 Cali Dog Security
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import base64
import datetime
import logging
import time

from collections import OrderedDict

from OpenSSL import crypto
from construct import Struct, Byte, Int16ub, Int64ub, Enum, Bytes, \
    Int24ub, this, GreedyBytes, GreedyRange, Terminated, Embedded


MerkleTreeHeader = Struct(
    "Version"         / Byte,
    "MerkleLeafType"  / Byte,
    "Timestamp"       / Int64ub,
    "LogEntryType"    / Enum(Int16ub, X509LogEntryType=0, PrecertLogEntryType=1),
    "Entry"           / GreedyBytes
)

Certificate = Struct(
    "Length" / Int24ub,
    "CertData" / Bytes(this.Length)
)

CertificateChain = Struct(
    "ChainLength" / Int24ub,
    "Chain" / GreedyRange(Certificate),
)

PreCertEntry = Struct(
    "LeafCert" / Certificate,
    Embedded(CertificateChain),
    Terminated
)

def dump_extensions(certificate):
    extensions = {}
    for x in range(certificate.get_extension_count()):
        extension_name = ""
        try:
            extension_name = certificate.get_extension(x).get_short_name()

            if extension_name == b'UNDEF':
                continue

            extensions[extension_name.decode('latin-1')] = certificate.get_extension(x).__str__()
        except:
            try:
                extensions[extension_name.decode('latin-1')] = "NULL"
            except Exception as e:
                logging.debug("Extension parsing error -> {}".format(e))
    return extensions

def serialize_certificate(certificate):
    subject = certificate.get_subject()
    not_before_datetime = datetime.datetime.strptime(certificate.get_notBefore().decode('ascii'), "%Y%m%d%H%M%SZ")
    not_after_datetime = datetime.datetime.strptime(certificate.get_notAfter().decode('ascii'), "%Y%m%d%H%M%SZ")
    return {
        "subject": {
            "aggregated": repr(certificate.get_subject())[18:-2],
            "C": subject.C,
            "ST": subject.ST,
            "L": subject.L,
            "O": subject.O,
            "OU": subject.OU,
            "CN": subject.CN
        },
        "extensions": dump_extensions(certificate),
        "not_before": not_before_datetime.timestamp(),
        "not_after": not_after_datetime.timestamp(),
        "serial_number": '{0:x}'.format(int(certificate.get_serial_number())),
        "fingerprint": str(certificate.digest("sha1"),'utf-8'),
        "as_der": base64.b64encode(
            crypto.dump_certificate(
                crypto.FILETYPE_ASN1, certificate
            )
        ).decode('utf-8')
    }

def add_all_domains(cert_data):
    all_domains = []

    # Apparently we have certificates with null CNs....what?
    if cert_data['leaf_cert']['subject']['CN']:
        all_domains.append(cert_data['leaf_cert']['subject']['CN'])

    subject_alternative_name = cert_data['leaf_cert']['extensions'].get('subjectAltName')

    if subject_alternative_name:
        for entry in subject_alternative_name.split(', '):
            if entry.startswith('DNS:'):
                all_domains.append(entry.replace('DNS:', ''))

    cert_data['leaf_cert']['all_domains'] = list(OrderedDict.fromkeys(all_domains))

    return cert_data

def parse_ctl_entry(entry, operator_information):
    mtl = MerkleTreeHeader.parse(base64.b64decode(entry['leaf_input']))

    cert_data = {}

    if mtl.LogEntryType == "X509LogEntryType":
        cert_data['update_type'] = "X509LogEntry"
        chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, Certificate.parse(mtl.Entry).CertData)]
        extra_data = CertificateChain.parse(base64.b64decode(entry['extra_data']))
        for cert in extra_data.Chain:
            chain.append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData))
    else:
        cert_data['update_type'] = "PreCertEntry"
        extra_data = PreCertEntry.parse(base64.b64decode(entry['extra_data']))
        chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, extra_data.LeafCert.CertData)]

        for cert in extra_data.Chain:
            chain.append(
                crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData)
            )

    cert_data.update({
        "leaf_cert": serialize_certificate(chain[0]),
        "chain": [serialize_certificate(x) for x in chain[1:]],
        "cert_index": entry['index'],
        "seen": time.time()
    })

    add_all_domains(cert_data)

    cert_data['source'] = {
        "url": operator_information['url'],
        "name": operator_information['description']
    }

    return cert_data