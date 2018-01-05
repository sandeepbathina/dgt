#!/usr/bin/python
from __future__ import print_function
class PyinotifyError(Exception):
    """Indicates exceptions raised by a Pyinotify class."""
    pass
class UnsupportedPythonVersionError(PyinotifyError):
    """
    Raised on unsupported Python versions.
    """
    def __init__(self, version):
        """
        :param version: Current Python version
        """
        err = 'Python %s is unsupported, requires at least Python 2.7+'
        PyinotifyError.__init__(self, err % version)
# Check Python version
import sys
if sys.version_info < (2, 7):
    raise UnsupportedPythonVersionError(sys.version)
# Import directives
import os
import requests
import hashlib
import argparse

import stat
import smtplib
import datetime
import pem
import logging.handlers

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID
from cryptography.exceptions import InvalidSignature
try:
    import configparser
except ImportError:
    import ConfigParser  # version < Py3
# Default, basic logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# Set up integrityd syslog handler
import logging, sys
from logging import config

# maximum allowed length for maintenance window (in seconds)
MAX_ALLOWED_MAINTENANCE_WINDOW = 21600
DEFAULT_MAINTENANCE_WINDOW = 3600
COUNTER = 0
THRESHOLD = 300

class ValidateSignedArtifact(object):
    def __init__(self, config_file="config.cfg", sig_file="test.sig", cert_chain="chain.pem",
                 chain_perm="0705", root_ca_oid="", signing_machine='ultra.apple.com'):
        self.config_file = config_file
        self.sig_file = sig_file
        self.cert_chain = cert_chain
        self.chain_perm = chain_perm
        self.root_ca_oid = root_ca_oid
        self.signing_machine = signing_machine
    def eval_pem(self):
        pem_chain = []
        # if os.path.exists(self.config_file):
        if not os.path.exists(self.config_file):
            return None
        # Verify that the pem chain exists
        if not os.path.exists(self.cert_chain):
            print("marker=ValidateSignedArtifact, msg=error -> cannot stat: %s" % self.cert_chain)
            return None
        # Verify the file permissions for certain chain in rootspace
        # file perm should be 0705
        if oct(stat.S_IMODE(os.stat(self.cert_chain).st_mode)) != self.chain_perm:
            print("marker=ValidateSignedArtifact, msg=error -> permissions for %s is not 0705" % self.cert_chain)
            return None
        # Check the owner and group privileges of self.cert_chain
        # note: cert chain should be root:root
        # if os.stat(self.cert_chain).st_uid != 0 or os.stat(self.cert_chain).st_gid != 0:
        #     print("marker=ValidateSignedArtifact, msg=error -> owner and/or group permissions does not compute to "
        #               "root for {}".format(self.cert_chain))
        #     return None
        # Load cert chain to confirm the chain length
        pem_chain = pem.parse_file(self.cert_chain)
        # Rudimentary length check
        if not pem_chain:
            print("marker=ValidateSignedArtifact, msg=error -> file type is not PEM!")
            return None
        if len(pem_chain) != 3:
            print("marker=ValidateSignedArtifact, msg=error -> incorrect certificate chain"
                  " length for: {}".format(self.cert_chain))
            return None
        return pem_chain
    def eval_chain_of_trust(self, pem_chain):
        if pem_chain is None:
            return None
            # load X509's in the following order:
            # Leaf
            # Intermediate
            # Root
        load_x509_leaf = x509.load_pem_x509_certificate(str(pem_chain[0]), default_backend())
        load_x509_intermediate = x509.load_pem_x509_certificate(str(pem_chain[1]), default_backend())
        load_x509_root = x509.load_pem_x509_certificate(str(pem_chain[2]), default_backend())
        pem_chain_dict = dict(x509_leaf=load_x509_leaf,
                              x509_intermediate=load_x509_intermediate,
                              x509_root=load_x509_root)
        cert_counter = 0
        # check 1: first and foremost, validate leaf CN
        # check 1a: leaf issuer should be the same as intermediate subject
        # get details on Leaf Issuer
        leaf_issuer = load_x509_leaf.issuer
        leaf_subject = load_x509_leaf.subject
        leafCN_subject = leaf_subject.get_attributes_for_oid(NameOID.COMMON_NAME).pop()._value
        leafCN = leaf_issuer.get_attributes_for_oid(NameOID.COMMON_NAME).pop()._value
        leafOU = leaf_issuer.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME).pop()._value
        leafO = leaf_issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME).pop()._value
        leafC = leaf_issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME).pop()._value
        leaf_issuer_tuple = (str(leafCN), str(leafOU), str(leafO), str(leafC))
        # get details on Intermediate Subject
        intermediate_subject = load_x509_intermediate.subject
        intermediateCN = intermediate_subject.get_attributes_for_oid(NameOID.COMMON_NAME).pop()._value
        intermediateOU = intermediate_subject.get_attributes_for_oid(
            NameOID.ORGANIZATIONAL_UNIT_NAME).pop()._value
        intermediateO = intermediate_subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME).pop()._value
        intermediateC = intermediate_subject.get_attributes_for_oid(NameOID.COUNTRY_NAME).pop()._value
        intermediate_subject_tuple = (
            str(intermediateCN), str(intermediateOU), str(intermediateO), str(intermediateC))
        if str(leafCN_subject) != str(self.signing_machine) or sorted(leaf_issuer_tuple) != sorted(
                intermediate_subject_tuple):
            print("marker=ValidateSignedArtifact, msg=error -> leaf issuer does not match with the intermediate "
                  "subject")
            return None
        cert_counter += 1
        # check 2: Intermediate issuer should be the same as Root subject
        # get details on Intermediate Issuer
        intermediate_issuer = load_x509_intermediate.issuer
        intermediateCN = intermediate_issuer.get_attributes_for_oid(NameOID.COMMON_NAME).pop()._value
        intermediateO = intermediate_issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME).pop()._value
        intermediateC = intermediate_issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME).pop()._value
        intermediate_issuer_tuple = (str(intermediateC), str(intermediateO), str(intermediateCN))
        # get details on root subject
        root_subject = load_x509_root.subject
        rootCN = root_subject.get_attributes_for_oid(NameOID.COMMON_NAME).pop()._value
        rootO = root_subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME).pop()._value
        rootC = root_subject.get_attributes_for_oid(NameOID.COUNTRY_NAME).pop()._value
        root_subject_tuple = (str(rootC), str(rootO), str(rootCN))
        if sorted(intermediate_issuer_tuple) != sorted(root_subject_tuple):
            print("marker=ValidateSignedArtifact, msg=error -> issuer for intermediate cert does not match with "
                  "root subject")
            return None
        cert_counter += 1
        # check 3: Root issuer and Root subject
        # get details on root issuer
        root_issuer = load_x509_root.issuer
        rootCN = root_issuer.get_attributes_for_oid(NameOID.COMMON_NAME).pop()._value
        rootO = root_issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME).pop()._value
        rootC = root_issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME).pop()._value
        root_issuer_tuple = (str(rootC), str(rootO), str(rootCN))
        if sorted(root_issuer_tuple) != sorted(root_subject_tuple):
            print("marker=ValidateSignedArtifact, msg=error -> issuer and subject does not match for root CA")
            return None
        # Check basic constraints for root
        basic_constraint = load_x509_root.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS).value.ca
        root_ca_oid = load_x509_root.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS).value.oid
        if not basic_constraint or root_ca_oid.dotted_string != self.root_ca_oid:
            print("marker=ValidateSignedArtifact, msg=error -> root CA OID mismatch OR basic constraints check "
                  "for root CA failed")
            return None
        cert_counter += 1
        if cert_counter != 3:
            print("marker=ValidateSignedArtifact, msg=error -> cert chain length is not equal to 3")
            return None
        # Check cert expiration for leaf, intermediate and root
        current_date_time = datetime.datetime.now().replace(second=0, microsecond=0)
        leaf_not_valid_after = load_x509_leaf.not_valid_after
        intermediate_not_valid_after = load_x509_intermediate.not_valid_after
        root_not_valid_after = load_x509_root.not_valid_after
        if current_date_time > leaf_not_valid_after:
            print("marker=ValidateSignedArtifact, msg=error -> leaf/entity cert has expired!")
            return None
        if current_date_time > intermediate_not_valid_after:
            print("marker=ValidateSignedArtifact, msg=error -> intermediate cert has expired!")
            return None
        if current_date_time > root_not_valid_after:
            print("marker=ValidateSignedArtifact, msg=error -> root CA has expired!")
            return None
        return pem_chain_dict
    def eval_crl(self, pem_chain_dict):
        if pem_chain_dict is None:
            return None
        crl_list = list()
        crl_list.append(pem_chain_dict["x509_leaf"].extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS).value._distribution_points.pop()._full_name.pop().value)
        crl_list.append(pem_chain_dict["x509_intermediate"].extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS).value._distribution_points.pop()._full_name.pop().value)
        crl_headers = {'Content-Type': 'application/pkix-crl'}
        for crl in crl_list:
            # download the crl
            r = requests.get(str(crl), headers=crl_headers)
            if r.status_code != 200:
                print("marker=ValidateSignedArtifact, msg=error -> failed to download crl"
                      " data from: {}".format(str(crl)))
                return None
            # load and parse crl data
            # Remember -> the crl is DER encoded!
            load_crl = x509.load_der_x509_crl(r.content, default_backend())
            # get the issuer and validate
            if str(load_crl.issuer.get_attributes_for_oid(NameOID.COMMON_NAME).pop()._value) == \
                    "G1" or \
                            str(load_crl.issuer.get_attributes_for_oid(NameOID.COMMON_NAME).pop()._value) \
                            == "GeoTrust Global CA":
                pass
            else:
                print(
                    "marker=ValidateSignedArtifact, msg=error -> crl issuer mismatch for leaf and/or intermediate")
                return None
            # Compute crl last and next update
            # last update should be current biz date
            # next update should be greater than current biz date
            # crl_last_update = load_crl.last_update.date()
            crl_next_update = load_crl.next_update.date()
            """
            if crl_last_update != datetime.datetime.now().date():
                print("marker=ValidateSignedArtifact, error=crl last update time is less than: %s" % datetime.datetime.now().date())
                sys.exit(-1)
            """
            if crl_next_update < datetime.datetime.now().date():
                print(
                    "marker=ValidateSignedArtifact, msg=error -> crl next update is less than: %s" % datetime.datetime.now().date())
                return None
            # load crl signatures
            revoked_serial_num = list()
            for rcert in load_crl:
                revoked_serial_num.append(rcert.serial_number)
            for revoked in revoked_serial_num:
                if pem_chain_dict["x509_leaf"].serial == revoked:
                    print("marker=ValidateSignedArtifact, msg=error -> leaf cert is revoked!")
                    return None
            for revoked in revoked_serial_num:
                if pem_chain_dict["x509_intermediate"].serial == revoked:
                    print("marker=ValidateSignedArtifact, msg=error -> intermediate cert is revoked")
                    return None
        return pem_chain_dict
    def eval_signature(self, pem_chain_dict):
        if pem_chain_dict is None:
            return None
        # Extract public cert from leaf
        pub_key_from_leaf = pem_chain_dict["x509_leaf"].public_key()
        # Read the signed artifact signature file into a buffer
        load_sig = open(self.sig_file, 'r')
        signature = load_sig.read()
        load_sig.close()
        # Independently calculate SHA256 of the configuration file
        try:
            # generate sha256 hash of integrityd config file
            # hash_configfile_obj = hashlib.sha256(self.config_file)
            # eval_hex_dig = hash_configfile_obj.hexdigest()
            fd = open(self.config_file, 'r')
            message = fd.read()
            fd.close()
        except (IOError, TypeError, OSError) as e:
            print("marker=ValidateSignedArtifact, msg=error -> failed to compute SHA256 of integrityd config file")
            return None
        verify_sig = pub_key_from_leaf.verifier(signature,
                                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                            salt_length=padding.PSS.MAX_LENGTH),
                                                hashes.SHA256())
        verify_sig.update(message)
        try:
            verify_sig.verify()
            print("marker=ValidateSignedArtifact, msg=success -> successful validation of signed artifact")
            return dict(valid_signature="pass")
        except InvalidSignature as e:
            print("marker=ValidateSignedArtifact, msg=error -> failed to validate signed artifact")
            return dict(valid_signature="fail")

def main():
    argp = argparse.ArgumentParser(description="integrityd - it really whips the server's a$$!")
    argp.add_argument('-c', '--configfile', metavar="ConfigurationFile",
                      help="Absolute path to the integrityd configuration file")
    argp.add_argument('-s', '--signature_file', metavar='SigFile', help="Absolute path to the signature file")
    args = argp.parse_args()
    global file_status
    file_status = ''
    eval_pid = ''
    # Define Constants
    # cert_chain, cert_chain_perm and root_ca_oid will be hardcoded
    cert_chain = "chain.pem"
    cert_chain_perm = "0705"
    signing_machine = "ultra.apple.com"
    # Check if secure load env var is set
    if os.getenv('DISABLE_SECURE_LOAD') is None:
        validate = ValidateSignedArtifact(config_file=args.configfile, sig_file=args.signature_file,
                                          cert_chain=cert_chain, chain_perm=cert_chain_perm,
                                          root_ca_oid=root_ca_oid, signing_machine=signing_machine)
        pem_chain = validate.eval_pem()
        eval_pem_chain = validate.eval_chain_of_trust(pem_chain)
        eval_crl = validate.eval_crl(eval_pem_chain)
        eval_artifact_signature = validate.eval_signature(eval_pem_chain)
        print(eval_artifact_signature)


if __name__ == '__main__':
    main()
