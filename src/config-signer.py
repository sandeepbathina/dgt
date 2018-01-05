#!/usr/bin/python
from __future__ import print_function
import argparse
import os
import logging
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
# Default, basic logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
CONFIG_HEX_DIGEST_SIGN = "integrityd.ini"
class ConfigSigner(object):
    def __init__(self, config_file, private_key, sig_dest):
        self.config_file = config_file
        self.private_key = private_key
        self.sig_dest = sig_dest
    def serialize_and_sign(self):
        gen_sig_file = ''
        private_key = ''
        read_them_up = ''
        get_hex_dig = ''
        # Check if the private key exists
        if os.path.isfile(self.config_file) and os.path.isfile(self.private_key):
            # Read/load private key
            try:
                with open(self.private_key, "rb") as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,
                        backend=default_backend()
                    )
                key_file.close()
            except OSError as e:
                logger.error("Error: file not found")
            try:
                # key serialization
                pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
                logger.debug("Serialized private key: \n {}".format(pem.splitlines()))
            except ValueError as e:
                logger.error("Error: could not serialize key data")
            try:
                # generate sha256 hash of integrityd config file
                hash_configfile_obj = hashlib.sha256(self.config_file)
                get_hex_dig = hash_configfile_obj.hexdigest()
            except IOError as e:
                logger.error(
                    "{0}{1}".format("Error: Failed to compute sha256 hex digest of {}".format(self.config_file),
                                    " OR unable to find {}".format(self.config_file)))
            # Now sign the hex digest
            try:
                if get_hex_dig:
                    signer = private_key.signer(padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                        hashes.SHA256()
                    )
                    signer.update(get_hex_dig)
                    signature = signer.finalize()
                    gen_sig_file = open(self.sig_dest, 'w+')
                    gen_sig_file.write(signature)
                    gen_sig_file.close()
                else:
                    logger.error("Error: Hex digest of the configuration file cannot be NoneType")
            except TypeError as e:
                logger.error("Error: failed to sign integrityd config file hex digest")
        else:
            logger.error("Error: Unable to locate integrityd configuration file or the private key")
        return gen_sig_file
def main():
    argp = argparse.ArgumentParser(description="This program signs integrityd configuration file(s)")
    argp.add_argument('-f', '--configfile', metavar="ConfigurationFile",
                      help="Absolute path to the integrityd configuration file")
    argp.add_argument('-k', '--privatekey', metavar='PrivateKey', help="Absolute path to the integrityd private key")
    argp.add_argument('-d', '--dest', metavar='Destination', help="Absolute path to the destination for the sig file")
    args = argp.parse_args()
    logger.debug("Config file: %s" % args.configfile + " \n" + " Private key: %s" % args.privatekey + " \n" + " Destination: %s" % args.dest)
    # Call signer class
    invoke_signer = ConfigSigner(args.configfile, args.privatekey, args.dest)
    signing_act = invoke_signer.serialize_and_sign()
if __name__ == '__main__':
    main()
