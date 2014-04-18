#! /usr/bin/env python
import argparse
import hashlib
import logging

import bencode
from Crypto.PublicKey import RSA
import pkiutils
import requests

GT_CERT_SIGN_TAIL = 'gtsession'
RSA_KEY_SIZE = 1024
RSA_EXPONENT = 65537 # RSA_F4
DISTINGUISHED_NAME = {
    'c': 'US',
    'st': 'CA',
    'l': 'San Jose',
    'o': 'ploaders, Inc',
    'ou': 'staff',
    'cn': 'www.uploadersinc.com',
    'emailaddress': 'root@uploadersinc.com',
}

def get_auth_token(credential_file):
    # TODO(hammer): handle URLs and files
    r = requests.get(credential_file)
    auth_token = r.content
    return auth_token

def get_gto_dict(content_specifier, auth_token):
    # TODO(hammer): handle non-URIs
    payload = {'token': auth_token}
    r = requests.post(content_specifier, data=payload)
    gto_dict = bencode.bdecode(r.content)
    return gto_dict

def get_cert_sign_url(content_specifier):
    # TODO(hammer): handle exceptions
    url_marker = '/cghub/data/'
    return content_specifier.split(url_marker)[0] + url_marker + GT_CERT_SIGN_TAIL

def get_info_hash(gto_dict):
    return hashlib.sha1(bencode.bencode(gto_dict.get('info'))).hexdigest()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--credential-file', dest='credential_file', required=True)
    parser.add_argument('-d', dest='content_specifiers', nargs='+', required=True)
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()
    if args.verbose: logging.basicConfig(level=logging.DEBUG)
    logging.debug('Parsed argument credential_file: %s' % args.credential_file)
    logging.debug('Parsed argument content_specifiers: %s' % args.content_specifiers)

    auth_token = get_auth_token(args.credential_file)
    logging.debug('Got auth_token: %s' % auth_token)

    for content_specifier in args.content_specifiers:
        # Get torrent information
        gto_dict = get_gto_dict(content_specifier, auth_token)
        logging.debug('Got gto_dict: %s' % gto_dict.get('info').get('name'))

        # Authenticate
        cert_sign_url = get_cert_sign_url(content_specifier)
        logging.debug('Got cert_sign_url: %s' % cert_sign_url)
        info_hash = get_info_hash(gto_dict)
        logging.debug('Got info_hash: %s' % info_hash)
        rsa = RSA.generate(bits=RSA_KEY_SIZE, e=RSA_EXPONENT)
        logging.debug('RSA keypair generated; public key: %s' % rsa.publickey().exportKey())
        pkiutils.create_csr(rsa, DISTINGUISHED_NAME)

        # TODO(hammer): Download
