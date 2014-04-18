#! /usr/bin/env python
import argparse
import logging

import bencode
import requests

def get_auth_token(credential_file):
    # TODO(hammer): handle URLs and files
    r = requests.get(credential_file)
    auth_token = r.text
    return auth_token

def get_gto_dict(content_specifier, auth_token):
    # TODO(hammer): handle non-URIs
    payload = {'token': auth_token}
    r = requests.post(content_specifier, data=payload)
    gto_dict = bencode.bdecode(r.text)
    return gto_dict

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
        gto_dict = get_gto_dict(content_specifier, auth_token)
        logging.debug('Got gto_dict: %s' % gto_dict.get('info').get('name'))
