#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import argparse
import os
import sys

if sys.version_info[:2] < (3, 6):
    sys.exit("You are running an incompatible version of Python, please use >= 3.6")
import logging
import requests

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

import lib.cuckoo.common.colors as colors
from lib.cuckoo.common.constants import CUCKOO_ROOT

log = logging.getLogger(__name__)
DOMAINS_URL = 'https://raw.githubusercontent.com/intezer/CAPEv2/master/extra/whitelist_domains.txt'
CIDR_URL = 'https://raw.githubusercontent.com/intezer/CAPEv2/master/extra/whitelist_cidrs.txt'


def refresh_whitelist_file(url: str, user: str, password: str, path: str = None):
    remote_content = requests.get(url, auth=(user, password)).content.decode()
    with open(path, 'w') as f:
        f.write(remote_content)

    print('File "{}" {}'.format(path, colors.green("updated")))


def refresh_files(user: str, password: str):
    try:
        refresh_whitelist_file(DOMAINS_URL, user, password, os.path.join(CUCKOO_ROOT, 'extra/whitelist_domains.txt'))
        refresh_whitelist_file(CIDR_URL, user, password, os.path.join(CUCKOO_ROOT, 'extra/whitelist_cidrs.txt'))
    except Exception as e:
        print('ERROR: Unable to update whitelist files')
        sys.exit(-1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--user", help="User name in github", type=str, required=False)
    parser.add_argument("-p", "--password", help="App password in github", type=str, required=False)
    args = parser.parse_args()

    refresh_files(args.user, args.password)


if __name__ == "__main__":
    main()
