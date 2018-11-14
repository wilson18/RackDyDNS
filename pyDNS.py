#!/usr/bin/env python2
import json
import keyring
import os
import pyrax
import socket

from requests import get

pyrax.set_setting("identity_type", "rackspace")

# Config file path
CONFIG_FILE = "config.json"

# API Global Settings read from config file
ACCOUNT_NUMBER = ""
API_KEY = ""
DOMAIN = ""
SUBDOMAIN = ""
DNS = None

# Exit Codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_ERROR_INVALID_CONFIG = 2


def main():
    global DOMAIN, DNS
    parse_config()
    ip_addr = get_ipv4()

    setup_api()
    DNS = pyrax.cloud_dns

    record = get_record()
    if record is not None:
        update_record_ip(record, ip_addr)
    else:
        print("Creating record")
        create_record(ip_addr)

def get_record():
    global DOMAIN, DNS, SUBDOMAIN
    fqdn = SUBDOMAIN + "." + DOMAIN
    record = None
    print("Searching for {fqdn}".format(fqdn=fqdn))
    all_records = DNS.list_records(DOMAIN)
    for this_record in all_records:
        if this_record.name.lower() == fqdn.lower():
            record = this_record
            break

    return record

def create_record(ip_addr):
    global DOMAIN, DNS, SUBDOMAIN
    fqdn = SUBDOMAIN + "." + DOMAIN
    record = {
        "type": "A",
        "name": fqdn,
        "data": ip_addr,
        "ttl": 3600,
    }
    # or
    DNS.add_records(DOMAIN, record)
    print("Record created for {subdomain} => {ip}".format(subdomain=fqdn, ip=ip_addr))


def update_record_ip(record, ip):
    if ip != record.data:
        print("Updating Record")
        record.update(data=ip)
        print("IP updated to {ip}".format(ip=ip))
    else:
        print("IP Address up to date.")
    return


def get_ipv4():
    return get('https://api.ipify.org').text


def get_hostname():
    return socket.gethostname()


def get_file_contents(file_path):
    file_contents = ""

    if os.path.exists(file_path):
        with open(file_path, 'r') as file_handle:
            file_contents = file_handle.read()

    return file_contents


def validate_text(text):
    return text != "" and text != None


def parse_config():
    global ACCOUNT_NUMBER, API_KEY, DOMAIN, SUBDOMAIN
    if not os.path.exists(CONFIG_FILE):
        print("Unable to read file {config_file}".format(config_file=CONFIG_FILE))
        exit(EXIT_ERROR_INVALID_CONFIG)

    json_text = get_file_contents(CONFIG_FILE)
    loaded_json = {}
    try:
        loaded_json = json.loads(json_text)
    except ValueError:
        print("Unable to decode {config_file}. Please ensure this is formatted correctly."
              .format(config_file=CONFIG_FILE))
        exit(EXIT_ERROR_INVALID_CONFIG)

    valid_config =  validate_text(loaded_json['AccountNumber']) \
                    and validate_text(loaded_json['APIKey']) \
                    and validate_text(loaded_json['Domain']) \
                    and validate_text(loaded_json['SubDomain'])

    if valid_config:
        ACCOUNT_NUMBER = loaded_json['AccountNumber']
        API_KEY = loaded_json['APIKey']
        DOMAIN = loaded_json['Domain']
        subdomain_option = loaded_json['SubDomain']
        if subdomain_option == "auto":
            SUBDOMAIN = get_hostname()
        else:
            SUBDOMAIN = subdomain_option
    else:
        print("{config_file} is invalid. Please ensure this is formatted correctly."
              .format(config_file=CONFIG_FILE))
        exit(EXIT_ERROR_INVALID_CONFIG)


def setup_api():
    global ACCOUNT_NUMBER, API_KEY
    keyring.set_password("pyrax", ACCOUNT_NUMBER, API_KEY)
    print("Authenticating with {account_number} using API Key".format(account_number=ACCOUNT_NUMBER))
    pyrax.set_setting("identity_type", "rackspace")
    pyrax.set_setting('region', 'LON')
    pyrax.keyring_auth(ACCOUNT_NUMBER)
    # Using keychain with username set in configuration file
    pyrax.keyring_auth(username=ACCOUNT_NUMBER)



if __name__ == "__main__":
    main()