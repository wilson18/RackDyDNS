#!/usr/bin/env python2
import json
import keyring
import os
import pyrax
import socket

from requests import get

# Exit Codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_ERROR_INVALID_CONFIG = 2

def main():
    working_directory = os.path.dirname(os.path.realpath(__file__)) + "/"

    # Config file path
    config_file = working_directory + "config.json"

    api_key, domain, hostname, username = parse_config(config_file)
    fqdn = hostname + "." + domain
    ip_addr = get_ipaddr()

    setup_api(api_key, username)
    dns_handle = pyrax.cloud_dns

    record = get_record(dns_handle, fqdn, domain)
    if record is not None:
        update_record_ip(record, ip_addr)
    else:
        print("Creating record")
        create_record(dns_handle, domain, fqdn, ip_addr)

    exit(EXIT_SUCCESS)

def get_record(dns_handle, fqdn, domain):
    """
    Iterates through all DNS records for a domain and returns the record where the data matches the fqdn.
    :param dns_handle: The pyrax.cloud_dns handle.
    :param fqdn: The fully qualified domain name to search for.
    :param domain: Domain to search through.
    :return: pyrax record for this domain.
    """
    record = None
    print("Searching for {fqdn}".format(fqdn=fqdn))
    all_records = dns_handle.list_records(domain)
    for this_record in all_records:
        if this_record.name.lower() == fqdn.lower():
            record = this_record
            break

    return record

def create_record(dns_handle, domain, fqdn, ip_addr):
    """
    Create a new A record for this fqdn which points to the ip_addr.
    :param dns_handle: The pyrax.cloud_dns handle.
    :param domain: The domain to add the entry for.
    :param fqdn: The fully qualified domain name to add.
    :param ip_addr: IPv4 Address to save in records data field.
    """
    record = {
        "type": "A",
        "name": fqdn,
        "data": ip_addr,
        "ttl": 3600,
    }

    dns_handle.add_records(domain, record)
    print("Record created for {subdomain} => {ip}".format(subdomain=fqdn, ip=ip_addr))


def update_record_ip(record, ip):
    """
    Calls the record.update function to update the IP address for an existing record.
    :param record: Record to update.
    :param ip: The IP to update it to.
    """
    if ip != record.data:
        print("Updating Record")
        record.update(data=ip)
        print("IP updated to {ip}".format(ip=ip))
    else:
        print("IP Address up to date.")


def get_ipaddr():
    """
    Get the current external IP address from ipify.
    :return: The current IP address.
    """
    return get('https://api.ipify.org').text


def get_hostname():
    """
    Get the current systems hostname.
    :return: The hostname of this machine.
    """
    return socket.gethostname()


def get_file_contents(file_path):
    """
    Gets the contents of a file.
    :param file_path: The path to read the file from.
    :return: The contents of the file.
    """
    file_contents = ""

    if os.path.exists(file_path):
        with open(file_path, 'r') as file_handle:
            file_contents = file_handle.read()

    return file_contents


def validate_text(text):
    """
    Checks if the variable is null or ""
    :param text:
    :return: True if valid else false.
    """
    return text != "" and text != None


def parse_config(config_file):
    """
    Parses the config file to get the api_key, domain, hostname and usernameusername
    :param config_file: Path to config file to parse.
    :return: api_key, domain, hostname, username
    """
    api_key = ""
    domain = ""
    hostname = ""
    username = ""

    if not os.path.exists(config_file):
        print("Unable to read file {config_file}".format(config_file=config_file))
        exit(EXIT_ERROR_INVALID_CONFIG)

    json_text = get_file_contents(config_file)
    loaded_json = {}
    try:
        loaded_json = json.loads(json_text)
    except ValueError:
        print("Unable to decode {config_file}. Please ensure this is formatted correctly."
              .format(config_file=config_file))
        exit(EXIT_ERROR_INVALID_CONFIG)

    valid_config =  validate_text(loaded_json['AccountNumber']) \
                    and validate_text(loaded_json['APIKey']) \
                    and validate_text(loaded_json['Domain']) \
                    and validate_text(loaded_json['SubDomain'])

    if valid_config:
        username = loaded_json['AccountNumber']
        api_key = loaded_json['APIKey']
        domain = loaded_json['Domain']
        subdomain_option = loaded_json['SubDomain']
        if subdomain_option == "auto":
            hostname = get_hostname().replace("." + domain, "")
        else:
            hostname = subdomain_option

    else:
        print("{config_file} is invalid. Please ensure this is formatted correctly."
              .format(config_file=config_file))
        exit(EXIT_ERROR_INVALID_CONFIG)

    return api_key, domain, hostname, username


def setup_api(api_key, username):
    """
    Setups up the pyrax API with the information required to connect.
    :param api_key: API Key to connect with
    :param username: Username to connect with
    """
    pyrax.set_setting("identity_type", "rackspace")
    keyring.set_password("pyrax", username, api_key)
    print("Authenticating with {username} using API Key".format(username=username))
    pyrax.set_setting("identity_type", "rackspace")
    pyrax.set_setting('region', 'LON')
    pyrax.keyring_auth(username)

    # Using keychain with username set in configuration file
    pyrax.keyring_auth(username=username)


if __name__ == "__main__":
    main()