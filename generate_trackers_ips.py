#!/usr/bin/env python3

import urllib.request
import json
import sys
import socket
import logging

__author__ = 'Alexander Kamyshnikov'
__version__ = '1.0.0'
__email__ = 'axill777@gmail.com'

def setup_logging():
    # set up logging to file - see previous section for more details
    logging.basicConfig(level=logging.ERROR,
                    format='%(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='errors.log',
                    filemode='w')

###################################################################################################
# Converter: host blacklist in JSON format --> blacklist of all resolved IPv4 addresses
###################################################################################################

def download_file(url, local_filename=""):
    if local_filename == "":
        local_filename = url.split('/')[-1]
        print("No filename specified, save as '{}'".format(local_filename))

    url_request = urllib.request.Request(url) # headers=headers
    url_connect = urllib.request.urlopen(url_request)

    # Remember to open file in bytes mode
    buffer_size = 8192
    with open(local_filename, 'wb') as f:
        while True:
            buffer = url_connect.read(buffer_size)
            if not buffer: break

            # An integer value of size of written data
            data_wrote = f.write(buffer)

    # You could probably use with-open-as manner
    url_connect.close()

    return local_filename


def is_allowed_public_ip(ip_addr):
    """
    :param ip_addr: str
    :return bool
    """
    ip_oct = [int(x) for x in ip_addr.split('.')]
    if all([x == 0 for x in ip_oct]):
        return False  # 0.0.0.0 is local address
    elif any([ip_oct[0] in (10, 127)]):
        return False  # 10/8 https://tools.ietf.org/html/rfc1918; 127.0.0.0/8 is localhost
    elif all([ip_oct[0] == 169, ip_oct[1] == 254]):
        return False  # 169.254/16 https://tools.ietf.org/html/rfc3927
    elif all([ip_oct[0] == 172, 16 <= ip_oct[1] <= 31]):
        return False  # 172.16/12 https://tools.ietf.org/html/rfc1918
    elif all([ip_oct[0] == 192, ip_oct[1] == 168]):
        return False  # 192.168/16 https://tools.ietf.org/html/rfc1918

    return True

# tries to revolse host address to ip's;
# returns ip's list
def resolve_host_ips(hostname):
    domain_ips = []

    try:
        domain_ips = socket.gethostbyname_ex(hostname)[2]

        for ip_addrs in domain_ips:
            if not is_allowed_public_ip(ip_addrs):
                domain_ips.remove(ip_addrs)

        #print('Host \'' + hostname + '\' successfully resolved to ' + str(len(domain_ips)) + ' ip\'s')
    except Exception as inst:
        logging.error("Unable to resolve host '{}': '{}'".format(hostname, inst))
        return []

    return domain_ips

def parse_exodus_list(fileName):
    blacklist_obj = {}
    total_host_count = 0
    unresolved_host_count = 0
    resolved_ip_count = 0
    ignored_trackers_count = 0

    # Read entire file contents into single variable
    # NOTE: file is pretty small and can fit into RAM (~60 Kb)
    json_text = ''
    with open(fileName, 'r') as f:
        json_text = f.read()
        f.close()

    # Parse json
    json_obj = json.loads(json_text)
    trackers_array = json_obj['trackers']
    for tracker_obj in trackers_array:
        # Get tracker name
        tracker_name = tracker_obj['name']

        # Get tracker hosts (if present)
        tracker_host_pattern = tracker_obj['network_signature']
        if tracker_host_pattern != "":
            print("Processing tracker '{}'...".format(tracker_name))

            # Unescape dots (JSON requirement) and regex "|" symbol (one or more)
            tracker_hosts = tracker_host_pattern.replace("\\", "").split("|")

            total_host_count += len(tracker_hosts)
            print("Tracker '{}' have {} hosts".format(tracker_name, len(tracker_hosts)))

            # Resolve each symbolic host name to one or more IP addresses
            hosts_obj = {}
            for host in tracker_hosts:
                # We unable to resolve addresses like '.my.domain.com'
                if host.startswith('.'):
                    logging.error("Host pattern '{}' was simplified to '{}'!".format(host, host.lstrip('.')))
                    host = host.lstrip('.')

                ips = resolve_host_ips(host)
                if len(ips) > 0:
                    print("Tracker '{}' host '{}' resolved to {} IP addresses"
                          .format(tracker_name, host, len(ips)))

                    # Save to JSON current host IP addresses list
                    hosts_obj[host] = ips
                    resolved_ip_count += len(ips)
                else:
                    #print("Unable to resolve tracker '{}' host '{}'!"
                    #    .format(tracker_name, host))
                    unresolved_host_count += 1
       
            # Save to JSON current tracker hosts IP addresses list
            blacklist_obj[tracker_name] = hosts_obj
        else:
            ignored_trackers_count += 1
            print("Ignore tracker '{}'...".format(tracker_name))

    return {
         "blacklist_obj": blacklist_obj,
         "total_host_count": total_host_count,
         "ignored_trackers_count": ignored_trackers_count,
         "unresolved_host_count": unresolved_host_count,
         "resolved_ip_count": resolved_ip_count
    }

def parse_disconnect_list(fileName):
    blacklist_obj = {}
    total_host_count = 0
    unresolved_host_count = 0
    resolved_ip_count = 0

    # Read entire file contents into single variable
    # NOTE: file is pretty small and can fit into RAM (~200 Kb)
    json_text = ''
    with open(fileName, 'r') as f:
        json_text = f.read()
        f.close()

    # Parse json
    json_obj = json.loads(json_text)

    categories_dict = json_obj['categories']
    for category_name in categories_dict:
        #print("Category: " + category_name)
        for tracker_list in categories_dict[category_name]:
            for tracker_name in tracker_list:
                #print("Vendor: " + vendor_name)
                for highlevel_host in tracker_list[tracker_name]:
                    #print("High-level host: " + highlevel_host)
                    if not highlevel_host.startswith('http'):
                        continue

                    lowlevel_host_list = tracker_list[tracker_name][highlevel_host]
                    total_host_count += len(lowlevel_host_list)

                    hosts_obj = {}
                    for lowlevel_host in lowlevel_host_list:
                        #print("Low-level host: " + lowlevel_host)

                        ips = resolve_host_ips(lowlevel_host)
                        if len(ips) > 0:
                            print("Tracker '{}' host '{}' resolved to {} IP addresses"
                                  .format(tracker_name, lowlevel_host, len(ips)))
                            # Save to JSON current host IP addresses list
                            hosts_obj[lowlevel_host] = ips
                            resolved_ip_count += len(ips)
                        else:
                            unresolved_host_count += 1

                # Save to JSON current tracker hosts IP addresses list
                blacklist_obj[tracker_name] = hosts_obj

    return {
        "blacklist_obj": blacklist_obj,
        "total_host_count": total_host_count,
        "unresolved_host_count": unresolved_host_count,
        "resolved_ip_count": resolved_ip_count
    }

###################################################################################################
setup_logging()

# 1) Exodus trackers list
download_file("https://etip.exodus-privacy.eu.org/trackers/export", "exodus_trackers.json")
exodus_result = parse_exodus_list('exodus_trackers.json')

print('\n\n---------------------------------------------------------------')
print('Exodus trackers summary')
print('Total host count       : {}'.format(exodus_result["total_host_count"]))
print('Ignored trackers count : {}'.format(exodus_result["ignored_trackers_count"]))
print('Resolved IP count      : {}'.format(exodus_result["resolved_ip_count"]))
print('Unresolved host count    : {}'.format(exodus_result["unresolved_host_count"]))
print('---------------------------------------------------------------\n\n')

# 2) Disconnect.me trackers list
download_file("https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json", "disconnect_me_trackers.json")
disconnect_result = parse_disconnect_list('disconnect_me_trackers.json')

print('---------------------------------------------------------------')
print('Disconnect.me trackers summary')
print('Total host count    : {}'.format(disconnect_result["total_host_count"]))
print('Resolved IP count   : {}'.format(disconnect_result["resolved_ip_count"]))
print('Unresolved host count : {}'.format(disconnect_result["unresolved_host_count"]))
print('---------------------------------------------------------------\n\n')

# Save resulting tracker list to JSON file
output_filename = "result_exodus.json"
with open(output_filename, 'w') as f:
    json.dump(exodus_result['blacklist_obj'], f, sort_keys=True, indent=4)

output_filename = "result_disconnectme.json"
with open(output_filename, 'w') as f:
    json.dump(disconnect_result['blacklist_obj'], f, sort_keys=True, indent=4)

sys.exit(0)

