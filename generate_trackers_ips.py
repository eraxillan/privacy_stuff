#!/usr/bin/env python3

import urllib.request
import json
import sys
import socket

__author__ = 'Alexander Kamyshnikov'
__version__ = '1.0.0'
__email__ = 'axill777@gmail.com'

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

# tries to revolse host address to ip's;
# returns ip's list
def resolve_host_ips(hostname):
    domain_ips = []

    try:
        domain_ips = socket.gethostbyname_ex(hostname)[2]

        if '0.0.0.0' in domain_ips:
            domain_ips.remove('0.0.0.0')
        if '127.0.0.1' in domain_ips:
            domain_ips.remove('127.0.0.1')
        if '127.0.0.2' in domain_ips:
            domain_ips.remove('127.0.0.2')
        if '127.0.0.10' in domain_ips:
            domain_ips.remove('127.0.0.10')

        #print('Host \'' + hostname + '\' successfully resolved to ' + str(len(domain_ips)) + ' ip\'s')
    except:
        print('Unable to resolve host \'' + hostname + '\'')
        return []

    return domain_ips

def parse_exodus_list(fileName):
    blacklist_ips = []
    total_host_count = 0
    ignored_trackers_count = 0
    unresolved_ip_count = 0

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
        tracker_name = tracker_obj['name']
        tracker_host_pattern = tracker_obj['network_signature']
        if tracker_host_pattern != "":
            print("Processing tracker '{}'...".format(tracker_name))
            tracker_hosts = tracker_host_pattern.replace("\\", "").split("|")
            total_host_count += len(tracker_hosts)
            print("Tracker '{}' have {} hosts".format(tracker_name, len(tracker_hosts)))

            for host in tracker_hosts:
                ips = resolve_host_ips(host)
                if len(ips) > 0:
                    print("Tracker '{}' host '{}' resolved to {} IP addresses"
                        .format(tracker_name, host, len(ips)))
                    blacklist_ips.extend(ips)
                else:
                    #print("Unable to resolve tracker '{}' host '{}'!"
                    #    .format(tracker_name, host))
                    unresolved_ip_count += 1
        else:
            ignored_trackers_count += 1
            print("Ignore tracker '{}'...".format(tracker_name))

    # Remove duplicates from list
    blacklist_ips = list(dict.fromkeys(blacklist_ips))
    
    # Sort the list
    blacklist_ips.sort()

    return {
         "blacklist_ips": blacklist_ips,
         "total_host_count": total_host_count,
         "ignored_trackers_count": ignored_trackers_count,
         "unresolved_ip_count": unresolved_ip_count
    }

def parse_disconnect_list(fileName):
    blacklist_ips = []
    total_host_count = 0
    unresolved_ip_count = 0

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
        for vendor_list in categories_dict[category_name]:
            for vendor_name in vendor_list:
                #print("Vendor: " + vendor_name)
                for highlevel_host in vendor_list[vendor_name]:
                    #print("High-level host: " + highlevel_host)
                    if not highlevel_host.startswith('http'):
                        continue

                    total_host_count += 1
                    lowlevel_host_list = vendor_list[vendor_name][highlevel_host]
            
                    for lowlevel_host in lowlevel_host_list:
                        #print("Low-level host: " + lowlevel_host)
                    
                        ips = resolve_host_ips(lowlevel_host)
                        if len(ips) > 0:
                            blacklist_ips.extend(ips)
                        else:
                            unresolved_ip_count += 1

    # Remove duplicates from list
    blacklist_ips = list(dict.fromkeys(blacklist_ips))
    
    # Sort the list
    blacklist_ips.sort()

    return {
        "blacklist_ips": blacklist_ips,
        "total_host_count": total_host_count,
        "unresolved_ip_count": unresolved_ip_count
    }

###################################################################################################

# 1) Exodus trackers list
download_file("https://etip.exodus-privacy.eu.org/trackers/export", "exodus_trackers.json")
exodus_result = parse_exodus_list('exodus_trackers.json')

print('\n\n---------------------------------------------------------------')
print('Exodus trackers summary')
print('Total host count       : {}'.format(exodus_result["total_host_count"]))
print('Ignored trackers count : {}'.format(exodus_result["ignored_trackers_count"]))
print('Resolved IP count      : {}'.format(len(exodus_result["blacklist_ips"])))
print('Unresolved IP count    : {}'.format(exodus_result["unresolved_ip_count"]))
print('---------------------------------------------------------------\n\n')

# 2) Disconnect.me trackers list
download_file("https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json", "disconnect_me_trackers.json")
disconnect_result = parse_disconnect_list('disconnect_me_trackers.json')

print('---------------------------------------------------------------')
print('Disconnect.me trackers summary')
print('Total host count    : {}'.format(disconnect_result["total_host_count"]))
print('Resolved IP count   : {}'.format(len(disconnect_result["blacklist_ips"])))
print('Unresolved IP count : {}'.format(disconnect_result["unresolved_ip_count"]))
print('---------------------------------------------------------------\n\n')

summary_blacklist_ips = []
summary_blacklist_ips.extend(exodus_result["blacklist_ips"])
summary_blacklist_ips.extend(disconnect_result["blacklist_ips"])
summary_blacklist_ips = list(dict.fromkeys(summary_blacklist_ips))
summary_blacklist_ips.sort()
print("Summary IP count: {}".format(len(summary_blacklist_ips)))

# Save resulting IP list to text file
output_filename = "result_ips.txt"
with open(output_filename, 'w') as f:
    for ip in summary_blacklist_ips:
        data_wrote = f.write(ip + '\n')

sys.exit(0)

