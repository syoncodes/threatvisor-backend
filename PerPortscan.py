from pymongo import MongoClient
import subprocess
import socket
import concurrent.futures
import re
from datetime import datetime, timedelta
import os

# MongoDB setup
client = MongoClient('mongodb://syonb:syonsmart@ac-0w6souu-shard-00-00.jfanqj5.mongodb.net:27017,ac-0w6souu-shard-00-01.jfanqj5.mongodb.net:27017,ac-0w6souu-shard-00-02.jfanqj5.mongodb.net:27017/?replicaSet=atlas-yytbi1-shard-0&ssl=true&authSource=admin')
db = client.test
collection = db.users

# Function to get port information from the output
def get_port_info(output):
    port_info = {
        "service": "Unknown",
        "version": "Unknown",
        "protocol": "Unknown"
    }

    # Define regex patterns
    vendorproductname_pattern = r"vendorproductname\s*:\s*([\w\s.-]+)"
    service_pattern = r"service\s*:\s*([\w\s.-]+)"
    service_column_pattern = r"SERVICE\n([\w\s/-]*)"
    version_pattern = r"version\s*:\s*([\w\s.-]+)"
    version_column_pattern = r"VERSION\n([\w\s.-]*)"

    # Search for vendorproductname and version in the output
    vendorproductname_match = re.search(vendorproductname_pattern, output, re.IGNORECASE)
    version_match = re.search(version_pattern, output, re.IGNORECASE)
    service_match = re.search(service_pattern, output, re.IGNORECASE)

    if vendorproductname_match and vendorproductname_match.group(1).strip():
        port_info["service"] = vendorproductname_match.group(1).strip().split()[0]  # Get the first part
    elif service_match and service_match.group(1).strip():
        # If no vendorproductname found, look for service in service_match
        port_info["service"] = service_match.group(1).strip()
    else:
        # If no vendorproductname and service found, look for service in column
        service_column_match = re.search(service_column_pattern, output, re.IGNORECASE)
        if service_column_match and service_column_match.group(1).strip():
            port_info["service"] = service_column_match.group(1).strip()

    if version_match and version_match.group(1).strip():
        port_info["version"] = version_match.group(1).strip().split()[0]  # Get the first part
    else:
        # If no version found, look for version in column
        version_column_match = re.search(version_column_pattern, output, re.IGNORECASE)
        if version_column_match and version_column_match.group(1).strip():
            port_info["version"] = version_column_match.group(1).strip()

    return port_info

def port_scanner(ip, port, user_id, endpoint_index, item_index):
    print(f"Scanning IP: {ip}, Port: {port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        if s.connect_ex((ip, port)) == 0:
            print(f"Port {port}: Open")
            s.close()

            # Run the shell command with item as the IP address, port as the port number, and the default TCP protocol
            command = f"python optiscan.py -t {ip} -p {port} -P TCP -s start"
            print(f"Running command: {command}")
            output = subprocess.run(command, shell=True, capture_output=True, text=True).stdout

            # Extract the protocol from the output using regex
            protocol_match = re.search(r"protocol: ([\w.-]+)", output, re.IGNORECASE)
            protocol = protocol_match.group(1) if protocol_match else "Unknown"

            # Update MongoDB document with port information
            port_info = get_port_info(output)
            port_info["protocol"] = protocol

            print(f"Saving to MongoDB for IP {ip} and port {port}: {port_info}")
            result = collection.update_one(
                {"_id": user_id, f"endpoints.{endpoint_index}.items.{item_index}.ipAddress": ip},
                {"$set": {f"endpoints.{endpoint_index}.items.{item_index}.ports.{port}": port_info}}
            )

            if result.modified_count == 0:
                print(f"Failed to update MongoDB for IP {ip} and port {port}. No document was modified.")
            else:
                print(f"Update successful for IP {ip} and port {port}.")

        else:
            print(f"Port {port}: Closed")

    except socket.error as e:
        print(f"Error occurred while scanning port {port} for IP {ip}: {e}")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while executing command for IP {ip} and port {port}: {e}")

def scan_ports(ips):
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for user_id, endpoint_index, item_index, ip in ips:
            print(f"Scanning IP: {ip}")
            collection.update_one(
                {'_id': user_id},
                {'$set': {f'endpoints.{endpoint_index}.status': 'scanning'}}
            )
            print(f"Status set to 'scanning' for IP {ip}.")
            tasks = [(ip, port, user_id, endpoint_index, item_index) for port in range(1, 3000)]
            for task in tasks:
                future = executor.submit(port_scanner, *task)
                futures.append(future)

        # Wait for all futures to complete
        concurrent.futures.wait(futures)

        # Update the status to "stopped" once all ports have been scanned
        for user_id, endpoint_index, item_index, ip in ips:
            collection.update_one(
                {'_id': user_id},
                {'$set': {f'endpoints.{endpoint_index}.status': 'stopped'}}
            )
            print(f"Scanning completed for IP {ip}. Status set to 'stopped'.")

# Initial scan of all IP addresses in the collection
all_ips = []
for user in collection.find({"endpoints.items.ipAddress": {"$exists": True}}):
    user_id = user["_id"]
    for endpoint_index, endpoint in enumerate(user["endpoints"]):
        for item_index, item in enumerate(endpoint["items"]):
            if "ipAddress" in item:
                ip = item["ipAddress"]
                all_ips.append((user_id, endpoint_index, item_index, ip))

scan_ports(all_ips)

# Continuously monitor the collection for changes
change_stream = collection.watch(full_document='updateLookup')
for change in change_stream:
    if change["operationType"] == "update":
        # Extract the full updated document
        updated_document = change.get('fullDocument')
        if updated_document:
            # Extract the endpoints field
            endpoints = updated_document.get('endpoints', [])
            ips_to_scan = []
            for endpoint_index, endpoint in enumerate(endpoints):
                items = endpoint.get('items', [])
                for item_index, item in enumerate(items):
                    if 'ipAddress' in item and item['ipAddress']:
                        ip = item['ipAddress']
                        ips_to_scan.append((updated_document['_id'], endpoint_index, item_index, ip))
            if ips_to_scan:
                print("New IPs found in the updated document. Starting scan...")
                scan_ports(ips_to_scan)
            else:
                print("No IPs found in the updated document.")
        else:
            print("No 'fullDocument' found in the change stream.")

