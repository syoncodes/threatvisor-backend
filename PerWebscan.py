from zapv2 import ZAPv2
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from datetime import datetime, timedelta
import time
import re
from concurrent.futures import ThreadPoolExecutor

# Define a regular expression for CVE
CVE_PATTERN = r'(CVE-\d{4}-\d{4,7})'
ZAP_API_ADDRESS = 'http://localhost:8080'

# ZAP setup
zap = ZAPv2(apikey='9e6aepmr4v44i6cu8fli1c219i', proxies={'http': ZAP_API_ADDRESS, 'https': ZAP_API_ADDRESS})

# MongoDB setup
client = MongoClient('mongodb://syonb:syonsmart@ac-0w6souu-shard-00-00.jfanqj5.mongodb.net:27017,ac-0w6souu-shard-00-01.jfanqj5.mongodb.net:27017,ac-0w6souu-shard-00-02.jfanqj5.mongodb.net:27017/?replicaSet=atlas-yytbi1-shard-0&ssl=true&authSource=admin')
db = client['test']
collection = db['users']

def convert_sets_to_lists(data):
    for key, value in data.items():
        if isinstance(value, set):
            data[key] = list(value)
        elif isinstance(value, dict):
            convert_sets_to_lists(value)

def is_valid_url(url):
    return re.match(r'https?://', url) is not None

def extract_cve_identifiers(text):
    """Extract and return all unique CVE identifiers from the text."""
    return set(re.findall(CVE_PATTERN, text))

def process_alerts(raw_alerts):
    alerts = {}
    for alert in raw_alerts:
        vuln_type = alert.get('alert', '')
        if not vuln_type:
            continue

        if vuln_type not in alerts:
            alerts[vuln_type] = {
                "CWE": set(),
                "CVE": set(),
                "WASC": set(),
                "Description": alert.get('description', ''),
                "Solution": alert.get('solution', ''),
                "ThreatLevel": alert.get('risk', ''),
                "Paths": []
            }

        # Add the CWE and WASC from the alert itself
        alerts[vuln_type]["CWE"].add(alert.get('cweid', ''))
        alerts[vuln_type]["WASC"].add(alert.get('wascid', ''))

        # Add the CVE from the alert itself
        cve_id = alert.get('cveid', '')
        if cve_id:
            alerts[vuln_type]["CVE"].add(cve_id)

        # Now extract any additional CVE from the 'Other' field
        other_info = alert.get('other', '')
        additional_cve_ids = extract_cve_identifiers(other_info)
        alerts[vuln_type]["CVE"].update(additional_cve_ids)

        # Add path information
        alerts[vuln_type]["Paths"].append({
            "URL": alert.get('url', ''),
            "Parameter": alert.get('param', ''),
            "Attack": alert.get('attack', ''),
            "Evidence": alert.get('evidence', ''),
            "Confidence": alert.get('confidence', ''),
            "Other": other_info,
            "Discovered": datetime.now()
        })

    # Convert sets to lists
    for vuln_type, data in alerts.items():
        convert_sets_to_lists(data)

    return alerts


def merge_alerts(alerts, new_alerts):
    for vuln_type, data in new_alerts.items():
        if vuln_type not in alerts:
            alerts[vuln_type] = data
            convert_sets_to_lists(alerts[vuln_type])
        else:
            alerts[vuln_type]["CWE"] = list(set(alerts[vuln_type]["CWE"]) | set(data["CWE"]))
            alerts[vuln_type]["CVE"] = list(set(alerts[vuln_type]["CVE"]) | set(data["CVE"]))
            alerts[vuln_type]["WASC"] = list(set(alerts[vuln_type]["WASC"]) | set(data["WASC"]))
            alerts[vuln_type]["Paths"].extend(data["Paths"])
            convert_sets_to_lists(alerts[vuln_type])

def run_spider(domain, spider_type='regular'):
    if spider_type == 'regular':
        zap.core.new_session()
        scan_id = zap.spider.scan(domain)
        while int(zap.spider.status(scan_id)) < 100:
            time.sleep(1)
    elif spider_type == 'ajax':
        zap.ajaxSpider.scan(domain)
        while zap.ajaxSpider.status == 'running':
            time.sleep(1)
    
    raw_alerts = zap.core.alerts()
    return process_alerts(raw_alerts)

def update_mongodb(user_id, endpoint_index, item_index, alerts, scan_type):
    try:
        update_query = {
            f'endpoints.{endpoint_index}.items.{item_index}.results': alerts,
            f'endpoints.{endpoint_index}.items.{item_index}.scanned': datetime.now()
        }
        if scan_type == 'one-time':
            update_query[f'endpoints.{endpoint_index}.items.{item_index}.scan'] = 'none'
        
        print("Update Query:", update_query)
        collection.update_one({'_id': user_id}, {'$set': update_query}, upsert=False)
    except DuplicateKeyError:
        pass

def scan_and_update(domain_details):
    user_id, endpoint_index, item_index, domain, scan_type = domain_details
    if not is_valid_url(domain):
        return

    # Update the status to "scanning"
    collection.update_one({'_id': user_id}, {'$set': {f'endpoints.{endpoint_index}.status': 'scanning'}})
    print(f"Status set to 'scanning' for domain: {domain}.")

    # Run regular spider and update MongoDB
    alerts = run_spider(domain, 'regular')
    print(f"Writing regular spider scan results to MongoDB for domain: {domain}")
    update_mongodb(user_id, endpoint_index, item_index, alerts, scan_type)

    # Run AJAX spider, merge results and update MongoDB
    print(f"Scanning domain: {domain} with AJAX spider")
    new_alerts = run_spider(domain, 'ajax')
    merge_alerts(alerts, new_alerts)
    print(f"Appending AJAX spider scan results to MongoDB for domain: {domain}")
    update_mongodb(user_id, endpoint_index, item_index, alerts, scan_type)

    print(f"AJAX spider scan completed for domain: {domain}")
    collection.update_one({'_id': user_id}, {'$set': {f'endpoints.{endpoint_index}.status': 'stopped'}})
    print(f"Status set to 'stopped' for domain: {domain}.")

# Continuously scan for new domains
while True:
    domain_tasks = []
    for document in collection.find({"endpoints.items.service": "Domain"}):
        user_id = document['_id']

        # Check if 'organizationName' is missing or blank
        organization_name = document.get('organizationName', '')
        if organization_name != '':
            continue  # Skip the document if organizationName is present and not blank

        for endpoint_index, endpoint in enumerate(document['endpoints']):
            for item_index, item in enumerate(endpoint['items']):
                if item['service'] == "Domain" and 'url' in item:
                    domain = item['url']
                    if not is_valid_url(domain):
                        continue  # Skip unsupported URLs

                    scan_type = item.get('scan', 'passive')
                    last_scan_date = item.get('scanned', datetime.min)
                    scan_needed = False
                    is_new_domain = last_scan_date == datetime.min

                    # Determine if a scan is needed
                    if scan_type == 'passive' and (is_new_domain or last_scan_date < datetime.now() - timedelta(weeks=1)):
                        scan_needed = True
                    elif scan_type == 'one-time' and is_new_domain:
                        scan_needed = True

                    if scan_needed:
                        domain_details = (user_id, endpoint_index, item_index, domain, scan_type)
                        domain_tasks.append(domain_details)

    # Use ThreadPoolExecutor for parallel domain scanning
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(scan_and_update, domain_tasks)

    time.sleep(60)
