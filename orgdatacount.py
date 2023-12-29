import logging
from pymongo import MongoClient
import time
from datetime import datetime, timedelta
from threading import Thread

# Setting up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# MongoDB setup
client = MongoClient('mongodb://syonb:syonsmart@ac-0w6souu-shard-00-00.jfanqj5.mongodb.net:27017,ac-0w6souu-shard-00-01.jfanqj5.mongodb.net:27017,ac-0w6souu-shard-00-02.jfanqj5.mongodb.net:27017/?replicaSet=atlas-yytbi1-shard-0&ssl=true&authSource=admin')
db = client.test
collection = db.organizations

def calculate_vulnerabilities(document, update_log=False):
    logger.info("Calculating vulnerabilities for document %s", document["_id"])
    
    # Initialize counters
    total_vulnerabilities = 0
    vulnerabilities_count = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0
    }

    # Iterate through endpoints and items to count vulnerabilities
    for endpoint in document.get("endpoints", []):
        for item in endpoint.get("items", []):
            # Process each vulnerability
            results = item.get("results", {})
            for vulnerability, details in results.items():
                threat_level = details.get("ThreatLevel", "Informational")
                # Increment the count for the corresponding threat level
                vulnerabilities_count[threat_level] += 1
                total_vulnerabilities += 1

    # Create a vulnerability info dictionary
    vulnerability_info = {
        "total": total_vulnerabilities,
        "High": vulnerabilities_count["High"],
        "Medium": vulnerabilities_count["Medium"],
        "Low": vulnerabilities_count["Low"],
        "Informational": vulnerabilities_count["Informational"],
        "timestamp": datetime.now().isoformat()
    }

    # Update the document in the collection with new vulnerability info
    update_query = {"$set": {"vulnerability": vulnerability_info}}
    
    # Append to timestamped log of past data counts only if update_log is True
    if update_log:
        update_query["$push"] = {"vulnerability_log": vulnerability_info}

    collection.update_one({"_id": document["_id"]}, update_query)
    
    logger.info("Updated document %s with vulnerability information: %s", document['_id'], vulnerability_info)

def process_existing_documents():
    logger.info("Processing existing documents in the collection")
    for document in collection.find():
        calculate_vulnerabilities(document, update_log=True)

def main():
    logger.info("Starting the main function")

    last_run = datetime.min  # Initialize to a time in the past

    while True:
        current_time = datetime.now()
        if current_time - last_run >= timedelta(weeks=1):
            process_existing_documents()
            last_run = current_time  # Update the last run time
        # Sleep for a day (could be less or more depending on how often you expect updates)
        time.sleep(86400)  # 86400 seconds = 1 day

if __name__ == "__main__":
    main()


