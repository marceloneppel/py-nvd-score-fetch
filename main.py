import csv
import os
from time import sleep

import requests

# Check if the file exists and read the already fetched CVEs.
already_fetched_cves = set()
if os.path.isfile("cve.csv"):
    with open("cve.csv", "r", newline='') as csv_file:
        lines = csv_file.readlines()
        for line in lines:
            if line.startswith("CVE"):
                already_fetched_cves.add(line.split(",")[0].strip())
            else:
                print("No CVE found in this line.")
                print(line)
                print("Please check the format of the input file.")
                break
print(f"Already fetched CVEs: {already_fetched_cves}")

# Read the CVE IDs from the file and fetch their details from NVD API.
with open("cve.txt", "r") as file, open("cve.csv", "a", newline='') as csv_file:
    writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    lines = file.readlines()
    for line in lines:
        line = line.strip()
        if line.startswith("CVE"):
            cve = line.strip()
            if cve in already_fetched_cves:
                print(f"{cve} already fetched, skipping...")
                continue
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                if "totalResults" in data and data["totalResults"] == 1:
                    # Retrieve CVE description.
                    description = next(
                        iter(
                            filter(
                                lambda c: c["lang"] == "en",
                                data["vulnerabilities"][0]["cve"]["descriptions"]
                            )
                        ), None
                    )
                    if description:
                        description = description["value"]
                    else:
                        description = "No description available"
                    # Retrieve CVSS score.
                    metrics = data["vulnerabilities"][0]["cve"]["metrics"]
                    if "cvssMetricV4" in metrics:
                        score = metrics["cvssMetricV4"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV31" in metrics:
                        score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV2" in metrics:
                        score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                    else:
                        score = "No score available"
                    print(f"{cve} - Description: {description} - Score: {score}")
                    writer.writerow([cve, description, score])
                else:
                    print("Invalid response format.")
            else:
                print(f"Error: {response.status_code}")
                break
        else:
            print("No CVE found in this line.")
            print(line)
            print("Please check the format of the input file.")
            break
        sleep(10) # Sleep for 10 seconds to avoid hitting the API rate limit.
