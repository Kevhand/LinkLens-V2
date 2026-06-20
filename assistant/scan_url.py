import requests
import os 
import time 
import base64

import os
import time
import base64
import requests

def search_virus_total(url_to_search):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        print("VirusTotal API key not found. Please set the 'VIRUSTOTAL_API_KEY' environment variable.")
        return None

    headers = {
        "x-apikey": api_key
    }
    try:
        url_id = base64.urlsafe_b64encode(
            url_to_search.encode()
        ).decode().strip("=")

        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        report_response = requests.get(report_url, headers=headers)

        if report_response.status_code == 200:
            report_data = report_response.json()

            cached_results = (
                report_data
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_results", {})
            )

            if cached_results:
                print("Using cached VirusTotal report")
                return cached_results

    except Exception as e:
        print(f"Cached report lookup failed: {e}")

    print("submit url called")

    url = "https://www.virustotal.com/api/v3/urls"

    data = {
        "url": url_to_search
    }

    response = requests.post(url, headers=headers, data=data)

    if response.status_code != 200:
        print(f"Error submitting URL for analysis: {response.status_code}")
        print(response.text)
        return None

    print(response.json())

    analysis_url = (
        response
        .json()
        .get("data", {})
        .get("links", {})
        .get("self")
    )

    if not analysis_url:
        print("Analysis URL not found.")
        return None

    for _ in range(10):
        time.sleep(60)

        analysis_response = requests.get(
            analysis_url,
            headers=headers
        )

        if analysis_response.status_code != 200:
            print(f"Error fetching analysis: {analysis_response.status_code}")
            return None

        analysis_data = analysis_response.json()

        status = (
            analysis_data
            .get("data", {})
            .get("attributes", {})
            .get("status")
        )

        print("Analysis Status:", status)

        if status == "completed":
            attributes = (
                analysis_data
                .get("data", {})
                .get("attributes", {})
                .get("results", {})
            )

            print("Attributes fetched from VirusTotal:", attributes)

            return attributes

    print("Analysis did not complete within timeout.")
    return {}
        
def url_haus(url_to_search):
    api_key = os.getenv("URL_HAUS_API_KEY")

    headers = {
        "Auth-Key": api_key
    }

    response = requests.post(
        "https://urlhaus-api.abuse.ch/v1/url/",
        headers=headers,
        data={
            "url": url_to_search
        }
    )

    url_haus_data = response.json()


    if url_haus_data.get("query_status") == "ok":
        url_info = url_haus_data["urls"][0]

        url_haus_result = {
            "detected": True,
            "url_status": url_info.get("url_status"),
            "threat": url_info.get("threat"),
            "host": url_info.get("host"),
            "indicators": url_info.get("tags", []),
            "date_added": url_info.get("date_added"),
            "reference": url_info.get("urlhaus_reference")
        }

    else:
        url_haus_result = {
            "detected": False
        }
    return url_haus_result