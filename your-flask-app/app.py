from flask import Flask, render_template, request, redirect, url_for
import requests
import json
import sys
import colorama
from time import sleep
from PyPDF2 import PdfReader
from io import BytesIO
import re

colorama.init()

def print_slow(words: str):
    for char in words:
        sleep(0.015)
        sys.stdout.write(char)
        sys.stdout.flush()
    print()

def scan_file(file_data, api_key):
    url = r'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {"apikey": api_key}

    try:
        files = {'file': file_data}
        response = requests.post(url, files=files, params=params)
        response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
        file_id = response.json()['resource']
        return file_id
    except requests.exceptions.RequestException as e:
        print(colorama.Fore.RED + f"Error: {e}")
        return None

def get_report(file_id, api_key):
    if file_id:
        url = f"https://www.virustotal.com/vtapi/v2/file/report"
        params = {"apikey": api_key, "resource": file_id}

        try:
            response = requests.get(url, params=params)
            response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
            report = response.json()
            return report
        except requests.exceptions.RequestException as e:
            print(colorama.Fore.RED + f"Error: {e}")
            return None
    else:
        return None

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']
        if file.filename == '':
            return "No selected file"

        api_key = "00dd05020a99baef64f164b8989ff918cd8c90fc5228bfe80c3cf368612f207a"  # Replace with your actual VirusTotal API key

        file_id = scan_file(file, api_key)
        if file_id:
            print_slow(colorama.Fore.YELLOW + "Analyzing...\n")
            report = get_report(file_id, api_key)
            if report is not None:
                return render_template('result.html', report=report)
            else:
                return "Error retrieving report. Please try again."
        else:
            return "Scan failed. Please check the file and try again."

    return render_template('hospital.html')

if __name__ == "__main__":
    app.run(debug=True)
