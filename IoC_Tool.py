import sys
import requests
import json

# URLScan class for interacting with the urlscan.io API
class URLScan:
    def __init__(self):
        self.apikey = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"   # Please enter your own API
        self.headers = {'API-Key': self.apikey, 'Content-Type': 'application/json'}
    def scan_url(self, url):
        # Scan a URL using urlscan.io API
        data = {"url": url, "visibility": "public"}
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=self.headers, data=json.dumps(data))

        return response.json()

    def search_url(self, url):
        # Search for URLs in urlscan.io API based on domain
        response = requests.get('https://urlscan.io/api/v1/search/?q=domain:' + url)

        return response.json()

# AbuseIPDB class for interacting with the AbuseIPDB API
class AbuseIPDB:
    def scan_ipdb(self, IPAddress):
        # Scan an IP address using AbuseIPDB API
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': IPAddress,
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' # Please enter your own API
        }

        response = requests.request(method='GET', url=url, headers=headers, params=querystring)

        # Formatted output
        return response.json()

# VirusTotal class for interacting with the VirusTotal API
class VirusTotal:            #
    def scan_file(self, hash):
        # Scan a file using the VirusTotal API
        url = "https://www.virustotal.com/api/v3/files/" + hash

        headers = {
            "accept": "application/json",
            "x-apikey": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" # Please enter your own API
        }

        response = requests.get(url, headers=headers)

        return response.json()





# ConsoleApp class for handling user input and running the application
class ConsoleApp:
    def __init__(self):
        self.urlscan = URLScan()
        self.abuseIPDB = AbuseIPDB()
        self.virusTotal = VirusTotal()

    def display_menu(self):
        # Display menu options for the user
        print("1. URLScan")
        print("2. AbuseIPDB")
        print("3. VirusTotal")
        print("4. Exit")

    def run(self):
        while True:
            self.display_menu()
            choice = input("Choose a service (1-3) or exit (4): ")

            if choice == '1':
                self.handle_urlscan()
            elif choice == '2':
                self.handle_abuseipdb()
            elif choice == '3':
                self.handle_virustotal()
            elif choice == '4':
                break
            else:
                print("Invalid choice. Please enter a valid option.")

    def handle_urlscan(self):
        # Handle user input for URLScan methods
        urlscan_choice = input("Choose a method for URLScan (a: scan_url, b: search_url) or go back (x): ")

        if urlscan_choice == 'a':
            url = input("Enter the URL to scan: ")
            response_json = self.urlscan.scan_url(url)
            print(response_json)
        elif urlscan_choice == 'b':
            domain = input("Enter the domain to search: ")
            response_json = self.urlscan.search_url(domain)
            print(response_json)
        elif urlscan_choice.lower() == 'x':
            return
        else:
            print("Invalid choice. Please enter a valid option.")

    def handle_abuseipdb(self):
        # Handle user input for AbuseIPDB
        ip_address = input("Enter the IP address to scan: ")
        response_json = self.abuseIPDB.scan_ipdb(ip_address)
        print(response_json)
    def handle_virustotal(self):
        # Handle user input for VirusTotal
        file_hash = input("Enter the file hash to scan: ")
        response_json = self.virusTotal.scan_file(file_hash)
        print(response_json)


# Main execution
if __name__ == '__main__':
    app = ConsoleApp()
    app.run()

