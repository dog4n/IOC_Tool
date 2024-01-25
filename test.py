import sys
import requests
import json


class URLScan:
    def __init__(self):
        self.apikey = "fbdea673-aa27-4d64-891e-f12287d7b9b0"
        self.headers = {'API-Key': self.apikey, 'Content-Type': 'application/json'}
    def scan_url(self, url):

        data = {"url": url, "visibility": "public"}
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=self.headers, data=json.dumps(data))

        return response.json()

    def search_url(self, url):
        response = requests.get('https://urlscan.io/api/v1/search/?q=domain:' + url)

        return response.json()


class AbuseIPDB:
    def scan_ipdb(self, IPAddress):
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': IPAddress,
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': '1965b5860ddac5550566add3208bd05dc18768512e92c6cdc4dbe22ede79d394e8d0811c93973ef2'
        }

        response = requests.request(method='GET', url=url, headers=headers, params=querystring)

        # Formatted output
        return response.json()


class VirusTotal:
    def scan_virustotal(self, hash):
        url = "https://www.virustotal.com/api/v3/files/" + hash

        headers = {
            "accept": "application/json",
            "x-apikey": "5c2f2c0e4f1a1962f68d33d46784a9d700a105c397c3d067e28ab367dd54f1e5"
        }

        response = requests.get(url, headers=headers)

        return response.json()


class ConsoleApp:
    def __init__(self):
        self.urlscan = URLScan()
        self.abuseIPDB = AbuseIPDB()
        self.virusTotal = VirusTotal()

    def display_menu(self):
        print("1. URLScan")
        print("2. AbuseIPDB")
        print("3. VirusTotal")
        print("4. Exit")

    def run(self):
        while True:
            self.display_menu()
            choice = input("Choose a class (1-3) or exit (4): ")

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
        ip_address = input("Enter the IP address to scan: ")
        response_json = self.abuseIPDB.scan_ipdb(ip_address)
        print(response_json)
    def handle_virustotal(self):
        file_hash = input("Enter the file hash to scan: ")
        response_json = self.virusTotal.scan_virustotal(file_hash)
        print(response_json)

if __name__ == '__main__':
    app = ConsoleApp()
    app.run()

