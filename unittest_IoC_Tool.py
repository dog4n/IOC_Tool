import unittest
from unittest.mock import patch
from IoC_Tool import URLScan, AbuseIPDB, VirusTotal

# Test class for URLScan
class TestURLScan(unittest.TestCase):


    def test_URLScan_searchurl(self):
        # Fake JSON response
        fake_json = {'response': "ok"}

        # Mocking requests.get to simulate API call
        with patch('IoC_Tool.requests.get') as mock_get:
            mock_get.return_value.status = 200
            mock_get.return_value.json.return_value = fake_json
            obj = URLScan()
            response = obj.search_url("http://google.com")

        # Asserting that the response matches the expected fake JSON
        self.assertEqual(response, fake_json)

    def test_URLScan_scanurl(self):

        # Fake JSON response
        fake_json = {'response': "ok"}

        # Mocking requests.post to simulate API call
        with patch('IoC_Tool.requests.post') as mock_post:
            mock_post.return_value.status = 200
            mock_post.return_value.json.return_value = fake_json
            obj = URLScan()
            response = obj.scan_url("http://google.com")

        # Asserting that the response matches the expected fake JSON
        self.assertEqual(response, fake_json)

# Test class for AbuseIPDB
class test_AbuseIPDB(unittest.TestCase):

    def test_AbuseIPDB(self):

        # Fake JSON response
        fake_json = {'response': "ok"}

        # Mocking requests.request to simulate API call
        with patch('IoC_Tool.requests.request') as mock_request:
            mock_request.return_value.status = 200
            mock_request.return_value.json.return_value = fake_json
            obj = AbuseIPDB()
            response = obj.scan_ipdb("177.66.55.55")

        # Asserting that the response matches the expected fake JSON
        self.assertEqual(response, fake_json)

# Test class for VirusTotal
class test_VirusTotal(unittest.TestCase):

    def test_VirusTotal(self):

        # Fake JSON response
        fake_json = {'response': "ok"}

        # Mocking requests.get to simulate API call
        with patch('IoC_Tool.requests.get') as mock_get:
            mock_get.return_value.status = 200
            mock_get.return_value.json.return_value = fake_json
            obj = VirusTotal()
            response = obj.scan_file("gahksdglasdhjalshdhlaksd")

        # Asserting that the response matches the expected fake JSON
        self.assertEqual(response, fake_json)



# Main execution for running the unit tests
if __name__ == '__main__':
    unittest.main()
