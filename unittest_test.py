import unittest
from unittest.mock import patch
from test import URLScan, AbuseIPDB, VirusTotal

class TestURLScan(unittest.TestCase):


    def test_URLScan_searchurl(self):

        fake_json = {'response': "ok"}

        with patch('test.requests.get') as mock_get:
            mock_get.return_value.status = 200
            mock_get.return_value.json.return_value = fake_json
            obj = URLScan()
            response = obj.search_url("http://google.com")


        self.assertEqual(response, fake_json)

    def test_URLScan_scanurl(self):

        fake_json = {'response': "ok"}

        with patch('test.requests.post') as mock_post:
            mock_post.return_value.status = 200
            mock_post.return_value.json.return_value = fake_json
            obj = URLScan()
            response = obj.scan_url("http://google.com")


        self.assertEqual(response, fake_json)


class test_AbuseIPDB(unittest.TestCase):

    def test_AbuseIPDB(self):

        fake_json = {'response': "ok"}

        with patch('test.requests.request') as mock_request:
            mock_request.return_value.status = 200
            mock_request.return_value.json.return_value = fake_json
            obj = AbuseIPDB()
            response = obj.scan_ipdb("177.66.55.55")

        self.assertEqual(response, fake_json)

class test_VirusTotal(unittest.TestCase):

    def test_VirusTotal(self):

        fake_json = {'response': "ok"}

        with patch('test.requests.get') as mock_get:
            mock_get.return_value.status = 200
            mock_get.return_value.json.return_value = fake_json
            obj = VirusTotal()
            response = obj.scan_virustotal("gahksdglasdhjalshdhlaksd")


        self.assertEqual(response, fake_json)




if __name__ == '__main__':
    unittest.main()
