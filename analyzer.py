import base64
import os
import pickle
import time
from datetime import datetime, timedelta
from threading import Lock

import requests
from error import APIError
from result import *

_API_URL = 'https://www.virustotal.com'
_ENDPOINT_PREFIX = '/api/v3'

__all__ = [
    'Analyzer'
]


def url_id(url: str) -> str:
    """
    Encodes URL string to base64.
    """
    return base64.urlsafe_b64encode(url.encode()).decode().strip('=')


def api_url(suffix: str) -> str:
    """
    Returns the full VT API URL with a custom suffix.
    """
    return _API_URL + _ENDPOINT_PREFIX + suffix


class Analyzer:
    def __init__(self, urls, cache_dir, apikey, age=182):
        self._urls = urls
        try:
            self._apikey = apikey or os.environ["VT_KEY"]
            self._age = timedelta(days=int(age))
        except (KeyError, ValueError):
            raise APIError('Either not provided API key at all or cache age is not a valid integer', 400)
        self._cache: dict[str: Result] = ...

        # Cache mapping: {url: Result()}
        if not os.path.isdir(cache_dir):
            os.mkdir(cache_dir)
        self._cache_dir = cache_dir

        if not os.path.isfile(os.path.join(self._cache_dir, 'cache.pickle')):
            self._cache = dict()
        else:
            with open(os.path.join(self._cache_dir, 'cache.pickle'), 'rb') as cache:
                self._cache = pickle.load(cache)

        self._lock = Lock()

    @property
    def cache(self):
        return self._cache

    @property
    def cache_dir(self):
        return self._cache_dir

    def check_cache(self, url: str) -> bool:
        """
        Accesses self._cache and returns a boolean value according to self._age
        """
        with self._lock:
            if url not in self._cache:
                return False

            epoch = self._cache[url].ts
            if datetime.utcnow() - datetime.utcfromtimestamp(epoch) <= self._age:
                self._cache[url].source = 'cache'
                return True
            return False

    def scan(self, url: str) -> str | APIError:
        """
        Scans provided URL and returns its scan ID from VT API.
        """
        headers = {
            "accept": "application/json",
            "x-apikey": self._apikey,
            "content-type": "application/x-www-form-urlencoded"
        }

        response = requests.post(url=api_url('/urls'), data=f"url={url}",
                                 headers=headers)

        if response.status_code == 200:
            return response.json()["data"]["id"]
        if 400 <= response.status_code <= 499:
            return APIError('ClientError', response.status_code)
        return APIError('ServerError', response.status_code)

    def analyze(self, url: str) -> Result | APIError:
        """
        Analyze a base64 URL and return its data from VT API.
        """
        if not self.check_cache(url):
            headers = {
                "accept": "application/json",
                "x-apikey": self._apikey
            }

            response = requests.get(url=api_url(f"/urls/{url_id(url)}"), headers=headers)
            if response.status_code == 200:
                if "error" in response.json():
                    return APIError('URLNotFoundError', response.status_code)
                else:
                    epoch = response.json()["data"]["attributes"]["last_analysis_date"]
                    if datetime.utcnow() - datetime.utcfromtimestamp(epoch) > self._age:
                        return self.full_scan(url)
                    else:
                        with self._lock:
                            self._cache[url] = Result(url, response.json()["data"]["attributes"]["last_analysis_date"],
                                                      self.get_url_reputation(
                                                          response.json()["data"]["attributes"]["last_analysis_stats"]),
                                                      'api')
                        return self._cache[url]

            if 400 <= response.status_code <= 499:
                return APIError('ClientError', response.status_code)
            return APIError('ServerError', response.status_code)

        return self._cache[url]

    @staticmethod
    def get_url_reputation(stats: dict) -> tuple:
        """
        Extract and calculate URL reputation (%) from JSON data.
        """
        total_values_sum, max_val = sum(stats.values()), max(stats.values())
        max_key = list(stats.keys())[list(stats.values()).index(max_val)]
        accuracy = f"{max_val / total_values_sum * 100:.2f}%"
        return max_key, accuracy

    def full_scan(self, url: str) -> Result | APIError:
        scan_id = self.scan(url)

        headers = {
            "accept": "application/json",
            "x-apikey": self._apikey
        }

        response = requests.get(url=api_url(f"/analyses/{scan_id}"), headers=headers)
        if response.status_code == 200:
            while True:
                if response.json()["data"]["attributes"]["status"] == 'completed':
                    break
                else:
                    time.sleep(5)
                    response = requests.get(url=api_url(f"/analyses/{scan_id}"), headers=headers)

            with self._lock:
                self._cache[url] = Result(url, response.json()["data"]["attributes"]["date"],
                                          self.get_url_reputation(response.json()["data"]["attributes"]["stats"]),
                                          'api')
                return self._cache[url]

        if 400 <= response.status_code <= 499:
            return APIError('ClientError', response.status_code)
        return APIError('ServerError', response.status_code)
