"""
Defines a result class.
"""

from datetime import datetime

__all__ = [
    'Result'
]


class Result:
    def __init__(self, url: str, ts: float, result: tuple, src: str):
        self._url = url
        self._ts = ts
        self._result = result
        self._src = src

    @property
    def url(self):
        return self._url

    @property
    def ts(self):
        return self._ts

    @property
    def result(self):
        return self._result

    @property
    def source(self):
        return self._src

    @source.setter
    def source(self, src: str):
        self._src = src

    def __str__(self):
        return f"URL: {self.url}, analysis date: {datetime.utcfromtimestamp(self.ts).strftime('%d-%m-%Y')}, " \
               f"result: {self.result}, source: {self.source}"

    def __repr__(self):
        return f"<{self.url}, {self.ts}, {self.result}, {self.source}>"
