"""
The module defines a uniformed exception handling class returned by VT API.
"""


class APIError(Exception):
    """
    APIError encapsulates errors returned by VT API.
    """

    def __init__(self, error: str, code: int):
        self.error = type
        self.code = code
        super().__init__(f"Error: {error}, HTTP code: {code}")
