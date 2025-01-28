class NetworkRequestError(Exception):
    """Exception for errors during network requests."""
    def __init__(self, message, errors):
        super().__init__(message)
        self.errors = errors

class APIResponseError(Exception):
    """Exception for non-successful API responses."""
    def __init__(self, message, response):
        super().__init__(message)
        self.response = response