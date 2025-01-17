class NoIDPFoundError(Exception):
    """Exception raised for errors in the input."""

    def __init__(self, message="No IDP found for user"):
        self.message = message
        super().__init__(self.message)
