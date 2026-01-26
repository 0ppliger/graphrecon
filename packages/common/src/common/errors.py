class UnhandledException(Exception):

    e: Exception

    def __init__(self, e: Exception):
        super().__init__(f"Unhandled exception: {e}")
        self.e = e
