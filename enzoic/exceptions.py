class UnsupportedPasswordType(Exception):
    def __init__(self, msg="Unsupported Password Type provided."):
        super().__init__(msg)


class UnexpectedEnzoicAPIError(Exception):
    def __init__(self, msg="Unexpected error from Enzoic API"):
        super().__init__(msg)
