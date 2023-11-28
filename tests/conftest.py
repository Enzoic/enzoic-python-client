import pytest
import os
from enzoic import Enzoic
from enzoic import exceptions
from enzoic.enums.password_types import PasswordType


@pytest.fixture
def check_constructor_with_parameters():
    def _check_constructor_with_parameters(api_key: str, secret: str) -> bool:
        try:
            Enzoic(api_key, secret)
        except Exception:
            return True
        return False

    yield _check_constructor_with_parameters


@pytest.fixture(scope="session")
def _get_api_key():
    # Set this variable to run live tests
    return os.environ.get(
        "PP_API_KEY", "There is no environment variable set for PP_API_KEY"
    )


@pytest.fixture(scope="session")
def _get_api_secret():
    # Set this variable to run live tests
    return os.environ.get(
        "PP_API_SECRET", "There is no environment variable set for PP_API_SECRET"
    )


@pytest.fixture
def enzoic(_get_api_key, _get_api_secret):
    def enzoic(api_key=None, api_secret=None, api_base_url="https://api.enzoic.com/v1"):
        if api_key is None:
            api_key = _get_api_key
        if api_secret is None:
            api_secret = _get_api_secret
        return Enzoic(api_key=api_key, api_secret=api_secret, api_base_url=api_base_url)
    yield enzoic


@pytest.fixture(scope="session")
def password_types():
    yield PasswordType


@pytest.fixture(scope="session")
def enzoic_exceptions():
    yield exceptions
