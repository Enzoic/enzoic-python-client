import pytest
import os
from enzoic import Enzoic
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


@pytest.fixture(scope="session")
def enzoic(_get_api_key, _get_api_secret):
    yield Enzoic(_get_api_key, _get_api_secret)


@pytest.fixture(scope="session")
def password_types():
    yield PasswordType
