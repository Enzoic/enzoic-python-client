import base64
import requests
from enzoic.exceptions import UnexpectedEnzoicAPIError
from enzoic.utilities import hashing
from enzoic.enums.password_types import PasswordType
from urllib.parse import urlencode, quote_plus
from typing import Tuple, Union
from datetime import datetime


class Enzoic:
    CREDENTIALS_API_PATH = "/credentials"
    PASSWORDS_API_PATH = "/passwords"
    EXPOSURE_API_PATH = "/exposures"
    ACCOUNTS_API_PATH = "/accounts"
    ALERTS_SERVICE_PATH = "/alert-subscriptions"

    def __init__(self, api_key, api_secret, api_base_url="https://api.enzoic.com/v1"):
        """
        Creates a new instance of Enzoic.
        :param api_key: API key provided by Enzoic for your account.
        :param api_secret: API Secret provided by Enzoic for your account.
        :param api_base_url: If you were provided an alternative API endpoint you may pass in
        this additional parameter to overwrite the default value.
        """
        if api_key is None or api_key == "":
            raise ValueError("API Key cannot be null or empty")
        if api_secret is None or api_secret == "":
            raise ValueError("API Secret cannot be null or empty")
        if api_base_url is None or api_base_url == "":
            raise ValueError("API Base URL cannot be null or empty")

        self.api_key = api_key
        self.api_secret = api_secret
        self.api_base_url = api_base_url

        self.auth_string = "basic " + base64.b64encode(
            (api_key + ":" + api_secret).encode("utf-8")
        ).decode("utf-8")

    def check_password(self, password: str) -> bool:
        """
        Checks whether the provided password is in the Enzoic database of known, compromised passwords.
        See: https://www.enzoic.com/docs/passwords-api
        :param password: The plaintext password to be checked
        :return: True if the password is a known, compromised password and should not be used
        """
        md5 = hashing.calc_md5_unsalted_hash(password)
        sha1 = hashing.calc_sha1_unsalted_hash(password)
        sha256 = hashing.calc_sha256_unsalted_hash(password)
        query_string = (
            f"?partialmd5={md5[:10]}&partial_sha1={sha1[:10]}&sha256={sha256[:10]}"
        )
        response = self._make_rest_call(
            self.api_base_url + self.PASSWORDS_API_PATH + query_string, "GET", None
        )

        if response.status_code != 404:
            for candidate in response.json()["candidates"]:
                keys = candidate.keys()
                if (
                    ("md5" in keys and candidate["md5"] == md5)
                    or ("sha1" in keys and candidate["sha1"] == sha1)
                    or ("sha256" in keys and candidate["sha256"] == sha256)
                ):
                    return True
            return False
        else:
            return False

    def check_password_ex(self, password: str) -> Tuple[bool, bool, None, int]:
        """
        Checks whether the provided password is in the Enzoic database of known, compromised passwords and returns the
        relative exposure frequency as well as exposure Count.
        See: https://www.enzoic.com/docs/passwords-api
        :param password: The plaintext password to be checked
        :returns: True if the password is a known, compromised password and should not be used
        revealed_in_exposure (bool) - If the password was found in a breach or not
        relative_exposure_frequency (bool) - How often we see this password relative to exposures
        exposure_count (int) - the amount of exposures this password has been found in
        """
        revealed_in_exposure = False
        relative_exposure_frequency = None
        exposure_count = 0

        md5 = hashing.calc_md5_unsalted_hash(password)
        sha1 = hashing.calc_sha1_unsalted_hash(password)
        sha256 = hashing.calc_sha256_unsalted_hash(password)
        query_string = (
            f"?partialmd5={md5[:10]}&partial_sha1={sha1[:10]}&sha256={sha256[:10]}"
        )
        response = self._make_rest_call(
            self.api_base_url + self.PASSWORDS_API_PATH + query_string, "GET", None
        )

        if response.status_code != 404:
            for candidate in response.json()["candidates"]:
                keys = candidate.keys()
                if (
                    ("md5" in keys and candidate["md5"] == md5)
                    or ("sha1" in keys and candidate["sha1"] == sha1)
                    or ("sha256" in keys and candidate["sha256"] == sha256)
                ):
                    return (
                        True,
                        candidate["revealedInExposure"],
                        candidate["relativeExposureFrequency"],
                        candidate["exposureCount"],
                    )
            return (
                False,
                revealed_in_exposure,
                relative_exposure_frequency,
                exposure_count,
            )
        else:
            return (
                False,
                revealed_in_exposure,
                relative_exposure_frequency,
                exposure_count,
            )

    def check_credentials(
        self,
        username: str,
        password: str,
        last_check_date: datetime = None,
        exclude_hash_types: list = None,
    ) -> bool:
        """
        Calls the Enzoic CheckCredentials API in a secure fashion to check whether the provided username and password
        are known to be compromised. This call is made securely to the server - only a salted and hashed representation
        of the credentials are passed and the salt value is not passed along with it.
        See https://www.enzoic.com/docs/credentials-api

        :param username: The username to check - may be an email address or a username
        :param password: The password to check
        :param last_check_date: (Optional) The timestamp for the last check you performed for this user. If the
        date/time you provide for the last check is greater than the timestamp Enzoic has for the last breach affecting
        this user, the check will not be performed. This can be used to substantially increase performance. Can be set
        to None if no last check was performed or the credentials have changed since.
        :param exclude_hash_types: (Optional) An array of PasswordTypes to ignore when calculating hashes for the
        credentials check. By excluding computationally expensive PasswordTypes, such as BCrypt, it is possible to
        balance the performance of this call against security. Can be set to null if you don't wish to exclude any hash
        types.
        :return: True if the credentials are known to be compromised, otherwise False.
        """
        # username needs to be converted to lowercase and url encoded
        params = {"username": str(username).lower()}
        result = urlencode(params, quote_via=quote_plus)

        response = self._make_rest_call(
            self.api_base_url + self.ACCOUNTS_API_PATH + f"?{result}", "GET", None
        )
        if response.status_code == 404:
            # This is all we needed to check for this, 404 means the email wasn't even in the database
            return False

        # see if the last_check_date was later than the lastBreachDate - if so, bail out
        if (
            last_check_date is not None
            and last_check_date.isoformat() >= response.json()["lastBreachDate"]
        ):
            return False

        bcrypt_count = 0
        credential_hashes = []
        query_string = ""

        for hash_spec in response.json()["passwordHashesRequired"]:
            if (
                exclude_hash_types is not None
                and hash_spec["hashType"] in exclude_hash_types
            ):
                # This type is meant to be excluded
                continue

            # Bcrypt gets far too expensive for good response time if there are many of them to calculate.
            # some (mostly garbage accounts) have accumulated a number of them in our DB and if we happen to hit one
            # it kills performance, so short circuit out after, at most, 2 BCrypt hashes
            if hash_spec["hashType"] != PasswordType.BCrypt or bcrypt_count <= 2:
                if hash_spec["hashType"] == PasswordType.BCrypt:
                    bcrypt_count += 1

                credential_hash = hashing._calc_credential_hash(
                    username=username,
                    password=password,
                    argon2_salt=response.json()["salt"],
                    hash_type=hash_spec["hashType"],
                    password_salt=hash_spec["salt"],
                )
                if credential_hash:
                    credential_hashes.append(credential_hash)
                    if len(query_string) == 0:
                        query_string += f"?partialHashes={credential_hash[:10]}"
                    else:
                        query_string += f"&partialHashes={credential_hash[:10]}"

        if len(query_string) > 0:
            creds_response = self._make_rest_call(
                self.api_base_url + self.CREDENTIALS_API_PATH + query_string,
                "GET",
                None,
            )

            if creds_response.status_code != 404:
                # loop through the candidate hashes returned and see if we have a match with the exact hash
                for candidate in creds_response.json()["candidateHashes"]:
                    if candidate in credential_hashes:
                        return True

        return False

    def get_exposures_for_user(self, username: str) -> Union[dict, requests.Response]:
        """
        Returns all of the credentials Exposures that have been found for a given username.
        See: https://www.enzoic.com/docs/exposures-api#get-exposures
        :param username: The username or the email address of the user to check
        :return: The json response contains an array of exposure IDs for the user. These IDs can be used with the
         get_exposure_details call to get additional information about each exposure
        """
        response = self._make_rest_call(
            self.api_base_url + self.EXPOSURE_API_PATH + "?username=" + username,
            "get",
            None,
        )

        if response.status_code == 404:
            # We don't have this email in the DB - return an empty response
            return {"count": 0, "exposures": []}
        else:
            return response.json()

    def get_exposure_details(self, exposure_id: str) -> Union[requests.Response, None]:
        """
        Returns the detailed information for a credentials Exposure.
        See: https://www.enzoic.com/docs/exposures-api#get-exposure-details
        :param exposure_id: The ID of the Exposure
        :return: The json response contains the details of the exposure or None if the Exposure ID could not be found.
        """
        response = self._make_rest_call(
            self.api_base_url + self.EXPOSURE_API_PATH + "?id=" + exposure_id,
            "GET",
            None,
        )

        if response.status_code != 404:
            return response.json()
        else:
            return None

    def _make_rest_call(
        self, url: str, method: str, body: dict = None
    ) -> requests.Response:
        headers = {
            "Authorization": self.auth_string,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        if method == "POST" or method == "PUT":
            r = requests.request(method, url=url, headers=headers, json=body)
        else:
            r = requests.request(method, url=url, headers=headers)

        if r.status_code not in (200, 201, 404):
            raise UnexpectedEnzoicAPIError(
                f"Unexpected error from Enzoic API: {r.status_code} {r.text}"
            )
        else:
            return r
