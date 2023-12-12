import base64
import requests
from enzoic.exceptions import UnexpectedEnzoicAPIError, UnsupportedPasswordType
from enzoic.utilities import hashing
from enzoic.enums.password_types import PasswordType
from urllib.parse import urlencode, quote_plus
from typing import Tuple, Union, Dict
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

    def __repr__(self):
        return "Enzoic(" + self.api_key + ", " + self.api_secret + ", " + self.api_base_url + ")"

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
            f"?partial_md5={md5[:10]}&partial_sha1={sha1[:10]}&partial_sha256={sha256[:10]}"
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

    def check_hashed_password(self, hashed_pw: str, hash_type: int) -> bool:
        """
        Checks whether the provided password is in the Enzoic database of known, compromised passwords. Pass in the type
        of password hash. Supports NTLM, MD5, SHA1, SHA256 (33, 1, 2, 3 respectively). You can utilize the PasswordTypes
        enum for ease of use like so:

        from enzoic.enums.password_types import PasswordType
        PasswordType.NTLM

        See: https://www.enzoic.com/docs/passwords-api
        :param hashed_pw: The full hash of a password you wish to check. Must match the corresponding hash_type
        parameter. Only the first 7 characters will be sent.
        :param hash_type: The int of the respective password hash supplied, possible values are:
         NTLM, MD5, SHA1, SHA256 (33, 1, 2, 3 respectively)
        :return: True if the password is a known, compromised password and should not be used
        """
        if hash_type == PasswordType.NTLM:
            key = "partialNTLM"
        elif hash_type == PasswordType.SHA256_UNSALTED:
            key = "partialSHA256"
        elif hash_type == PasswordType.MD5_UNSALTED:
            key = "partialMD5"
        elif hash_type == PasswordType.SHA1_UNSALTED:
            key = "partialSHA1"
        else:
            raise UnsupportedPasswordType(
                "Unsupported hash type provided. The following values for 'password_type' are supported:"
                f"\nNTLM: {PasswordType.NTLM}"
                f"\nMD5: {PasswordType.MD5_UNSALTED}"
                f"\nSHA1: {PasswordType.SHA1_UNSALTED}"
                f"\nSHA256: {PasswordType.SHA256_UNSALTED}"
            )

        payload = {
            key: hashed_pw[:7]
        }

        response = self._make_rest_call(
            self.api_base_url + self.PASSWORDS_API_PATH, "POST", body=payload
        )

        if response.status_code != 404:
            for candidate in response.json()["candidates"]:
                keys = candidate.keys()
                if (
                    ("md5" in keys and candidate["md5"] == hashed_pw)
                    or ("sha1" in keys and candidate["sha1"] == hashed_pw)
                    or ("sha256" in keys and candidate["sha256"] == hashed_pw)
                    or ("ntlm" in keys and candidate["ntlm"] == hashed_pw)
                ):
                    return True
            return False
        else:
            return False

    def retrieve_list_of_candidates_for_partial_hash(self, hashed_pw: str, hash_type: int) -> list:
        """
        Pass in the type of password hash as well as the first 7 characters of that hash. Supports NTLM, MD5, SHA1,
        SHA256 (33, 1, 2, 3 respectively). You can utilize the PasswordTypes enum for ease of use like so:

        from enzoic.enums.password_types import PasswordType
        PasswordType.NTLM

        See: https://www.enzoic.com/docs/passwords-api
        :param hashed_pw: The first 7 characters of the hash type you wish to check.
        :param hash_type: The int of the respective password hash supplied, possible values are:
         NTLM, MD5, SHA1, SHA256 (33, 1, 2, 3 respectively)
        :return: A list of potential matches for the first 7 characters of the hash provided
        """
        if len(hashed_pw) < 7:
            raise ValueError(
                "Password hash must be greater than or equal to 7 characters in length."
            )

        if hash_type == PasswordType.NTLM:
            key = "partialNTLM"
        elif hash_type == PasswordType.SHA256_UNSALTED:
            key = "partialSHA256"
        elif hash_type == PasswordType.MD5_UNSALTED:
            key = "partialMD5"
        elif hash_type == PasswordType.SHA1_UNSALTED:
            key = "partialSHA1"
        else:
            raise UnsupportedPasswordType(
                "Unsupported hash type provided. The following values for 'password_type' are supported:"
                f"\nNTLM: {PasswordType.NTLM}"
                f"\nMD5: {PasswordType.MD5_UNSALTED}"
                f"\nSHA1: {PasswordType.SHA1_UNSALTED}"
                f"\nSHA256: {PasswordType.SHA256_UNSALTED}"
            )

        payload = {
            key: hashed_pw[:7]
        }

        response = self._make_rest_call(
            self.api_base_url + self.PASSWORDS_API_PATH, "POST", body=payload
        )

        if response.status_code != 404:
            if hash_type == PasswordType.NTLM:
                return [candidate["ntlm"] for candidate in response.json()["candidates"]]
            elif hash_type == PasswordType.MD5_UNSALTED:
                return [candidate["md5"] for candidate in response.json()["candidates"]]
            elif hash_type == PasswordType.SHA1_UNSALTED:
                return [candidate["sha1"] for candidate in response.json()["candidates"]]
            elif hash_type == PasswordType.SHA256_UNSALTED:
                return [candidate["sha256"] for candidate in response.json()["candidates"]]
        else:
            return []

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
            f"?partial_md5={md5[:10]}&partial_sha1={sha1[:10]}&partial_sha256={sha256[:10]}"
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
        exclude_hash_types: list = None
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

    def get_exposures_for_user(self, username: str) -> Dict:
        """
        Returns all the credentials Exposures that have been found for a given username.
        See: https://www.enzoic.com/docs/exposures-api#get-exposures
        :param username: The username or the email address of the user to check
        :return: The json response contains an array of exposure IDs for the user. These IDs can be used with the
         get_exposure_details call to get additional information about each exposure
        """
        response = self._make_rest_call(
            self.api_base_url + self.EXPOSURE_API_PATH + "?username=" + username,
            "GET",
            None,
        )

        if response.status_code == 404:
            # We don't have this email in the DB - return an empty response
            return {"count": 0, "exposures": []}
        else:
            return response.json()

    def get_exposure_details(self, exposure_id: str) -> Union[Dict, None]:
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

        if response.status_code == 404:
            return None
        else:
            return response.json()

    def get_exposed_users_for_domain(
        self,
        domain: str,
        page_size: int = None,
        paging_token: str = None
    ) -> Union[Dict, requests.Response]:
        """
        GetExposedUsersForDomain returns a list of all users for a given email domain who have had credentials revealed
        in exposures. The results of this call are paginated.
        see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-all-email-addresses-in-a-domain
        :param domain: Name of the domain you wish to check, e.g. enzoic.com
        :param page_size: Can be any value from 1 to 1000. If page_size is not specified, the default is 1000.
        :param paging_token: A value returned with each page of results and should be passed into this call to retrieve
        the next page of results
        :return:
        """
        query_string = "?accountDomain=" + domain

        if page_size:
            query_string += "&pageSize=" + str(page_size)

        if paging_token:
            query_string += "&pagingToken=" + paging_token

        response = self._make_rest_call(
            self.api_base_url + self.EXPOSURE_API_PATH + query_string,
            "GET",
            None,
        )

        if response.status_code == 404:
            # We don't have this email in the DB - return an empty response
            return {"count": 0, "users": []}
        else:
            return response.json()

    def get_exposures_for_domain(
        self,
        domain: str,
        include_exposure_details: bool = False,
        page_size: int = None,
        paging_token: str = None
    ) -> Dict:
        """
        Returns a list of all exposures found involving users with email addresses from a
        given domain with the details for each exposure included inline in the response.
        see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/exposures-api/get-exposures-for-a-domain
        :param domain: The domain to check.
        :param include_exposure_details: If True will include exposure details.
        :param page_size: The results of this call are paginated. page_size can be any value from 1 to 500.
        If page_size is not specified, the default is 100.
        :param paging_token: paging_token is a value returned with each page of results and should be passed into this
        call to retrieve the next page of results.
        :return: The result will be an dictionary containing total count and a list of exposure IDs which can be used
        with the get_exposure_details call to retrieve details
        """

        query_string = "?domain=" + domain

        if include_exposure_details:
            query_string += f"&includeExposureDetails={int(include_exposure_details)}"

        if page_size:
            query_string += "&pageSize=" + str(page_size)

        if paging_token:
            query_string += "&pagingToken=" + paging_token

        response = self._make_rest_call(
            self.api_base_url + self.EXPOSURE_API_PATH + query_string,
            "GET",
            None,
        )

        if response.status_code == 404:
            # We don't have this domain in the DB - return empty response
            return {"count": 0, "exposures": []}
        else:
            return response.json()

    def add_user_alert_subscriptions(
        self,
        username_hashes: list,
        custom_data: str = ""
    ) -> Dict:
        """
        Takes an array of email addresses that are added to the list of users your account monitors for new
        credentials exposures.
        see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#add-breach-alert-subscriptions
        :param username_hashes: the array of email addresses that are added to the list of users your account monitors
        :param custom_data: can optionally be used with any string value to tag the new subscription items with a
        custom value.  This value will be sent to your webhook when a new alert is found for one of these users and
        can also be used to lookup or delete entries.
        :return:
        """
        payload = {
            "usernameHashes": [hashing.calc_sha256_unsalted_hash(username_hash.lower()) for username_hash in username_hashes],
        }
        if custom_data != "":
            payload["customData"] = custom_data

        response = self._make_rest_call(
            self.api_base_url + self.ALERTS_SERVICE_PATH, "POST", body=payload,
        )
        return response.json()

    def delete_user_alert_subscriptions(self, username_hashes: list) -> Dict:
        """
        Takes a list of email addresses you wish to remove from monitoring for new credentials exposures.
        see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#remove-breach-alert-subscriptions
        :param username_hashes: The list of email addresses you wish to remove from monitoring.
        :return:
        """
        payload = {
            "usernameHashes": [hashing.calc_sha256_unsalted_hash(username_hash.lower()) for username_hash in username_hashes],
        }
        response = self._make_rest_call(
            self.api_base_url + self.ALERTS_SERVICE_PATH, "DELETE", body=payload,
        )
        return response.json()

    def delete_user_alert_subscriptions_with_custom_data(self, custom_data: str) -> Dict:
        """
        Takes a custom_data value and deletes all alert subscriptions that have that value.
        see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#remove-breach-alert-subscriptions
        :param custom_data: The matching custom data you wish to match alert subscriptions on.
        :return:
        """
        payload = {
            "usernameCustomData": custom_data,
        }
        response = self._make_rest_call(
            self.api_base_url + self.ALERTS_SERVICE_PATH, "DELETE", body=payload,
        )
        return response.json()

    def get_user_alert_subscriptions(
        self,
        page_size: int = None,
        paging_token: str = None
    ) -> Dict:
        """
        This method returns a list of all the users your account is monitoring for new credentials exposures.
        The results of this call are paginated.
        see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#retrieve-current-breach-alert-subscriptions
        :param page_size: Can be any value from 1 to 1000, if page_size is not specified, the default is 1000.
        :param paging_token: Returned with each page of results and should be passed into this call to retrieve the
        next page of results.
        :return:
        """
        return self.get_user_alert_subscriptions_with_custom_data(
            custom_data="",
            page_size=page_size,
            paging_token=paging_token,
        )

    def get_user_alert_subscriptions_with_custom_data(
        self,
        custom_data: str,
        page_size: int = None,
        paging_token: str = None
    ) -> Dict:
        """
        This returns a list of all the users your account is monitoring for new credentials exposures with the provided
        custom_data value. The results of this call are paginated.
        see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#retrieve-current-breach-alert-subscriptions
        :param custom_data:
        :param page_size: Can be any value from 1 to 1000, if page_size is not specified, the default is 1000.
        :param paging_token: Returned with each page of results and should be passed into this call to retrieve the
        next page of results.
        :return:
        """
        query_params = {}

        if custom_data != "":
            query_params["customData"] = custom_data

        if page_size:
            query_params["pageSize"] = str(page_size)

        if paging_token:
            query_params["pagingToken"] = paging_token

        response = self._make_rest_call(
            self.api_base_url + self.ALERTS_SERVICE_PATH + "?" + urlencode(query_params), "GET", None,
        )

        if response.status_code == 404:
            return {"count": 0, "usernameHashes": [], "pagingToken": ""}
        else:
            return response.json()

    def is_user_subscribed_for_alerts(self, username_hash: str) -> bool:
        """
        Takes a username and returns true if the user is subscribed for alerts, false otherwise.
        see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-user#retrieve-current-breach-alert-subscriptions
        :param username_hash: The username hash you wish to check for alert subscriptions.
        :return:
        """
        username_hash = hashing.calc_sha256_unsalted_hash(username_hash.lower())
        response = self._make_rest_call(
            self.api_base_url + self.ALERTS_SERVICE_PATH + f"usernameHash={username_hash}", "GET", None,
        )

        if response.status_code == 404:
            return False
        else:
            return True

    def add_domain_alert_subscriptions(self, domains: list) -> Dict:
        """
        Takes a list of domains (e.g. enzoic.com) and adds them to the list of domains your account monitors for new
        credentials exposures.
        see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#add-breach-alert-subscriptions
        :param domains: The list of domains you wish to add to monitoring.
        :return:
        """
        payload = {
            "domains": domains
        }
        response = self._make_rest_call(
            self.api_base_url + self.ALERTS_SERVICE_PATH, "POST", body=payload,
        )
        return response.json()

    def delete_domain_alert_subscriptions(self, domains: list) -> Dict:
        """
        Takes an array of domains you wish to remove from monitoring for new credentials exposures.
        see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#remove-breach-alert-subscriptions
        :param domains: The list of domains you wish to remove from monitoring.
        :return:
        """
        payload = {
            "domains": domains
        }
        response = self._make_rest_call(
            self.api_base_url + self.ALERTS_SERVICE_PATH, "DELETE", body=payload,
        )
        return response.json()

    def get_domain_alert_subscriptions(self, page_size: int = None, paging_token: str = None) -> Dict:
        """
        Returns a list of all the domains your account is monitoring for new credentials exposures.
        The results of this call are paginated.
        see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#retrieve-current-breach-alert-subscriptions
        :param page_size: Can be any value from 1 to 1000. If it is not specified, the default is 1000.
        :param paging_token: A value returned with each page of results and should be passed into this call to retrieve
        the next page of results.
        :return:
        """
        query_params = {
             "domains": 1,
        }
        if page_size:
            query_params["pageSize"] = str(page_size)

        if paging_token:
            query_params["pagingToken"] = paging_token

        response = self._make_rest_call(
            self.api_base_url + self.ALERTS_SERVICE_PATH + "?" + urlencode(query_params), "GET", None,
        )
        return response.json()

    def is_domain_subscribed_for_alerts(self, domain: str) -> bool:
        """
        Takes a domain and returns true if the domain is subscribed for alerts, false otherwise.
        see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/breach-monitoring-api/breach-monitoring-by-domain#retrieve-current-breach-alert-subscriptions
        :param domain: The domain you wish to check the subscription status of.
        :return:
        """
        response = self._make_rest_call(
            self.api_base_url + self.ALERTS_SERVICE_PATH + f"?domain={domain}", "GET", None,
        )
        if response.status_code == 404:
            return False
        else:
            return True

    def get_user_passwords(self, username: str, include_exposure_details: bool = False) -> Union[bool, Dict]:
        """
        Returns a list of passwords that Enzoic has found for a specific user.  This call must be enabled for your
        account or you will receive a 403 rejection when attempting to call it.
        see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/credentials-api/cleartext-credentials-api
        :param username: The username you wish to receive a list of passwords for.
        :param include_exposure_details: Includes the details of the exposure the password was found in if True,
        :return:
        """
        # username needs to be converted to lowercase and url encoded
        query_params = {
            "username": str(username).lower(),
        }

        if include_exposure_details:
            query_params["includeExposureDetails"] = int(include_exposure_details)

        result = urlencode(query_params, quote_via=quote_plus)

        response = self._make_rest_call(
            self.api_base_url + f"/cleartext-credentials?{result}", "GET", None
        )
        if response.status_code == 404:
            return False
        else:
            return response.json()

    def get_user_passwords_by_partial_hash(self, username: str, include_exposure_details: bool = False) -> Union[bool, Dict]:
        """
        Returns a list of passwords that Enzoic has found for a specific user.  This call must be enabled for your
        account or you will receive a 403 rejection when attempting to call it.
        see https://docs.enzoic.com/enzoic-api-developer-documentation/api-reference/credentials-api/cleartext-credentials-api
        :param username: The username you wish to receive a list of passwords for.
        :param include_exposure_details: Includes the details of the exposure the password was found in if True,
        :return:
        """
        # username needs to be converted to sha256 partial hash and url encoded
        query_params = {
            "partialUsernameHash": hashing.calc_sha256_unsalted_hash(str(username).lower())[:8],
        }

        if include_exposure_details:
            query_params["includeExposureDetails"] = int(include_exposure_details)

        result = urlencode(query_params, quote_via=quote_plus)

        response = self._make_rest_call(
            self.api_base_url + f"/cleartext-credentials-by-partial-hash?{result}", "GET", None
        )
        if response.status_code == 404:
            return False
        else:
            return response.json()

    def get_user_passwords_by_domain(self, domain: str, page_size: int = None, paging_token: str = None) -> Union[bool, Dict]:
        """
        See: https://api.enzoic.com/v1/cleartext-credentials-by-domain
        :param domain: The domain you wish to receive a list of exposed users and their passwords for.
        :param page_size: The amount of results returned per request, defaults to 100, max is 500.
        :param paging_token: If there are additional pages of results then use this to get the next page.
        :return:
        """
        query_params = {
            "domain": str(domain).lower(),
        }
        if page_size:
            query_params["pageSize"] = str(page_size)

        if paging_token:
            query_params["pagingToken"] = paging_token

        result = urlencode(query_params, quote_via=quote_plus)

        response = self._make_rest_call(
            self.api_base_url + f"/cleartext-credentials-by-domain?{result}", "GET", None
        )

        if response.status_code == 404:
            return False
        else:
            return response.json()

    def _make_rest_call(
        self, url: str, method: str, body: Dict = None
    ) -> requests.Response:
        headers = {
            "Authorization": self.auth_string,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if method == "POST" or method == "PUT" or method == "DELETE":
            r = requests.request(method, url=url, headers=headers, json=body)
        else:
            r = requests.request(method, url=url, headers=headers)

        if r.status_code not in (200, 201, 404):
            raise UnexpectedEnzoicAPIError(
                f"Unexpected error from Enzoic API: {r.status_code} {r.text}"
            )
        else:
            return r
