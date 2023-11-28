import os
import pytest
from datetime import datetime


class TestEnzoic:
    def test_constructor_with_null_parameters(self, check_constructor_with_parameters):
        assert check_constructor_with_parameters(None, None) is True

    def test_constructor_with_null_secret(self, check_constructor_with_parameters):
        assert check_constructor_with_parameters("test", None) is True

    def test_constructor_with_null_key(self, check_constructor_with_parameters):
        assert check_constructor_with_parameters(None, "test") is True

    def test_constructor_with_empty_str_parameters(
        self, check_constructor_with_parameters
    ):
        assert check_constructor_with_parameters("", "") is True

    def test_constructor_with_empty_str_key(self, check_constructor_with_parameters):
        assert check_constructor_with_parameters("", "test") is True

    def test_constructor_with_empty_str_secret(self, check_constructor_with_parameters):
        assert check_constructor_with_parameters("test", "") is True

    def test_constructor_with_valid_parameters(self, check_constructor_with_parameters):
        assert check_constructor_with_parameters("test", "test") is False


class TestCheckCredentials:
    def test_email_creds_are_exposed(self, enzoic):
        assert enzoic().check_credentials("test@passwordping.com", "123456") is True

    def test_email_creds_are_not_exposed(self, enzoic):
        assert enzoic().check_credentials("test@passwordping.com", "notvalid") is False

    def test_username_creds_are_exposed(self, enzoic):
        assert enzoic().check_credentials("testpwdpng445", "testpwdpng4452") is True

    def test_username_creds_are_not_exposed(self, enzoic):
        assert enzoic().check_credentials("testpwdpng445", "notvalid") is False

    def test_ignored_hash_type_is_not_exposed(self, enzoic, password_types):
        assert enzoic().check_credentials(
            "testpwdpng445",
            "testpwdpng4452",
            exclude_hash_types=[password_types.VBulletinPost3_8_5],
        ) is False

    def test_last_check_date_on_exposure(self, enzoic):
        assert enzoic().check_credentials(
            "testpwdpng445", "testpwdpng4452", last_check_date=datetime(2018, 3, 1)
        ) is False


class TestGetExposuresForUser:
    def test_no_exposure_for_username(self, enzoic):
        """Test a bad value"""
        response = enzoic().get_exposures_for_user("@@bogus-username@@")
        assert response["count"] == 0
        assert len(response["exposures"]) == 0

    def test_actual_exposure_for_username(self, enzoic):
        response = enzoic().get_exposures_for_user("eicar")
        assert response["count"] == 9
        assert len(response["exposures"]) == 9
        assert set(response["exposures"]) == {
            "5820469ffdb8780510b329cc",
            "58258f5efdb8780be88c2c5d",
            "582a8e51fdb87806acc426ff",
            "583d2f9e1395c81f4cfa3479",
            "59ba1aa369644815dcd8683e",
            "59cae0ce1d75b80e0070957c",
            "5bc64f5f4eb6d894f09eae70",
            "5bdcb0944eb6d8a97cfacdff",
            "653980098502d3ce61f8bfbb"
        }


class TestGetExposureDetails:
    def test_no_exposure_details(self, enzoic):
        """Test a bad exposure ID"""
        assert enzoic().get_exposure_details("111111111111111111111111") is None

    def test_valid_exposure_with_details(self, enzoic):
        """Test a valid exposure ID"""
        response = enzoic().get_exposure_details("5820469ffdb8780510b329cc")
        assert response is not None
        assert "5820469ffdb8780510b329cc" == response["id"]
        assert "last.fm" == response["title"]
        assert "Music" == response["category"]
        assert datetime(2012, 3, 1).isoformat() in response["date"]
        assert "MD5" == response["passwordType"]
        assert {"Emails", "Passwords", "Usernames", "Website Activity"} == set(
            response["exposedData"]
        )
        assert 81967007 == response["entries"]
        assert 1219053 == response["domainsAffected"]


class TestCheckPassword:
    def test_uncompromised_password(self, enzoic):
        assert (
            enzoic().check_password("kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd") is False
        )

    def test_compromised_password(self, enzoic):
        assert enzoic().check_password("123456") is True

    def test_uncompromised_password_no_exposure_stats(self, enzoic):
        (
            compromised,
            revealed_in_exposure,
            relative_exposure_frequency,
            exposure_count,
        ) = enzoic().check_password_ex("kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd")
        assert compromised is False
        assert revealed_in_exposure is False
        assert relative_exposure_frequency is None

    def test_compromised_password_no_exposure_stats(self, enzoic):
        (
            compromised,
            revealed_in_exposure,
            relative_exposure_frequency,
            exposure_count,
        ) = enzoic().check_password_ex("`!(&,<:{`>")
        assert compromised is True
        assert revealed_in_exposure is False
        assert relative_exposure_frequency is None

    def test_compromised_password_has_exposure_stats(self, enzoic):
        (
            compromised,
            revealed_in_exposure,
            relative_exposure_frequency,
            exposure_count,
        ) = enzoic().check_password_ex("password")
        assert compromised is True
        assert revealed_in_exposure is True
        assert relative_exposure_frequency > 0


class TestGetUserPasswords:
    def test_get_user_password(self, enzoic):
        response = enzoic().get_user_passwords("eicar_0@enzoic.com")
        assert len(response["passwords"]) == 4
        assert response["lastBreachDate"] == "2022-10-14T07:02:40.000Z"
        assert response["passwords"] == [
            {
                "hashType": 0,
                "salt": "",
                "password": "password123",
                "exposures": [
                    "634908d2e0513eb0788aa0b9",
                    "634908d06715cc1b5b201a1a"
                ]
            },
            {
                "hashType": 0,
                "salt": "",
                "password": "g0oD_on3",
                "exposures": [
                    "634908d2e0513eb0788aa0b9"
                ]
            },
            {
                "hashType": 0,
                "salt": "",
                "password": "Easy2no",
                "exposures": [
                    "634908d26715cc1b5b201a1d"
                ]
            },
            {
                "hashType": 0,
                "salt": "",
                "password": "123456",
                "exposures": [
                    "63490990e0513eb0788aa0d1",
                    "634908d0e0513eb0788aa0b5"
                ]
            }
        ]

    def test_get_user_password_with_details(self, enzoic):
        response = enzoic().get_user_passwords("eicar_0@enzoic.com", include_exposure_details=True)
        assert len(response["passwords"]) == 4
        assert response["lastBreachDate"] == "2022-10-14T07:02:40.000Z"
        assert response["passwords"] == [
            {
            "hashType": 0,
            "salt": "",
            "password": "password123",
            "exposures": [
                {
                    "category": "Testing Ignore",
                    "date": None,
                    "dateAdded": "2022-10-14T06:59:28.000Z",
                    "domainsAffected": 1,
                    "entries": 5,
                    "exposedData": [
                        "Emails",
                        "Passwords"
                    ],
                    "id": "634908d06715cc1b5b201a1a",
                    "passwordType": "MD5",
                    "source": "Testing - Ignore",
                    "sourceFileCount": 1,
                    "sourceURLs": [],
                    "title": "enzoic test breach 1",
                },
                {
                    "category": "Testing Ignore",
                    "date": None,
                    "dateAdded": "2022-10-14T06:59:30.000Z",
                    "domainsAffected": 1,
                    "entries": 2,
                    "exposedData": [
                        "Emails",
                        "Passwords"
                    ],
                    "id": "634908d2e0513eb0788aa0b9",
                    "passwordType": "Cleartext",
                    "source": "Testing - Ignore",
                    "sourceFileCount": 1,
                    "sourceURLs": [],
                    "title": "enzoic test breach 5"
                }
            ]
        },
        {
            "hashType": 0,
            "salt": "",
            "password": "g0oD_on3",
            "exposures": [
                {
                    "category": "Testing Ignore",
                    "date": None,
                    "dateAdded": "2022-10-14T06:59:30.000Z",
                    "domainsAffected": 1,
                    "entries": 2,
                    "exposedData": [
                        "Emails",
                        "Passwords"
                    ],
                    "id": "634908d2e0513eb0788aa0b9",
                    "passwordType": "Cleartext",
                    "source": "Testing - Ignore",
                    "sourceFileCount": 1,
                    "sourceURLs": [],
                    "title": "enzoic test breach 5"
                }
            ]
        },
        {
            "hashType": 0,
            "salt": "",
            "password": "Easy2no",
            "exposures": [
                {
                    "category": "Testing Ignore",
                    "date": None,
                    "dateAdded": "2022-10-14T06:59:30.000Z",
                    "domainsAffected": 1,
                    "entries": 4,
                    "exposedData": [
                        "Emails",
                        "Passwords"
                    ],
                    "id": "634908d26715cc1b5b201a1d",
                    "passwordType": "MD5",
                    "source": "Testing - Ignore",
                    "sourceFileCount": 1,
                    "sourceURLs": [],
                    "title": "enzoic test breach 4"
                }
            ]
        },
        {
            "hashType": 0,
            "salt": "",
            "password": "123456",
            "exposures": [
                {
                    "category": "Testing Ignore",
                    "date": None,
                    "dateAdded": "2022-10-14T06:59:28.000Z",
                    "domainsAffected": 1,
                    "entries": 5,
                    "exposedData": [
                        "Emails",
                        "Passwords"
                    ],
                    "id": "634908d0e0513eb0788aa0b5",
                    "passwordType": "MD5",
                    "source": "Testing - Ignore",
                    "sourceFileCount": 1,
                    "sourceURLs": [],
                    "title": "enzoic test breach 2"
                },
                {
                    "category": "Testing Ignore",
                    "date": None,
                    "dateAdded": "2022-10-14T07:02:40.000Z",
                    "domainsAffected": 1,
                    "entries": 3,
                    "exposedData": [
                        "Emails",
                        "Passwords"
                    ],
                    "id": "63490990e0513eb0788aa0d1",
                    "passwordType": "Cleartext",
                    "source": "Testing - Ignore",
                    "sourceFileCount": 1,
                    "sourceURLs": [],
                    "title": "enzoic test breach 3",
                }
            ]
        }
    ]

    def test_get_user_password_not_found(self, enzoic):
        response = enzoic().get_user_passwords(username="@@bogus-user@@")
        assert response is False

    def test_account_without_permissions(self, enzoic, enzoic_exceptions):
        with pytest.raises(enzoic_exceptions.UnexpectedEnzoicAPIError) as exc_info:
            enzoic(
                os.environ.get("PP_API_KEY_2"), os.environ.get("PP_API_SECRET_2")
            ).get_user_passwords("eicar_0@enzoic.com")
        assert "Your account is not allowed to make this call.  Please contact sales@enzoic.com." in str(exc_info.value)


class TestGetDomainExposures:

    def test_get_exposed_users_for_domain_no_details(self, enzoic):
        response = enzoic().get_exposures_for_domain("email.tst", include_exposure_details=False)
        assert response["count"] == 10
        assert len(response["exposures"]) == 10
        assert response["exposures"] == [
            "57ffcf3c1395c80b30dd4429",
            "57dc11964d6db21300991b78",
            "5805029914f33808dc802ff7",
            "598e5b844eb6d82ea07c5783",
            "59bbf691e5017d2dc8a96eab",
            "59bc2016e5017d2dc8bdc36a",
            "59bebae9e5017d2dc85fc2ab",
            "59f36f8c4eb6d85ba0bee09c",
            "5bcf9af3e5017d07201e2149",
            "5c4f818bd3cef70e983dda1e"
        ]

    def test_get_exposed_users_for_domain_with_details(self, enzoic):
        response = enzoic().get_exposures_for_domain("email.tst", include_exposure_details=True)
        assert response["count"] == 10
        assert len(response["exposures"]) == 10
        assert response["exposures"][0] == {
            "id": "57dc11964d6db21300991b78",
            "title": "funsurveys.net",
            "entries": 5123,
            "date": "2015-05-01T00:00:00.000Z",
            "category": "Marketing",
            "passwordType": "Cleartext",
            "exposedData": [
                "Emails",
                "Passwords"
            ],
            "dateAdded": "2016-09-16T15:36:54.000Z",
            "sourceURLs": [],
            "domainsAffected": 683,
            "source": "Unspecified",
            "sourceFileCount": 1
        }

    def test_get_users_for_bad_domain_no_results(self, enzoic):
        response = enzoic().get_exposures_for_domain("@@bogus-domain@@")
        assert response["count"] == 0
        assert len(response["exposures"]) == 0

    def test_get_exposed_users_for_domain_with_specified_page_size(self, enzoic):
        response = enzoic().get_exposures_for_domain("email.tst", include_exposure_details=False, page_size=2)
        assert response["count"] == 10
        assert len(response["exposures"]) == 2
        assert response["pagingToken"] is not None
        assert response["exposures"] == [
            "57ffcf3c1395c80b30dd4429",
            "57dc11964d6db21300991b78",
        ]

    def test_get_exposed_users_for_domain_pagination(self, enzoic):
        domain = "email.tst"
        first_response = enzoic().get_exposures_for_domain(domain, include_exposure_details=False, page_size=2)
        # now retrieve the second page with all the results
        paged_response = enzoic().get_exposures_for_domain(domain, include_exposure_details=True, paging_token=first_response["pagingToken"])
        assert paged_response["count"] == 10
        assert len(paged_response["exposures"]) == 8
        assert paged_response["pagingToken"] is None


class TestAlertSubscriptions:
    TEST_USERS = [
            "eicar_0@enzoic.com",
            "eicar_1@enzoic.com"
        ]

    @pytest.mark.order(1)
    def test_user_alert_subscription_cleanup_previous_test_data(self, enzoic):
        response = enzoic().delete_user_alert_subscriptions(username_hashes=self.TEST_USERS)
        assert response["deleted"] >= 0
        assert response["notFound"] >= 0

    @pytest.mark.order(2)
    def test_add_user_alert_subscription(self, enzoic):
        response = enzoic().add_user_alert_subscriptions(username_hashes=self.TEST_USERS)
        assert response == {
            "added": 2,
            "alreadyExisted": 0,
        }

    @pytest.mark.order(3)
    def test_add_user_alert_subscription_again(self, enzoic):
        response = enzoic().add_user_alert_subscriptions(username_hashes=self.TEST_USERS)
        assert response == {
            "added": 0,
            "alreadyExisted": 2,
        }

    @pytest.mark.order(4)
    def test_user_alert_subscription_cleanup(self, enzoic):
        response = enzoic().delete_user_alert_subscriptions(username_hashes=self.TEST_USERS)
        assert response["deleted"] == 2
        assert response["notFound"] == 0

    @pytest.mark.order(5)
    def test_user_alert_subscription_cleanup_no_data(self, enzoic):
        response = enzoic().delete_user_alert_subscriptions(username_hashes=self.TEST_USERS)
        assert response["deleted"] == 0
        assert response["notFound"] == 2


class TestAlertSubscriptionsCustomData:
    TEST_USERS = [
            "eicar_0@enzoic.com",
            "eicar_1@enzoic.com"
        ]
    CUSTOM_DATA_1 = "123456"
    CUSTOM_DATA_2 = "1234567"

    @pytest.mark.order(6)
    def test_user_alert_subscription_custom_data_cleanup_previous_test_data(self, enzoic):
        response = enzoic().delete_user_alert_subscriptions_with_custom_data(custom_data=self.CUSTOM_DATA_1)
        assert response["deleted"] >= 0
        assert response["notFound"] >= 0

    @pytest.mark.order(7)
    def test_user_alert_subscription_custom_data_cleanup_previous_test_data_2(self, enzoic):
        response = enzoic().delete_user_alert_subscriptions_with_custom_data(custom_data=self.CUSTOM_DATA_2)
        assert response["deleted"] >= 0
        assert response["notFound"] >= 0

    @pytest.mark.order(8)
    def test_add_user_alert_subscription_custom_data(self, enzoic):
        response = enzoic().add_user_alert_subscriptions(username_hashes=self.TEST_USERS, custom_data=self.CUSTOM_DATA_1)
        assert response == {
            "added": 2,
            "alreadyExisted": 0,
        }

    @pytest.mark.order(9)
    def test_add_user_alert_subscription_again_custom_data(self, enzoic):
        response = enzoic().add_user_alert_subscriptions(username_hashes=self.TEST_USERS, custom_data=self.CUSTOM_DATA_1)
        assert response == {
            "added": 0,
            "alreadyExisted": 2,
        }

    @pytest.mark.order(10)
    def test_add_user_alert_subscription_again_different_custom_data(self, enzoic):
        response = enzoic().add_user_alert_subscriptions(username_hashes=self.TEST_USERS, custom_data=self.CUSTOM_DATA_2)
        assert response == {
            "added": 2,
            "alreadyExisted": 0,
        }

    @pytest.mark.order(11)
    def test_user_alert_subscription_cleanup_custom_data(self, enzoic):
        response = enzoic().delete_user_alert_subscriptions_with_custom_data(custom_data=self.CUSTOM_DATA_1)
        assert response["deleted"] == 2
        assert response["notFound"] == 0

    @pytest.mark.order(12)
    def test_user_alert_subscription_cleanup_alt_custom_data(self, enzoic):
        response = enzoic().delete_user_alert_subscriptions_with_custom_data(custom_data=self.CUSTOM_DATA_2)
        assert response["deleted"] == 2
        assert response["notFound"] == 0

    @pytest.mark.order(13)
    def test_user_alert_subscription_cleanup_custom_data_nothing_to_delete(self, enzoic):
        response = enzoic().delete_user_alert_subscriptions_with_custom_data(custom_data=self.CUSTOM_DATA_1)
        assert response["deleted"] == 0
        assert response["notFound"] == 1

    @pytest.mark.order(14)
    def test_user_alert_subscription_cleanup_alt_custom_data_nothing_to_delete(self, enzoic):
        response = enzoic().delete_user_alert_subscriptions_with_custom_data(custom_data=self.CUSTOM_DATA_2)
        assert response["deleted"] == 0
        assert response["notFound"] == 1


class TestGetUserAlertSubscriptions:
    TEST_USER_HASHES = [
        "eicar_0@enzoic.com",
        "eicar_1@enzoic.com",
        "eicar_2@enzoic.com",
        "eicar_3@enzoic.com",
        "eicar_4@enzoic.com",
        "eicar_5@enzoic.com",
        "eicar_6@enzoic.com",
        "eicar_7@enzoic.com",
        "eicar_8@enzoic.com",
        "eicar_9@enzoic.com",
        "eicar_10@enzoic.com",
        "eicar_11@enzoic.com",
        "eicar_12@enzoic.com",
        "eicar_13@enzoic.com",
    ]

    def test_add_large_user_alert_subscriptions(self, enzoic):
        response = enzoic().add_user_alert_subscriptions(username_hashes=self.TEST_USER_HASHES)
        assert response["added"] >= 0
        assert response["alreadyExisted"] >= 0

    def test_user_get_alert_subscriptions(self, enzoic):
        response = enzoic().get_user_alert_subscriptions(4)
        assert response["count"] > 13
        assert len(response["usernameHashes"]) >= 4
        assert response["pagingToken"] is not None
