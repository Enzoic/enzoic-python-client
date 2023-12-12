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

    def test_hashed_password_by_ntlm(self, enzoic, password_types):
        ntlm_hash = "8846f7eaee8fb117ad06bdd830b7586c"
        assert enzoic().check_hashed_password(hashed_pw=ntlm_hash, hash_type=password_types.NTLM) is True

    def test_hashed_password_by_md5(self, enzoic, password_types):
        md5_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
        assert enzoic().check_hashed_password(hashed_pw=md5_hash, hash_type=password_types.MD5_UNSALTED) is True

    def test_hashed_password_by_sha256(self, enzoic, password_types):
        sha256_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        assert enzoic().check_hashed_password(hashed_pw=sha256_hash, hash_type=password_types.SHA256_UNSALTED) is True

    def test_hashed_password_by_sha1(self, enzoic, password_types):
        sha1_hash = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
        assert enzoic().check_hashed_password(hashed_pw=sha1_hash, hash_type=password_types.SHA1_UNSALTED) is True

    def test_unsupported_hash_type_provided(self, enzoic, password_types, enzoic_exceptions):
        ntlm_hash = "8846f7eaee8fb117ad06bdd830b7586c"
        with pytest.raises(enzoic_exceptions.UnsupportedPasswordType) as exc_info:
            enzoic().check_hashed_password(hashed_pw=ntlm_hash, hash_type=password_types.VBulletinPost3_8_5)
            assert "Unsupported hash type provided." in str(exc_info.value)
            assert password_types.NTLM in str(exc_info.value)
            assert password_types.SHA1_UNSALTED in str(exc_info.value)
            assert password_types.SHA256_UNSALTED in str(exc_info.value)
            assert password_types.MD5_UNSALTED in str(exc_info.value)

    def test_uncompromised_password_hash(self, enzoic, password_types):
        ntlm_hash = "6708d6fd35e9fbcda86be9703a20af8c6f595a2f"
        assert enzoic().check_hashed_password(hashed_pw=ntlm_hash, hash_type=password_types.NTLM) is False

    def test_get_candidates_by_partial_ntlm_hash(self, enzoic, password_types):
        ntlm_hash = "8846f7e"
        candidates = enzoic().retrieve_list_of_candidates_for_partial_hash(hashed_pw=ntlm_hash, hash_type=password_types.NTLM)
        assert len(candidates) > 0
        for candidate in candidates:
            assert candidate.startswith(ntlm_hash)

    def test_get_candidates_by_partial_md5_hash(self, enzoic, password_types):
        md5_hash = "5f4dcc3"
        candidates = enzoic().retrieve_list_of_candidates_for_partial_hash(hashed_pw=md5_hash, hash_type=password_types.MD5_UNSALTED)
        assert len(candidates) > 0
        for candidate in candidates:
            assert candidate.startswith(md5_hash)

    def test_get_candidates_by_partial_sha256_hash(self, enzoic, password_types):
        sha256_hash = "5e88489"
        candidates = enzoic().retrieve_list_of_candidates_for_partial_hash(hashed_pw=sha256_hash, hash_type=password_types.SHA256_UNSALTED)
        assert len(candidates) > 0
        for candidate in candidates:
            assert candidate.startswith(sha256_hash)

    def test_get_candidates_by_partial_sha1_hash(self, enzoic, password_types):
        sha1_hash = "5baa61e"
        candidates = enzoic().retrieve_list_of_candidates_for_partial_hash(hashed_pw=sha1_hash, hash_type=password_types.SHA256_UNSALTED)
        assert len(candidates) > 0
        for candidate in candidates:
            assert candidate.startswith(sha1_hash)

    def test_get_candidates_unsupported_partial_hash_type_provided(self, enzoic, password_types, enzoic_exceptions):
        ntlm_hash = "8846f7e"
        with pytest.raises(enzoic_exceptions.UnsupportedPasswordType) as exc_info:
            enzoic().retrieve_list_of_candidates_for_partial_hash(hashed_pw=ntlm_hash, hash_type=password_types.VBulletinPost3_8_5)
            assert "Unsupported hash type provided." in str(exc_info.value)
            assert password_types.NTLM in str(exc_info.value)
            assert password_types.SHA1_UNSALTED in str(exc_info.value)
            assert password_types.SHA256_UNSALTED in str(exc_info.value)
            assert password_types.MD5_UNSALTED in str(exc_info.value)

    def test_partial_hash_too_short(self, enzoic, password_types):
        with pytest.raises(ValueError) as exc_info:
            ntlm_hash = "000000"
            enzoic().retrieve_list_of_candidates_for_partial_hash(hashed_pw=ntlm_hash, hash_type=password_types.NTLM)
            assert "Password hash must be greater than or equal to 7 characters in length." in exc_info.value


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


class TestGetUserPasswordsByDomain:
    def test_get_passwords_for_domain_default_page_size(self, enzoic):
        domain_response = enzoic().get_user_passwords_by_domain(domain="enzoic.com")
        assert domain_response["count"] == 94
        assert domain_response["pagingToken"] is None
        assert len(domain_response["users"]) == 94

    def test_get_passwords_for_domain_specific_page_size(self, enzoic):
        domain_response = enzoic().get_user_passwords_by_domain(domain="enzoic.com", page_size=10)
        assert domain_response["count"] == 94
        assert domain_response["pagingToken"] is not None
        assert len(domain_response["users"]) == 10

    def test_get_passwords_for_domain_pagination(self, enzoic):
        paged_response = enzoic().get_user_passwords_by_domain(domain="enzoic.com", page_size=10)
        # now get the paginated results
        domain_response = enzoic().get_user_passwords_by_domain(domain="enzoic.com", paging_token=paged_response["pagingToken"])
        assert domain_response["count"] == 94
        assert domain_response["pagingToken"] is None
        assert len(domain_response["users"]) == 84


class TestGetUserPasswordsByPartialHash:
    def test_get_user_password(self, enzoic):
        response = enzoic().get_user_passwords_by_partial_hash("eicar_0@enzoic.com")
        assert response["candidates"] == [
            {
                'usernameHash': '705bce5505615a1437cc005f933f5891c53778ead4b18b44195682b2ae90d7f7',
                'lastBreachDate': '2020-04-23T17:06:16.000Z',
                'passwords': [
                    {'hashType': 0, 'salt': '', 'password': 'sofi130991', 'exposures': ['5825260cfdb8780854c40c84']},
                    {'hashType': 0, 'salt': '', 'password': 'Merda39a2j', 'exposures': ['5820469ffdb8780510b329cc']},
                    {'hashType': 0, 'salt': '', 'password': 'nirvana', 'exposures': ['5ea1cb08d3cef70b4cda265a']}]
            },
            {
                'usernameHash': '705bce557110384a4ce76aa9c33a12af14ac1eee3978ac3076f866aa0d84f07a',
                'lastBreachDate': '2022-10-14T07:02:40.000Z',
                'passwords': [
                    {'hashType': 0, 'salt': '', 'password': 'password123', 'exposures': ['634908d2e0513eb0788aa0b9', '634908d06715cc1b5b201a1a']},
                    {'hashType': 0, 'salt': '', 'password': 'g0oD_on3', 'exposures': ['634908d2e0513eb0788aa0b9']},
                    {'hashType': 0, 'salt': '', 'password': 'Easy2no', 'exposures': ['634908d26715cc1b5b201a1d']},
                    {'hashType': 0, 'salt': '', 'password': '123456', 'exposures': ['63490990e0513eb0788aa0d1', '634908d0e0513eb0788aa0b5']}]
            },
            {
                'usernameHash': '705bce557ebcf8504587e87fb691ae37c2f00655db024f0fc72c29b775533641',
                'lastBreachDate': '2022-05-16T17:20:13.000Z',
                'passwords': [
                    {'hashType': 0, 'salt': '', 'password': '122000888', 'exposures': ['628287cd3e27d0867a43070a']}
                ]
            }
        ]

    def test_get_user_password_with_details(self, enzoic):
        response = enzoic().get_user_passwords_by_partial_hash("eicar_0@enzoic.com", include_exposure_details=True)
        assert response["candidates"] == [
           {
              "usernameHash":"705bce5505615a1437cc005f933f5891c53778ead4b18b44195682b2ae90d7f7",
              "lastBreachDate":"2020-04-23T17:06:16.000Z",
              "passwords":[
                 {
                    "hashType":0,
                    "salt":"",
                    "password":"sofi130991",
                    "exposures":[
                       {
                          "id":"5825260cfdb8780854c40c84",
                          "title":"zoosk.com",
                          "entries":53778792,
                          "date":"2011-12-31T00:00:00.000Z",
                          "category":"Dating",
                          "source":"Unspecified",
                          "passwordType":"MD5",
                          "exposedData":[
                             "Emails",
                             "Passwords",
                             "Usernames"
                          ],
                          "dateAdded":"2016-11-11T01:59:40.000Z",
                          "sourceURLs":[

                          ],
                          "sourceFileCount":1,
                          "domainsAffected":639449
                       }
                    ]
                 },
                 {
                    "hashType":0,
                    "salt":"",
                    "password":"Merda39a2j",
                    "exposures":[
                       {
                          "id":"5820469ffdb8780510b329cc",
                          "title":"last.fm",
                          "entries":81967007,
                          "date":"2012-03-01T00:00:00.000Z",
                          "category":"Music",
                          "source":"Unspecified",
                          "passwordType":"MD5",
                          "exposedData":[
                             "Emails",
                             "Passwords",
                             "Usernames",
                             "Website Activity"
                          ],
                          "dateAdded":"2016-11-07T09:17:19.000Z",
                          "sourceURLs":[

                          ],
                          "sourceFileCount":1,
                          "domainsAffected":1219053
                       }
                    ]
                 },
                 {
                    "hashType":0,
                    "salt":"",
                    "password":"nirvana",
                    "exposures":[
                       {
                          "id":"5ea1cb08d3cef70b4cda265a",
                          "title":"christianpassions.com",
                          "entries":1275759,
                          "date":"2020-02-01T00:00:00.000Z",
                          "category":"Dating",
                          "source":"Unspecified",
                          "passwordType":"Cleartext",
                          "exposedData":[
                             "Passwords",
                             "Usernames"
                          ],
                          "dateAdded":"2020-04-23T17:06:16.000Z",
                          "sourceURLs":[

                          ],
                          "sourceFileCount":1,
                          "domainsAffected":16150
                       }
                    ]
                 }
              ]
           },
           {
              "usernameHash":"705bce557110384a4ce76aa9c33a12af14ac1eee3978ac3076f866aa0d84f07a",
              "lastBreachDate":"2022-10-14T07:02:40.000Z",
              "passwords":[
                 {
                    "hashType":0,
                    "salt":"",
                    "password":"password123",
                    "exposures":[
                       {
                          "id":"634908d06715cc1b5b201a1a",
                          "title":"enzoic test breach 1",
                          "entries":5,
                          "date":None,
                          "category":"Testing Ignore",
                          "source":"Testing - Ignore",
                          "passwordType":"MD5",
                          "exposedData":[
                             "Emails",
                             "Passwords"
                          ],
                          "dateAdded":"2022-10-14T06:59:28.000Z",
                          "sourceURLs":[

                          ],
                          "sourceFileCount":1,
                          "domainsAffected":1
                       },
                       {
                          "id":"634908d2e0513eb0788aa0b9",
                          "title":"enzoic test breach 5",
                          "entries":2,
                          "date":None,
                          "category":"Testing Ignore",
                          "source":"Testing - Ignore",
                          "passwordType":"Cleartext",
                          "exposedData":[
                             "Emails",
                             "Passwords"
                          ],
                          "dateAdded":"2022-10-14T06:59:30.000Z",
                          "sourceURLs":[

                          ],
                          "sourceFileCount":1,
                          "domainsAffected":1
                       }
                    ]
                 },
                 {
                    "hashType":0,
                    "salt":"",
                    "password":"g0oD_on3",
                    "exposures":[
                       {
                          "id":"634908d2e0513eb0788aa0b9",
                          "title":"enzoic test breach 5",
                          "entries":2,
                          "date":None,
                          "category":"Testing Ignore",
                          "source":"Testing - Ignore",
                          "passwordType":"Cleartext",
                          "exposedData":[
                             "Emails",
                             "Passwords"
                          ],
                          "dateAdded":"2022-10-14T06:59:30.000Z",
                          "sourceURLs":[

                          ],
                          "sourceFileCount":1,
                          "domainsAffected":1
                       }
                    ]
                 },
                 {
                    "hashType":0,
                    "salt":"",
                    "password":"Easy2no",
                    "exposures":[
                       {
                          "id":"634908d26715cc1b5b201a1d",
                          "title":"enzoic test breach 4",
                          "entries":4,
                          "date":None,
                          "category":"Testing Ignore",
                          "source":"Testing - Ignore",
                          "passwordType":"MD5",
                          "exposedData":[
                             "Emails",
                             "Passwords"
                          ],
                          "dateAdded":"2022-10-14T06:59:30.000Z",
                          "sourceURLs":[

                          ],
                          "sourceFileCount":1,
                          "domainsAffected":1
                       }
                    ]
                 },
                 {
                    "hashType":0,
                    "salt":"",
                    "password":"123456",
                    "exposures":[
                       {
                          "id":"634908d0e0513eb0788aa0b5",
                          "title":"enzoic test breach 2",
                          "entries":5,
                          "date":None,
                          "category":"Testing Ignore",
                          "source":"Testing - Ignore",
                          "passwordType":"MD5",
                          "exposedData":[
                             "Emails",
                             "Passwords"
                          ],
                          "dateAdded":"2022-10-14T06:59:28.000Z",
                          "sourceURLs":[

                          ],
                          "sourceFileCount":1,
                          "domainsAffected":1
                       },
                       {
                          "id":"63490990e0513eb0788aa0d1",
                          "title":"enzoic test breach 3",
                          "entries":3,
                          "date":None,
                          "category":"Testing Ignore",
                          "source":"Testing - Ignore",
                          "passwordType":"Cleartext",
                          "exposedData":[
                             "Emails",
                             "Passwords"
                          ],
                          "dateAdded":"2022-10-14T07:02:40.000Z",
                          "sourceURLs":[

                          ],
                          "sourceFileCount":1,
                          "domainsAffected":1
                       }
                    ]
                 }
              ]
           },
           {
              "usernameHash":"705bce557ebcf8504587e87fb691ae37c2f00655db024f0fc72c29b775533641",
              "lastBreachDate":"2022-05-16T17:20:13.000Z",
              "passwords":[
                 {
                    "hashType":0,
                    "salt":"",
                    "password":"122000888",
                    "exposures":[
                       {
                          "id":"628287cd3e27d0867a43070a",
                          "title":"readnovel.com",
                          "entries":19125314,
                          "date":"2019-05-01T00:00:00.000Z",
                          "category":"Books",
                          "source":"Unspecified",
                          "passwordType":"MD5",
                          "exposedData":[
                             "Emails",
                             "Passwords",
                             "Usernames",
                             "Phone Numbers",
                             "Genders"
                          ],
                          "dateAdded":"2022-05-16T17:20:13.000Z",
                          "sourceURLs":[

                          ],
                          "sourceFileCount":1,
                          "domainsAffected":297923
                       }
                    ]
                 }
              ]
           }
        ]

    def test_get_user_password_not_found(self, enzoic):
        response = enzoic().get_user_passwords_by_partial_hash(username="!!!!!@@bogus-user@@!!!!!")
        assert len(response["candidates"]) == 0

    def test_account_without_permissions(self, enzoic, enzoic_exceptions):
        with pytest.raises(enzoic_exceptions.UnexpectedEnzoicAPIError) as exc_info:
            enzoic(
                os.environ.get("PP_API_KEY_2"), os.environ.get("PP_API_SECRET_2")
            ).get_user_passwords_by_partial_hash("eicar_0@enzoic.com")
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


class TestDomainAlertSubscriptions:
    TEST_DOMAINS = [
        "enzoictestadddomaintest1.com",
        "enzoictestadddomaintest2.com"
    ]

    def test_clean_up_previous_add_domain_data(self, enzoic):
        response = enzoic().delete_domain_alert_subscriptions(domains=self.TEST_DOMAINS)
        assert response["deleted"] >= 0
        assert response["notFound"] >= 0

    def test_add_domain_alert_subscriptions(self, enzoic):
        response = enzoic().add_domain_alert_subscriptions(domains=self.TEST_DOMAINS)
        assert response["added"] >= 2
        assert response["alreadyExisted"] >= 0

    def test_add_domain_alert_subscriptions_again(self, enzoic):
        response = enzoic().add_domain_alert_subscriptions(domains=self.TEST_DOMAINS)
        assert response["added"] >= 0
        assert response["alreadyExisted"] >= 2

    def test_delete_domain_alert_subscription(self, enzoic):
        response = enzoic().delete_domain_alert_subscriptions(domains=self.TEST_DOMAINS)
        assert response["deleted"] >= 2
        assert response["notFound"] >= 0

    def test_delete_domain_alert_subscription_again_shows_not_found(self, enzoic):
        response = enzoic().delete_domain_alert_subscriptions(domains=self.TEST_DOMAINS)
        assert response["deleted"] >= 0
        assert response["notFound"] >= 2


class TestIsDomainSubscribedForAlerts:
    TEST_DOMAIN = "enzoictesttestdomaintest1.com"

    def test_add_test_data(self, enzoic):
        response = enzoic().add_domain_alert_subscriptions(self.TEST_DOMAIN)
        assert response["added"] >= 0
        assert response["alreadyExisted"] >= 0

    def test_domain_subscription_exists(self, enzoic):
        response = enzoic().is_domain_subscribed_for_alerts(self.TEST_DOMAIN)
        assert response is True

    def test_delete_test_data(self, enzoic):
        response = enzoic().delete_domain_alert_subscriptions(self.TEST_DOMAIN)
        assert response["deleted"] >= 0
        assert response["notFound"] >= 0

    def test_domain_subscription_doesnt_exist(self, enzoic):
        response = enzoic().is_domain_subscribed_for_alerts(self.TEST_DOMAIN)
        assert response is False


class TestGetDomainAlertSubscriptions:
    TEST_DOMAINS = [
        "enzoictestgetdomaintest1.com",
        "enzoictestgetdomaintest2.com",
        "enzoictestgetdomaintest3.com",
        "enzoictestgetdomaintest4.com",
        "enzoictestgetdomaintest5.com",
        "enzoictestgetdomaintest6.com",
        "enzoictestgetdomaintest7.com",
        "enzoictestgetdomaintest8.com",
        "enzoictestgetdomaintest9.com",
        "enzoictestgetdomaintest10.com",
        "enzoictestgetdomaintest11.com",
        "enzoictestgetdomaintest12.com",
        "enzoictestgetdomaintest13.com",
        "enzoictestgetdomaintest14.com"
    ]

    def test_add_test_data(self, enzoic):
        response = enzoic().add_domain_alert_subscriptions(self.TEST_DOMAINS)
        assert response["added"] >= 0
        assert response["alreadyExisted"] >= 0

    def test_get_subscribed_domains(self, enzoic):
        response = enzoic().get_domain_alert_subscriptions(4)
        assert response["count"] >= 13
        assert len(response["domains"]) == 4
        assert response["pagingToken"] is not None

    def test_get_subscribed_domains_for_next_page(self, enzoic):
        first = enzoic().get_domain_alert_subscriptions(4)
        paged_response = enzoic().get_domain_alert_subscriptions(4, paging_token=first["pagingToken"])
        assert paged_response["count"] >= 13
        assert len(paged_response["domains"]) == 4
        assert paged_response["pagingToken"] is not None


