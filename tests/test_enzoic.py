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
        assert enzoic.check_credentials("test@passwordping.com", "123456") is True

    def test_email_creds_are_not_exposed(self, enzoic):
        assert enzoic.check_credentials("test@passwordping.com", "notvalid") is False

    def test_username_creds_are_exposed(self, enzoic):
        assert enzoic.check_credentials("testpwdpng445", "testpwdpng4452") is True

    def test_username_creds_are_not_exposed(self, enzoic):
        assert enzoic.check_credentials("testpwdpng445", "notvalid") is False

    def test_ignored_hash_type_is_not_exposed(self, enzoic, password_types):
        assert enzoic.check_credentials(
            "testpwdpng445",
            "testpwdpng4452",
            exclude_hash_types=[password_types.VBulletinPost3_8_5],
        ) is False

    def test_last_check_date_on_exposure(self, enzoic):
        assert enzoic.check_credentials(
            "testpwdpng445", "testpwdpng4452", last_check_date=datetime(2018, 3, 1)
        ) is False


class TestGetExposuresForUser:
    def test_no_exposure_for_username(self, enzoic):
        """Test a bad value"""
        response = enzoic.get_exposures_for_user("@@bogus-username@@")
        assert response["count"] == 0
        assert len(response["exposures"]) == 0

    def test_actual_exposure_for_username(self, enzoic):
        response = enzoic.get_exposures_for_user("eicar")
        assert response["count"] == 8
        assert len(response["exposures"]) == 8
        assert set(response["exposures"]) == {
            "5820469ffdb8780510b329cc",
            "58258f5efdb8780be88c2c5d",
            "582a8e51fdb87806acc426ff",
            "583d2f9e1395c81f4cfa3479",
            "59ba1aa369644815dcd8683e",
            "59cae0ce1d75b80e0070957c",
            "5bc64f5f4eb6d894f09eae70",
            "5bdcb0944eb6d8a97cfacdff",
        }


class TestGetExposureDetails:
    def test_no_exposure_details(self, enzoic):
        """Test a bad exposure ID"""
        assert enzoic.get_exposure_details("111111111111111111111111") is None

    def test_valid_exposure_with_details(self, enzoic):
        """Test a valid exposure ID"""
        response = enzoic.get_exposure_details("5820469ffdb8780510b329cc")
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
            enzoic.check_password("kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd") is False
        )

    def test_compromised_password(self, enzoic):
        assert enzoic.check_password("123456") is True

    def test_uncompromised_password_no_exposure_stats(self, enzoic):
        (
            compromised,
            revealed_in_exposure,
            relative_exposure_frequency,
            exposure_count,
        ) = enzoic.check_password_ex("kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd")
        assert compromised is False
        assert revealed_in_exposure is False
        assert relative_exposure_frequency is None

    def test_compromised_password_no_exposure_stats(self, enzoic):
        (
            compromised,
            revealed_in_exposure,
            relative_exposure_frequency,
            exposure_count,
        ) = enzoic.check_password_ex("`!(&,<:{`>")
        assert compromised is True
        assert revealed_in_exposure is False
        assert relative_exposure_frequency is None

    def test_compromised_password_has_exposure_stats(self, enzoic):
        (
            compromised,
            revealed_in_exposure,
            relative_exposure_frequency,
            exposure_count,
        ) = enzoic.check_password_ex("password")
        assert compromised is True
        assert revealed_in_exposure is True
        assert relative_exposure_frequency > 0
