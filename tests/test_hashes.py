from src.utilities.hashing import Hashing


class TestEnzoic:

    def test_unsalted_sha_256(self):
        assert '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8' \
               == Hashing.calc_sha256_unsalted_hash('password')

    def test_unsalted_sha_1(self):
        assert '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' == Hashing.calc_sha1_unsalted_hash('password')

    def test_unsalted_md5(self):
        assert '5f4dcc3b5aa765d61d8327deb882cf99' == Hashing.calc_md5_unsalted_hash('password')

    def test_ipboard_mybb_hash(self):
        assert '96c06579d8dfc66d81f05aab51a9b284' == Hashing.calc_ipboard_mybb_hash('123456', '12345')

    def test_triple_des_hash(self):
        assert "yDba8kDA7NUDQ" == Hashing.calc_triple_des_hash('qwerty', 'yD')

    def test_vbulletin_pre_385_hash(self):
        assert '77d3b7ed9db7d236b9eac8262d27f6a5' == Hashing.calc_vbulletin_pre_3_8_5_hash('123456', '123')

    def test_vbulletin_post_385_hash(self):
        assert '77d3b7ed9db7d236b9eac8262d27f6a5' == Hashing.calc_vbulletin_post_3_8_5_hash('123456', '123')

    def test_bcrypt_hash(self):
        assert '$2a$12$2bULeXwv2H34SXkT1giCZeJW7A6Q0Yfas09wOCxoIC44fDTYq44Mm' \
               == Hashing.calc_bcrypt_hash('12345', '$2a$12$2bULeXwv2H34SXkT1giCZe')

    def test_crc32_hash(self):
        assert '901924565' == Hashing.calc_crc32_hash('password')

    def test_get_phpbb3_hash(self):
        assert '$H$993WP3hbzy0N22X06wxrCc3800D2p41' == Hashing.calc_phpbb3_hash('123456789', '$H$993WP3hbz')

    def test_custom_algorithm_1_hash(self):
        assert 'cee66db36504915f48b2d545803a4494bb1b76b6e9d8ba8c0e6083ff9b281abdef31f6172548fdcde4000e903c5a98a1178c414f7dbf44cffc001aee8e1fe206' \
               == Hashing.calc_custom_algorithm_1_hash('123456', '00new00')

    def test_custom_algorithm_2_hash(self):
        assert '579d9ec9d0c3d687aaa91289ac2854e4' == Hashing.calc_custom_algorithm_2_hash('123456', '123')

    def test_sha_512_unsalted_hash(self):
        assert 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff' \
               == Hashing.calc_sha512_unsalted_hash('test')

    def test_custom_algorithm_3_hash(self):
        assert 'abe45d28281cfa2a4201c9b90a143095' == Hashing.calc_custom_algorithm_3_hash('test', '123')

    def test_md5crypt_hash(self):
        assert '$1$4d3c09ea$hPwyka2ToWFbLTOq.yFjf.' == Hashing.calc_md5crypt_hash('123456', '4d3c09ea')

    def test_custom_algorithm_4_hash(self):
        assert '$2y$12$Yjk3YjIzYWIxNDg0YWMzZOpp/eAMuWCD3UwX1oYgRlC1ci4Al970W' \
               == Hashing.calc_custom_algorithm_4_hash('1234',
                                                       '$2y$12$Yjk3YjIzYWIxNDg0YWMzZOpp/eAMuWCD3UwX1oYgRlC1ci4Al970W')

    def test_custom_algorithm_5_hash(self):
        assert '69e7ade919a318d8ecf6fd540bad9f169bce40df4cae4ac1fb6be2c48c514163' \
               == Hashing.calc_custom_algorithm_5_hash('password', '123456')

    def test_oscommerce_aef_hash(self):
        assert 'd2bc2f8d09990ebe87c809684fd78c66' == Hashing.calc_oscommerce_aef_hash('password', '123')

    def test_descrypt_hash(self):
        assert 'X.OPW8uuoq5N.' == Hashing.calc_descrypt_hash('password', 'X.')

    def test_get_mysql_pre_4_1(self):
        assert '5d2e19393cc5ef67' == Hashing.calc_mysql_pre_4_1('password')

    def test_get_mysql_post_4_1(self):
        assert '*94bdcebe19083ce2a1f959fd02f964c7af4cfc29' == Hashing.calc_mysql_post_4_1('test')

    def test_peoplesoft_hash(self):
        assert '3weP/BR8RHPLP2459h003IgJxyU=' == Hashing.calc_peoplesoft_hash('TESTING')

    def test_punbb_hash(self):
        assert '0c9a0dc3dd0b067c016209fd46749c281879069e' == Hashing.calc_punbb_hash('password', '123')

    def test_sha1_salted_hash(self):
        assert '7288edd0fc3ffcbe93a0cf06e3568e28521687bc' == Hashing.calc_sha1_salted_hash('test', '123')

    def test_partial_md5_20_hash(self):
        assert '5f4dcc3b5aa765d61d83' == Hashing.calc_partial_md5_20_hash('password')

    def test_partial_md5_29_hash(self):
        assert '5f4dcc3b5aa765d61d8327deb882c' == Hashing.calc_partial_md5_29_hash('password')

    def test_ave_datalife_diferior_hash(self):
        assert '696d29e0940a4957748fe3fc9efd22a3' == Hashing.calc_ave_datalife_diferior_hash('password')

    def test_django_md5_hash(self):
        assert 'md5$c6218$346abd81f2d88b4517446316222f4276' == Hashing.calc_django_md5_hash('password', 'c6218')

    def test_django_sha1_hash(self):
        assert 'sha1$c6218$161d1ac8ab38979c5a31cbaba4a67378e7e60845' \
               == Hashing.calc_django_sha1_hash('password', 'c6218')

    def test_pligg_cms_hash(self):
        assert '1230de084f38ace8e3d82597f55cc6ad5d6001568e6' == Hashing.calc_pligg_cms_hash('password', '123')

    def test_run_cms_smf1_1_hash(self):
        assert '0de084f38ace8e3d82597f55cc6ad5d6001568e6' == Hashing.calc_run_cms_smf1_1('password', '123')

    def test_ntlm_hash(self):
        assert '32ed87bdb5fdc5e9cba88547376818d4' == Hashing.calc_ntlm_hash('123456')

    def test_sha1_dash(self):
        assert '55566a759b86fbbd979b579b232f4dd214d08068' \
               == Hashing.calc_sha1dash_hash('123456', '478c8029d5efddc554bf2fe6bb2219d8c897d4a0')

    def test_sha384(self):
        assert '0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454' \
               == Hashing.calc_sha384_hash('123456')

    def test_custom_algorithm_7_hash(self):
        assert 'a753d386613efd6d4a534cec97e73890f8ec960fe6634db6dbfb9b2aab207982'\
               == Hashing.calc_custom_algorithm_7_hash('123456', '123456')

    def test_custom_algorithm_8_hash(self):
        assert '9fc389447b7eb88aff45a1069bf89fbeff89b8fb7d11a6f450583fa4c9c70503' \
               == Hashing.calc_custom_algorithm_8_hash('matthew', 'Dn')

    def test_custom_algorithm_9_hash(self):
        assert '07c691fa8b022b52ac1c44cab3e056b344a7945b6eb9db727e3842b28d94fe18c17fe5b47b1b9a29d8149acbd7b3f73866cc12f0a8a8b7ab4ac9470885e052dc' \
               == Hashing.calc_custom_algorithm_9_hash('0rangepeel', '6kpcxVSjagLgsNCUCr-D')

    def test_sha512crypt_hash(self):
        assert '$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/' \
               == Hashing.calc_sha512crypt_hash('hashcat', '$6$52450745')


class TestCalcArgon2:

    def test_custom_algorithm_10_hash(self):
        assert 'bd17b9d14010a1d4f8c8077f1be1e20b9364d9979bbcf8591337e952cc6037026aa4a2025543d39169022344b4dd1d20f499395533e35705296034bbf7e7d663' \
               == Hashing.calc_custom_algorithm_10_hash(
            'chatbooks', 'NqXCvAHUpAWAco3hVTG5Sg0FfmJRQPKi0LvcHwylzXHhSNuWwvYdMSSGzswi0ZdJ')

    def test_argon2_hash_1(self):
        assert '$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o' \
               == Hashing.calc_argon_2_hash('123456', 'saltysalt')

    def test_argon2_hash_2(self):
        assert '$argon2i$v=19$m=4096,t=2,p=4$c29tZXNhbHQ$ZPidoNOWM3jRl0AD+3mGdZsq+GvHprGL' \
               == Hashing.calc_argon_2_hash('password', '$argon2i$v=19$m=4096,t=2,p=4,l=24$c29tZXNhbHQ')

    def test_argon2_hash_3(self):
        assert '$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o' \
               == Hashing.calc_argon_2_hash('123456', '$argon2d$v=19$m=1024,t=3,p=2,l=20$c2FsdHlzYWx0')

    def test_argon2_hash_4(self):
        assert '$argon2i$v=19$m=1024,t=2,p=2$c29tZXNhbHQ$bBKumUNszaveOgEhcaWl6r6Y91Y' \
               == Hashing.calc_argon_2_hash('password', '$argon2i$v=19$m=1024,t=2,p=2,l=20$c29tZXNhbHQ')

    def test_argon2_hash_5(self):
        assert '$argon2i$v=19$m=4096,t=2,p=4$c29tZXNhbHQ$M2X6yo+ZZ8ROwC7MB6/+1yMhGytTzDczBMgo3Is7ptY' \
               == Hashing.calc_argon_2_hash('password', '$argon2i$v=19$m=4096,t=2,p=4,l=32$c29tZXNhbHQ')

    def test_argon2_hash_6(self):
        assert '$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o' \
               == Hashing.calc_argon_2_hash('123456', '$argon2d$v=19$m=10d4,t=ejw,p=2$c2FsdHlzYWx0')
