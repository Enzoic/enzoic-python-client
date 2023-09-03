import hashlib
import hmac
import base64
import re

import argon2
import bcrypt
import zlib
import passlib.hash
import binascii
from enzoic.enums.password_types import PasswordType
from enzoic.exceptions import UnsupportedPasswordType


def base_64_decode(base64_string):
    return base64.b64decode(base64_string + "=" * (-len(base64_string) % 4))


def calc_sha256_unsalted_hash(password: str) -> hex:
    hashed_pw = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return hashed_pw


def calc_sha1_unsalted_hash(password: str) -> hex:
    hashed_pw = hashlib.sha1(password.encode("utf-8")).hexdigest()
    return hashed_pw


def calc_md5_unsalted_hash(password: str) -> hex:
    hashed_pw = hashlib.md5(password.encode("utf-8")).hexdigest()
    return hashed_pw


def calc_ipboard_mybb_hash(password: str, salt: str) -> hex:
    md5_salt = hashlib.md5(salt.encode("utf-8")).hexdigest()
    md5_pw = hashlib.md5(password.encode("utf-8")).hexdigest()
    hashed_pw = hashlib.md5((md5_salt + md5_pw).encode("utf-8")).hexdigest()
    return hashed_pw


def calc_triple_des_hash(password: str, salt: str):
    hashed_pw = passlib.hash.des_crypt.using(salt=salt[:2]).hash(password)
    return hashed_pw


def calc_vbulletin_pre_3_8_5_hash(password: str, salt: str) -> hex:
    hashed_pw = hashlib.md5(
        (hashlib.md5(password.encode("utf-8")).hexdigest() + salt).encode("utf-8")
    ).hexdigest()
    return hashed_pw


def calc_vbulletin_post_3_8_5_hash(password: str, salt: str) -> hex:
    return calc_vbulletin_pre_3_8_5_hash(password, salt)


def calc_bcrypt_hash(password: str, salt: str) -> bcrypt:
    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), salt.encode("utf-8"))
    return hashed_pw.decode()


def calc_crc32_hash(password: str) -> hex:
    hashed_pw = zlib.crc32(password.encode("utf-8"))
    return str(hashed_pw)


def calc_phpbb3_hash(password: str, salt: str) -> hex:
    itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return passlib.hash.phpass.using(
        salt=salt[4:12], rounds=itoa64.index(salt[3]), ident=salt.split("$")[1]
    ).hash(password)


def calc_scrypt_hash(password: str, salt: str):
    """Not currently in use"""
    hashed_pw = passlib.hash.scrypt.using(salt=salt.encode("utf-8")).hash(password)
    return hashed_pw


def calc_custom_algorithm_1_hash(password: str, salt: str) -> hex:
    to_whirlpool = salt + password
    to_sha = password + salt
    # make these byte objects
    sha512_out = hashlib.sha512(to_sha.encode("utf-8")).digest()
    whirlpool_out = hashlib.new("whirlpool")
    whirlpool_out.update(to_whirlpool.encode("utf-8"))
    whirlpool_out = whirlpool_out.digest()
    # xor byte objects
    hashed_pw = bytes(a ^ b for (a, b) in zip(sha512_out, whirlpool_out))
    return hashed_pw.hex()


def calc_custom_algorithm_2_hash(password: str, salt: str) -> hex:
    hashed_pw = hashlib.md5(f"{password}{salt}".encode("utf-8")).hexdigest()
    return hashed_pw


def calc_sha512_unsalted_hash(password: str) -> hex:
    hashed_pw = hashlib.sha512(password.encode("utf-8")).hexdigest()
    return hashed_pw


def calc_custom_algorithm_3_hash(password: str, salt="kikugalanet") -> hex:
    hashed_pw = hashlib.md5(f"{salt}{password}".encode("utf-8")).hexdigest()
    return hashed_pw


def calc_md5crypt_hash(password: str, salt: str) -> passlib.hash.md5_crypt:
    hashed_pw = passlib.hash.md5_crypt.using(salt=salt[:8]).hash(password)
    return hashed_pw


def calc_custom_algorithm_4_hash(password: str, salt: str) -> bcrypt:
    md5_value = hashlib.md5(password.encode("utf-8")).hexdigest()
    hashed_pw = bcrypt.hashpw(md5_value.encode("utf-8"), salt.encode("utf-8"))
    return hashed_pw.decode()


def calc_custom_algorithm_5_hash(password: str, salt: str) -> hex:
    md5_value = hashlib.md5(f"{password}{salt}".encode("utf-8")).hexdigest()
    hashed_pw = hashlib.sha256(md5_value.encode("utf-8")).hexdigest()
    return hashed_pw


def calc_oscommerce_aef_hash(password: str, salt: str) -> hex:
    hashed_pw = hashlib.md5(f"{salt}{password}".encode("utf-8")).hexdigest()
    return hashed_pw


def calc_descrypt_hash(password: str, salt: str):
    hashed_pw = passlib.hash.des_crypt.using(salt=salt[:2]).hash(password)
    return hashed_pw


def calc_mysql_pre_4_1(password: str) -> hex:
    hashed_pw = passlib.hash.mysql323.hash(password)
    return hashed_pw


def calc_mysql_post_4_1(password: str) -> hex:
    hashed_pw = passlib.hash.mysql41.hash(password).lower()
    return hashed_pw


def calc_peoplesoft_hash(password: str) -> hex:
    sha1_hash = hashlib.sha1(password.encode("utf-16-le")).digest()
    hashed_pw = base64.b64encode(sha1_hash).decode()
    return hashed_pw


def calc_punbb_hash(password: str, salt: str) -> hex:
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest()
    hashed_pw = hashlib.sha1(f"{salt}{sha1_hash}".encode("utf-8")).hexdigest()
    return hashed_pw


def calc_sha1_salted_hash(password: str, salt: str) -> hex:
    hashed_pw = hashlib.sha1(f"{password}{salt}".encode("utf-8")).hexdigest()
    return hashed_pw


def calc_partial_md5_20_hash(password: str) -> hex:
    hashed_pw = calc_md5_unsalted_hash(password)[:20]
    return hashed_pw


def calc_partial_md5_29_hash(password: str) -> hex:
    hashed_pw = calc_md5_unsalted_hash(password)[:29]
    return hashed_pw


def calc_ave_datalife_diferior_hash(password: str) -> hex:
    hashed_pw = calc_md5_unsalted_hash(
        calc_md5_unsalted_hash(password)
    )
    return hashed_pw


def calc_django_md5_hash(password: str, salt: str) -> hex:
    hashed_pw = f'md5${salt}${calc_md5_unsalted_hash(f"{salt}{password}")}'
    return hashed_pw


def calc_django_sha1_hash(password: str, salt: str) -> hex:
    hashed_pw = (
        f'sha1${salt}${calc_sha1_unsalted_hash(f"{salt}{password}")}'
    )
    return hashed_pw


def calc_pligg_cms_hash(password: str, salt: str) -> hex:
    hashed_pw = f'{salt}{calc_sha1_unsalted_hash(f"{salt}{password}")}'
    return hashed_pw


def calc_run_cms_smf1_1(password: str, salt: str) -> hex:
    hashed_pw = calc_sha1_unsalted_hash(f"{salt}{password}")
    return hashed_pw


def calc_ntlm_hash(password: str) -> hex:
    hashed_pw = hashlib.new("md4", password.encode("utf-16le")).digest()
    return binascii.hexlify(hashed_pw).decode("utf-8")


def calc_sha1dash_hash(password: str, salt: str) -> hex:
    return calc_sha1_unsalted_hash(f"--{salt}--{password}--")


def calc_sha384_hash(password: str) -> hex:
    return hashlib.sha384(password.encode("utf-8")).hexdigest()


def calc_custom_algorithm_7_hash(password: str, salt: str) -> hex:
    # This key is hardcoded and specific to this algorithm
    byte_key = b"d2e1a4c569e7018cc142e9cce755a964bd9b193d2d31f02d80bb589c959afd7e"
    derived_salt = calc_sha1_unsalted_hash(salt)
    msg = derived_salt.encode("utf-8") + password.encode("utf-8")
    hashed = hmac.new(byte_key, msg, digestmod=hashlib.sha256)
    return hashed.hexdigest()


def calc_custom_algorithm_8_hash(password: str, salt: str) -> hex:
    return calc_sha256_unsalted_hash(salt + password)


def calc_custom_algorithm_9_hash(password: str, salt: str) -> hex:
    result = calc_sha512_unsalted_hash(password + salt)
    for _ in range(11):
        result = calc_sha512_unsalted_hash(result)
    return result


def calc_sha256crypt_hash(password: str, salt: str) -> hex:
    rounds = 5000
    add_back_in = False
    # extract the number of rounds and the salt value
    if "$rounds=" in salt:
        rounds = int(salt.split("=")[1].split("$")[0])
        salt = re.sub(r"\$rounds=\d{1,}", "", salt)
        add_back_in = True

    result = passlib.hash.sha256_crypt.using(salt=salt[3:], rounds=rounds, relaxed=True).hash(password)
    # if rounds was supplied in the salt and is set to 5000 add it back in as the hashing library spec doesn't
    # require this to be present in the hash and removes it
    if add_back_in and rounds == 5000:
        result = f"{result[:3]}rounds={rounds}${result[3:]}"
    return result


def calc_sha512crypt_hash(password: str, salt: str) -> hex:
    rounds = 5000
    add_back_in = False
    # extract the number of rounds and the salt value
    if "$rounds=" in salt:
        rounds = int(salt.split("=")[1].split("$")[0])
        salt = re.sub(r"\$rounds=\d{1,}", "", salt)
        add_back_in = True

    result = passlib.hash.sha512_crypt.using(salt=salt[3:], rounds=rounds, relaxed=True).hash(password)
    # if rounds was supplied in the salt and is set to 5000 add it back in as the hashing library spec doesn't
    # require this to be present in the hash and removes it
    if add_back_in and rounds == 5000:
        result = f"{result[:3]}rounds={rounds}${result[3:]}"
    return result


def calc_custom_algorithm_10_hash(password: str, salt: str) -> hex:
    return calc_sha512_unsalted_hash(password + ":" + salt)


def calc_hmac_sha1_salt_as_key(password: str, salt: str) -> hex:
    hashed = hmac.new(salt.encode("utf-8"), password.encode("utf-8"), hashlib.sha1)
    return hashed.hexdigest()


def calc_auth_me_sha256(password: str, salt: str) -> hex:
    return f"$SHA${salt}${calc_sha256_unsalted_hash(calc_sha256_unsalted_hash(password)+salt)}"


def calc_argon_2_hash(password, salt):
    """Use this for the tests. For calling the api with partial hashes use the calc_argon_2_raw_hash"""
    argon_type = argon2.Type.D
    iterations = 3
    memory_cost = 1024
    parallelism = 2
    hash_length = 20
    just_salt = salt

    # Encode if this comes in as a str
    if isinstance(password, str):
        password = password.encode("utf-8")

    # Check if salt has encoded settings
    if salt.startswith("$argon2"):
        # settings are encoded, use them
        if salt.startswith("$argon2i"):
            argon_type = argon2.Type.I

        salt_components = salt.split("$")
        if len(salt_components) == 5:
            # maker sure b64 encoded salt length is a multiple of 4
            # just_salt = base64.b64decode(salt_components[4] + '=' * (-len(salt_components[4]) % 4)).decode()
            just_salt = base_64_decode(salt_components[4]).decode()
            # loop through and calculate the new params
            salt_params = salt_components[3].split(",")
            for param in salt_params:
                param = param.split("=")
                if param[0] == "t":
                    try:
                        iterations = int(param[1])
                    except:
                        iterations = 3
                elif param[0] == "m":
                    try:
                        memory_cost = int(param[1])
                    except:
                        memory_cost = 1024
                elif param[0] == "p":
                    try:
                        parallelism = int(param[1])
                    except:
                        parallelism = 2
                elif param[0] == "l":
                    try:
                        hash_length = int(param[1])
                    except:
                        hash_length = 20

    # calculate the hash
    argon2_hash = argon2.PasswordHasher(
        time_cost=iterations,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_length,
        type=argon_type,
    ).hash(password=password, salt=just_salt.encode("utf-8"))
    return argon2_hash


def _calc_credential_hash(
    username, password, argon2_salt, hash_type, password_salt
):
    password_hash = calculate_password_hash(
        password_to_hash=password, salt=password_salt, hash_type=hash_type
    )

    if password_hash is not None:
        argon2_hash = calc_argon_2_hash(
            f"{username}${password_hash}", argon2_salt
        )

        just_hash = argon2_hash.split("$")[-1]

        return base_64_decode(just_hash).hex()
    else:
        return


def calculate_password_hash(hash_type: int, password_to_hash: str, salt=""):
    """Pass in a hashtype int and calculate the required password hash"""
    if hash_type == PasswordType.MD5_UNSALTED:
        return calc_md5_unsalted_hash(password_to_hash)

    elif hash_type == PasswordType.SHA1_UNSALTED:
        return calc_sha1_unsalted_hash(password_to_hash)

    elif hash_type == PasswordType.SHA256_UNSALTED:
        return calc_sha256_unsalted_hash(password_to_hash)

    elif hash_type == PasswordType.TripleDES:
        return calc_triple_des_hash(password_to_hash, salt)

    elif hash_type == PasswordType.IPBoard_MyBB:
        return calc_ipboard_mybb_hash(password_to_hash, salt)

    elif hash_type == PasswordType.VBulletinPre3_8_5:
        return calc_vbulletin_pre_3_8_5_hash(password_to_hash, salt)

    elif hash_type == PasswordType.VBulletinPost3_8_5:
        return calc_vbulletin_post_3_8_5_hash(password_to_hash, salt)

    elif hash_type == PasswordType.BCrypt:
        return calc_bcrypt_hash(password_to_hash, salt)

    elif hash_type == PasswordType.CRC32:
        return calc_crc32_hash(password_to_hash)

    elif hash_type == PasswordType.PHPBB3:
        return calc_phpbb3_hash(password_to_hash, salt)

    elif hash_type == PasswordType.CustomAlgorithm1:
        return calc_custom_algorithm_1_hash(password_to_hash, salt)

    # This one can be ignored as we have no SCRYPT breaches in our database
    # as well as there not being any set standard way to compute it
    elif hash_type == PasswordType.SCrypt:
        return calc_scrypt_hash(password_to_hash, salt)

    elif hash_type == PasswordType.CustomAlgorithm2:
        return calc_custom_algorithm_2_hash(password_to_hash, salt)

    elif hash_type == PasswordType.SHA512:
        return calc_sha512_unsalted_hash(password_to_hash)

    elif hash_type == PasswordType.CustomAlgorithm3:
        return calc_custom_algorithm_3_hash(password_to_hash)

    elif hash_type == PasswordType.MD5Crypt:
        return calc_md5crypt_hash(password_to_hash, salt)

    elif hash_type == PasswordType.CustomAlgorithm4:
        return calc_custom_algorithm_4_hash(password_to_hash, salt)

    elif hash_type == PasswordType.CustomAlgorithm5:
        return calc_custom_algorithm_5_hash(password_to_hash, salt)

    elif hash_type == PasswordType.osCommerce_AEF:
        return calc_oscommerce_aef_hash(password_to_hash, salt)

    elif hash_type == PasswordType.DESCrypt:
        return calc_descrypt_hash(password_to_hash, salt)

    elif hash_type == PasswordType.MySQLPre4_1:
        return calc_mysql_pre_4_1(password_to_hash)

    elif hash_type == PasswordType.MySQLPost4_1:
        return calc_mysql_post_4_1(password_to_hash)

    elif hash_type == PasswordType.PeopleSoft:
        return calc_peoplesoft_hash(password_to_hash)

    elif hash_type == PasswordType.PunBB:
        return calc_punbb_hash(password_to_hash, salt)

    elif hash_type == PasswordType.CustomAlgorithm6:
        return calc_sha1_salted_hash(password_to_hash, salt)

    elif hash_type == PasswordType.PartialMD5_20:
        return calc_partial_md5_20_hash(password_to_hash)

    elif hash_type == PasswordType.AVE_DataLife_Diferior:
        return calc_ave_datalife_diferior_hash(password_to_hash)

    elif hash_type == PasswordType.DjangoMD5:
        return calc_django_md5_hash(password_to_hash, salt)

    elif hash_type == PasswordType.DjangoSHA1:
        return calc_django_sha1_hash(password_to_hash, salt)

    elif hash_type == PasswordType.PartialMD5_29:
        return calc_partial_md5_29_hash(password_to_hash)

    elif hash_type == PasswordType.PliggCMS:
        return calc_pligg_cms_hash(password_to_hash, salt)

    elif hash_type == PasswordType.RunCMS_SMF1_1:
        return calc_run_cms_smf1_1(password_to_hash, salt)

    elif hash_type == PasswordType.NTLM:
        return calc_ntlm_hash(password_to_hash)

    elif hash_type == PasswordType.SHA1Dash:
        return calc_sha1dash_hash(password_to_hash, salt)

    elif hash_type == PasswordType.SHA384:
        return calc_sha384_hash(password_to_hash)

    elif hash_type == PasswordType.CustomAlgorithm7:
        return calc_custom_algorithm_7_hash(password_to_hash, salt)

    elif hash_type == PasswordType.CustomAlgorithm8:
        return calc_custom_algorithm_8_hash(password_to_hash, salt)

    elif hash_type == PasswordType.CustomAlgorithm9:
        return calc_custom_algorithm_9_hash(password_to_hash, salt)

    elif hash_type == PasswordType.SHA512Crypt:
        return calc_sha512crypt_hash(password_to_hash, salt)

    elif hash_type == PasswordType.SHA256Crypt:
        return calc_sha256crypt_hash(password_to_hash, salt)

    elif hash_type == PasswordType.HMACSHA1_SaltAsKey:
        return calc_hmac_sha1_salt_as_key(password_to_hash, salt)

    elif hash_type == PasswordType.AuthMeSHA256:
        return calc_auth_me_sha256(password_to_hash, salt)

    elif hash_type == PasswordType.CustomAlgorithm10:
        return calc_custom_algorithm_10_hash(password_to_hash, salt)

    else:
        raise UnsupportedPasswordType
