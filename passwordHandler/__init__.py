import hashlib
import secrets


class PasswordHandler:
    @staticmethod
    def hash_password(password: str, salt: str = None):
        if salt is None:
            salt = PasswordHandler.gensalt()
        plaintext = password + salt
        sha256_hash = hashlib.sha256(plaintext.encode("utf-8"))
        return sha256_hash.hexdigest(), salt

    @staticmethod
    def gensalt(length: int = 8):
        characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"
        salt = ""
        for i in range(0, length):
            salt = salt + characters[secrets.randbelow(len(characters))]
        return salt

    @staticmethod
    def check_password(password: str, salt: str, hash: str):
        if PasswordHandler.hash_password(password, salt)[0] == hash:
            return True
        else:
            return False
