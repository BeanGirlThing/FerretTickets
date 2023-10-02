from configparser import ConfigParser
import shortuuid

class InviteCodes:

    @staticmethod
    def create_invite_code(config: ConfigParser):
        return f"{config.get('invite_codes', 'code_prefix')}-{shortuuid.uuid()}"
