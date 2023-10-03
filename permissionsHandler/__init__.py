import json
import logging
from configparser import ConfigParser


class InvalidPermissionException(Exception):
    """Raised when an invalid permission value is provided to permission handler"""
    pass


class PermissionGroupObject(object):
    GROUP_TITLE = None
    DATABASE_GROUP_ID = None

    PERMISSIONS = None
    PERMISSION_TOPICS = []

    logger = None

    def __init__(self, config: ConfigParser, permissions_title: str, permissions_string: str = None):
        self.GROUP_TITLE = permissions_title

        self.logger = logging.getLogger(
            f"{config.get('logger', 'logger_name')}.GroupPermissionObject-for-{self.GROUP_TITLE}")

        #  Following are the permissions a UserGroup within the system can have.
        self.PERMISSIONS = {
            "ADMIN": False,  # Administrator (Bypasses all permission checks)

            # Ticket Permissions
            "TICKETS": {
                "READ_TICKETS": False,
                "CREATE_TICKETS": False,
                "UPDATE_TICKETS": False,
                "DELETE_TICKETS": False,
                "RESOLVE_OWN_TICKETS": False,
                "RESOLVE_OTHERS_TICKETS": False
            },

            # Invite Code Permissions
            "INVITECODES": {
                "READ_CODES": False,
                "CREATE_CODES": False,
                "REVOKE_CODES": False
            },

            # Users Table Permissions
            "USERACCOUNTS": {
                "READ_USERS": False,
                "UPDATE_USERS": False,
                "DELETE_USERS": False
            },

            # Usergroups Table Permissions
            "USERGROUPS": {
                "READ_USERGROUPS": False,
                "CREATE_USERGROUPS": False,
                "UPDATE_USERGROUPS": False,
                "DELETE_USERGROUPS": False
            }
        }

        for permission_topic in self.PERMISSIONS.keys():
            if permission_topic == "ADMIN":
                continue
            else:
                self.PERMISSION_TOPICS.append(permission_topic)

        if permissions_string is None:
            return

        permissions_list = permissions_string.split(",")
        if "ADMIN" in permissions_list:
            self.logger.info("is Administrator, finishing group object creation")
            self.PERMISSIONS["ADMIN"] = True
            return

        for permission in permissions_list:
            if permission == "":
                continue
            if permission in self.PERMISSION_TOPICS:
                for permission_key in self.PERMISSIONS[permission].keys():
                    self.PERMISSIONS[permission][permission_key] = True
            else:
                topic = self.find_permission_topic_location(permission)
                if topic is not False:
                    self.PERMISSIONS[topic][permission] = True
                else:
                    self.logger.warning(f"{permission} is not a valid permission, skipping")

        self.logger.info("Object created Successfully!")

    def find_permission_topic_location(self, permission_name: str):
        for topic in self.PERMISSION_TOPICS:
            for key in self.PERMISSIONS[topic]:
                if key == permission_name:
                    return topic
        return False

    def update_permissions(self, **kwargs: bool):
        """Updates permissions for the permission arguments given
                :Keyword Arguments:
                **Permission Name Literal (bool) : True or False
            """
        for permission, value in kwargs.items():
            if permission == "ADMIN":
                self.PERMISSIONS["ADMIN"] = value
                continue
            if permission in self.PERMISSION_TOPICS:
                for permission_key in self.PERMISSIONS[permission].keys():
                    self.PERMISSIONS[permission][permission_key] = value
            else:
                topic = self.find_permission_topic_location(permission)
                if topic is False:
                    self.logger.warning(f"{permission} is not a valid permission")
                else:
                    self.PERMISSIONS[topic][permission] = value

    def build_permission_string(self):
        permission_string = ""
        if self.PERMISSIONS["ADMIN"]:
            return "ADMIN"

        for topic in self.PERMISSION_TOPICS:
            has_whole_topic = True
            topic_permission_string = ""
            for permission, value in self.PERMISSIONS[topic].items():
                if value:
                    topic_permission_string = f"{topic_permission_string}{permission},"
                else:
                    has_whole_topic = False
            if has_whole_topic:
                permission_string = f"{permission_string}{topic},"
            else:
                permission_string = f"{permission_string}{topic_permission_string}"

    def has_permission(self, permission_name: str):
        if self.PERMISSIONS["ADMIN"]:
            return True
        topic = self.find_permission_topic_location(permission_name)
        if topic is not False:
            return self.PERMISSIONS[topic][permission_name]
        else:
            return False


class PermissionsParser:
    @staticmethod
    def get_default_groups_from_file(config: ConfigParser):
        with open("permissionsHandler/default_groups.json", "r") as f:
            default_permissions = json.loads(f.read())

        permissionGroups = []
        for group in default_permissions["groups"]:
            tmp_group = PermissionGroupObject(config, group["name"], group["permissions"])
            permissionGroups.append(tmp_group)

        return permissionGroups

    @staticmethod
    def get_group_object_from_sql_response(config: ConfigParser, database_response: tuple):
        group = PermissionGroupObject(config, database_response[1], database_response[2])
        group.DATABASE_GROUP_ID = database_response[0]

        return group
