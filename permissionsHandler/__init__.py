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

    logger = None

    def __init__(self, config: ConfigParser, permissions_title: str, permissions_string: str = None):
        self.GROUP_TITLE = permissions_title

        self.logger = logging.getLogger(f"{config.get('logger', 'logger_name')}.GroupPermissionObject-for-{self.GROUP_TITLE}")

        #  Following are the permissions a UserGroup within the system can have.
        self.PERMISSIONS = {
            "ADMIN": False,  # Administrator (Bypasses all permission checks)

            # Ticket Permissions
            "READ_TICKETS": False,
            "CREATE_TICKETS": False,
            "UPDATE_TICKETS": False,
            "DELETE_TICKETS": False,
            "RESOLVE_OWN_TICKETS": False,
            "RESOLVE_OTHERS_TICKETS": False,

            # Invite Code Permissions
            "READ_CODES": False,
            "CREATE_CODES": False,
            "REVOKE_CODES": False,

            # Users Table Permissions
            "READ_USERS": False,
            "UPDATE_USERS": False,
            "DELETE_USERS": False,

            # Usergroups Table Permissions
            "READ_USERGROUPS": False,
            "CREATE_USERGROUPS": False,
            "UPDATE_USERGROUPS": False,
            "DELETE_USERGROUPS": False
        }

        if permissions_string is None:
            return

        if "ADMIN" in permissions_string:
            self.PERMISSIONS["ADMIN"] = True
            return

        permissions_list = permissions_string.split(",")
        for permission in permissions_list:
            if permission == "":
                continue
            self.PERMISSIONS[permission] = True

    def update_permissions(self, **kwargs: bool):
        """Updates permissions for the permission arguments given
                :Keyword Arguments:
                **Permission Name Literal (bool) : True or False
            """
        for permission, value in kwargs.items():
            if permission in self.PERMISSIONS.keys():
                self.PERMISSIONS[permission] = value
            else:
                raise InvalidPermissionException(f"{permission} is not a valid permission")

    def build_permission_string(self):
        permission_string = ""
        for key, value in self.PERMISSIONS.items():
            if key == "ADMIN" and value:
                return "ADMIN"
            if value:
                permission_string = f"{permission_string}{key},"
        if permission_string[-1] == ",":
            permission_string = permission_string[:-1]
        return permission_string

    def has_permission(self, permission_name: str):
        if self.PERMISSIONS["ADMIN"]:
            return True
        try:
            return self.PERMISSIONS[permission_name]
        except IndexError:
            self.logger.warning(f"Permission {permission_name} not a known permission")
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
        group = PermissionGroupObject(config, database_response[1],database_response[2])
        group.DATABASE_GROUP_ID = database_response[0]

        return group

