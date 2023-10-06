import json
import logging
from configparser import ConfigParser


class PermissionGroupObject(object):
    GROUP_TITLE = None
    DATABASE_GROUP_ID = None

    PERMISSIONS = None
    PERMISSION_CATEGORIES = ["TICKETS", "INVITECODES", "USERACCOUNTS", "USERGROUPS"]
    PERMISSION_DESCRIPTIONS = None

    logger = None

    def __init__(self, config: ConfigParser, permissions_title: str, permissions_string: str = None):
        self.GROUP_TITLE = permissions_title

        self.logger = logging.getLogger(
            f"{config.get('logger', 'logger_name')}.GroupPermissionObject-for-{self.GROUP_TITLE}")

        with open("permissionsHandler/permissions_description.json") as f:
            self.PERMISSION_DESCRIPTIONS = json.loads(f.read())

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
            if permission in self.PERMISSION_CATEGORIES:
                for permission_key in self.PERMISSIONS[permission].keys():
                    self.PERMISSIONS[permission][permission_key] = True
            else:
                permission_category_location = self.find_permission_category_location(permission)
                if permission_category_location is not False:
                    self.PERMISSIONS[permission_category_location][permission] = True
                else:
                    self.logger.warning(f"{permission} is not a valid permission, skipping")

        self.logger.info("Object created Successfully!")

    def find_permission_category_location(self, permission_name: str) -> bool | str:
        for category in self.PERMISSION_CATEGORIES:
            for key in self.PERMISSIONS[category]:
                if key == permission_name:
                    return category
        return False

    def update_permissions(self, permission_list: dict):
        for permission, value in permission_list.items():
            if permission == "ADMIN":
                self.PERMISSIONS["ADMIN"] = value
                continue
            if permission in self.PERMISSION_CATEGORIES:
                for permission_key in self.PERMISSIONS[permission].keys():
                    self.PERMISSIONS[permission][permission_key] = value
            else:
                category = self.find_permission_category_location(permission)
                if category is not False:
                    self.PERMISSIONS[category][permission] = value
                else:
                    self.logger.warning(f"{permission} is not a valid permission")


    def build_permission_string(self):
        permission_string = ""
        if self.PERMISSIONS["ADMIN"]:
            return "ADMIN"

        for i, category in enumerate(self.PERMISSION_CATEGORIES):
            has_whole_category = True
            category_permission_string = ""
            for permission, value in self.PERMISSIONS[category].items():
                if value:
                    category_permission_string = f"{category_permission_string}{permission},"
                else:
                    has_whole_category = False
            if has_whole_category:
                permission_string = f"{permission_string}{category},"
            else:
                permission_string = f"{permission_string}{category_permission_string}"
        return permission_string

    def has_permission(self, permission_name: str):
        if self.PERMISSIONS["ADMIN"]:
            return True
        category = self.find_permission_category_location(permission_name)
        if category is not False:
            return self.PERMISSIONS[category][permission_name]
        else:
            return False

    def has_permission_category(self, permission_category: str):
        response = True
        for permission in self.PERMISSIONS[permission_category].values():
            if not permission:
                response = False
        return response

    def get_description_by_permission(self, permission_name):
        if permission_name in self.PERMISSION_CATEGORIES:
            return "Permission Category"
        else:
            return self.PERMISSION_DESCRIPTIONS[permission_name]

    def is_administrator(self):
        return self.PERMISSIONS["ADMIN"]






class PermissionsParser:
    @staticmethod
    def get_system_dependant_groups_from_config(config: ConfigParser):
        return [
            PermissionGroupObject(config, config.get("system_groups", "supergroup_name"), "ADMIN"),
            PermissionGroupObject(config, config.get("system_groups", "default_name"), config.get("system_groups", "default_permissions"))
        ]

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
