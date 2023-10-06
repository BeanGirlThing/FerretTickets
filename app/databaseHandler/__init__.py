import logging
import os
import sqlite3
from configparser import ConfigParser
import json
from pypika import Table, SQLLiteQuery

from passwordHandler import PasswordHandler
from permissionsHandler import PermissionGroupObject, PermissionsParser
from inviteCodeHandler import InviteCodes


class DatabaseHandler(object):
    # Paths for file access
    databasePath = None
    modulePath = None

    newDatabase = True

    # config.ini file passed into this object from the importer
    config = None

    # Python logging.Logger object connected to the importers logger
    logger = None

    # Database Connection and Cursor for executing queries
    connection = None
    cursor = None

    # Pypika Table objects
    userGroupsTable = None
    usersTable = None
    ticketsTable = None
    inviteCodesTable = None

    SUPERUSER_GROUP_ID = None
    SUPERUSER_USER_ID = None
    SUPERUSER_USERNAME = None

    # Dict object containing lists of stored static queries in the ./staticQueries folder, derived from ./staticQueries/index.json
    staticQueriesJsonFile = None


    def __init__(self, config: ConfigParser):
        self.config = config
        self.logger = logging.getLogger(f"{config.get('logger', 'logger_name')}.DatabaseHandler")

        self.logger.info("Setting up DatabaseHandler...")

        self.modulePath = f"{os.getcwd()}/databaseHandler"

        self.databasePath = config.get("database", "path")
        if self.databasePath.upper() == "DEFAULT":
            self.databasePath = None

        if self.databasePath is None:
            self.databasePath = f"{os.getcwd()}/database"
            self.logger.info(f"No database path provided using relative path: {self.databasePath}")

        if not os.path.exists(self.databasePath):
            os.mkdir(self.databasePath)

        self.databasePath = f"{self.databasePath}/data.db"

        if os.path.isfile(self.databasePath):
            self.newDatabase = False

        try:
            with open(f"{self.modulePath}/staticQueries/index.json", "r") as queriesFile:
                queriesFileRead = queriesFile.read()
        except FileNotFoundError as e:
            self.logger.critical("Could not find Static Query index.json", exc_info=True)
            raise e
        except PermissionError as e:
            self.logger.critical("Could not access Static Query index.json", exc_info=True)
            raise e

        try:
            self.staticQueriesJsonFile = json.loads(queriesFileRead)
        except json.decoder.JSONDecodeError as e:
            self.logger.critical("JSON Failed to parse Static Query index.json", exc_info=True)
            raise e
        self.logger.info("Successfully set up DatabaseHandler")

    def no_resource_manager_entry(self):
        self.logger.warning("No resource manager (python `with`) used to run DatabaseHandler, ensure it is closed before exiting")
        self.logger.info(f"Connecting to the database at {self.databasePath}")
        try:
            self.connection = sqlite3.connect(self.databasePath, check_same_thread=False)
        except sqlite3.Error as e:
            self.logger.critical(f"Database connection failed with {e}", exc_info=True)
            raise e
        self.logger.info(f"Successfully opened database connection to {self.databasePath}")
        self.cursor = self.connection.cursor()

        self.userGroupsTable = Table("usergroups")
        self.usersTable = Table("users")
        self.ticketsTable = Table("tickets")
        self.inviteCodesTable = Table("inviteCodes")

        if self.newDatabase:
            self.logger.info("Database detected as new, setting up")
            self.setup_new_database()
            self.commit_to_database()
            self.logger.info("New Database setup complete")
        else:
            self.logger.info("Database already exists, skipping table setup")
            self.set_superuser_consts()

        return self

    def no_resource_manager_exit(self):
        self.logger.info(f"Closing database connection to {self.databasePath}...")
        self.connection.close()
        self.logger.info("Database connection closed")

    def __enter__(self):
        self.logger.info(f"Connecting to the database at {self.databasePath}")
        try:
            self.connection = sqlite3.connect(self.databasePath, check_same_thread=False)
        except sqlite3.Error as e:
            self.logger.critical(f"Database connection failed with {e}", exc_info=True)
            raise e
        self.logger.info(f"Successfully opened database connection to {self.databasePath}")
        self.cursor = self.connection.cursor()

        self.userGroupsTable = Table("usergroups")
        self.usersTable = Table("users")
        self.ticketsTable = Table("tickets")
        self.inviteCodesTable = Table("inviteCodes")

        if self.newDatabase:
            self.logger.info("Database detected as new, setting up")
            self.setup_new_database()
            self.commit_to_database()
            self.logger.info("New Database setup complete")
        else:
            self.logger.info("Database already exists, skipping table setup")
            self.set_superuser_consts()

        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.logger.info(f"Closing database connection to {self.databasePath}...")
        self.connection.close()
        self.logger.info("Database connection closed")

    def setup_new_database(self):
        self.logger.debug("Creating default tables")

        for fileName in self.staticQueriesJsonFile["createTables"]:
            try:
                with open(f"{self.modulePath}/staticQueries/{fileName}", "r") as SQLQuery:
                    self.cursor.execute(SQLQuery.read())
            except (FileNotFoundError, PermissionError) as e:
                self.logger.critical(f"Failed to open {fileName}", exc_info=True)
                raise e
            except sqlite3.OperationalError as e:
                self.logger.critical(f"Failed to execute query from {fileName}", exc_info=True)
                raise e

        self.commit_to_database()

        self.logger.debug("Default Tables created")

        self.logger.debug("Creating system dependant UserGroups")

        system_groups = PermissionsParser.get_system_dependant_groups_from_config(self.config)
        for group in system_groups:
            self.create_usergroup(group)

        self.logger.debug("Successfully created system dependant UserGroups")

        self.logger.debug("Creating default UserGroups")

        default_groups = PermissionsParser.get_default_groups_from_file(self.config)

        for group in default_groups:
            self.create_usergroup(group)

        self.logger.debug("Successfully created default UserGroups")

        self.logger.debug("Inserting Superuser into Users")

        supergroup_group_id = self.get_usergroup_id_by_name(self.config.get("system_groups", "supergroup_name"))

        self.logger.debug(f"Superuser group ID is {str(supergroup_group_id)}")

        superuser_hashed_password, superuser_salt = PasswordHandler.hash_password(
            self.config.get("superuser", "password"))
        create_superuser = SQLLiteQuery.into(self.usersTable) \
            .columns("username", "password", "salt", "usergroup") \
            .insert(
            self.config.get("superuser", "username"),
            superuser_hashed_password,
            superuser_salt,
            supergroup_group_id
        )
        self.execute_query(create_superuser.get_sql())

        self.set_superuser_consts()

        self.commit_to_database()
        self.logger.debug("Successfully inserted Superuser into Users Table")

        default_invite_codes = self.config.getint("invite_codes", "initial_creation")
        self.logger.info(f"Creating {str(default_invite_codes)} invite codes")

        for i in range(0, default_invite_codes):
            self.create_invite_code(self.SUPERUSER_USER_ID)

        if self.config.getboolean("demo_mode", "create_demo_data"):
            self.create_demo_usergroups()
            self.create_demo_users()
            self.create_demo_tickets()


    def create_usergroup(self, group: PermissionGroupObject):
        group_creation_query = SQLLiteQuery.into(self.userGroupsTable) \
            .columns("group_title", "permissions") \
            .insert(
            group.GROUP_TITLE,
            group.build_permission_string()
        )
        self.execute_query(group_creation_query.get_sql())
        self.commit_to_database()

    def update_usergroup(self, group: PermissionGroupObject):
        group_creation_query = SQLLiteQuery.update(self.userGroupsTable) \
            .set("permissions", group.build_permission_string()) \
            .where(self.userGroupsTable.ID == group.DATABASE_GROUP_ID)
        print(group_creation_query.get_sql())
        self.execute_query(group_creation_query.get_sql())
        self.commit_to_database()

    def create_demo_tickets(self):
        with open("demo_data/demo_tickets.json", "r") as f:
            demo_tickets = json.loads(f.read())

        for ticket in demo_tickets["tickets"]:
            self.create_ticket(
                ticket["creator"],
                ticket["title"],
                ticket["description"],
                ticket["state"]
            )

    def create_demo_usergroups(self):
        with open("demo_data/demo_groups.json", "r") as f:
            demo_groups = json.loads(f.read())

        for group in demo_groups["groups"]:
            self.create_usergroup(PermissionGroupObject(self.config, group["name"], group["permissions"]))

    def create_demo_users(self):
        with open("demo_data/demo_users.json", "r") as f:
            demo_users = json.loads(f.read())

        for user in demo_users["users"]:
            password_hash, salt = PasswordHandler.hash_password(user["password"], PasswordHandler.gensalt())
            self.register_new_user(user["username"], password_hash, salt)
            user_id = self.get_user_id_by_name(user["username"])
            group_id = self.get_usergroup_id_by_name(user["usergroup"])
            self.set_user_usergroup(user_id, group_id)


    def create_ticket(self, creator: int, title: str, description: str, state: str):
        create_ticket_query = SQLLiteQuery.into(self.ticketsTable) \
            .columns("Creator", "Title", "Description", "State") \
            .insert(creator, title, description, state)
        self.cursor.execute(create_ticket_query.get_sql())
        self.commit_to_database()

    def get_all_tickets(self):
        get_tickets_query = SQLLiteQuery.from_(self.ticketsTable) \
            .select("ID", "creator", "title", "description", "state")

        self.execute_query(get_tickets_query.get_sql())

        return self.cursor.fetchall()

    def get_all_invite_codes(self):
        get_invites_query = SQLLiteQuery.from_(self.inviteCodesTable) \
            .select("ID", "code", "creator", "revoked", "used_by")

        self.execute_query(get_invites_query.get_sql())

        return self.cursor.fetchall()

    def set_user_usergroup(self, user: int, usergroup: int):
        set_user_usergroup_query = SQLLiteQuery.update(self.usersTable) \
            .set(self.usersTable.usergroup, usergroup) \
            .where(self.usersTable.ID == user)

        self.execute_query(set_user_usergroup_query.get_sql())
        self.commit_to_database()

    def delete_usergroup(self, group_id: int):
        delete_group_query = SQLLiteQuery.from_(self.userGroupsTable) \
            .where(self.userGroupsTable.ID == group_id) \
            .delete()
        self.execute_query(delete_group_query.get_sql())
        self.commit_to_database()

    def delete_user(self, user_id:int):
        delete_user_query = SQLLiteQuery.from_(self.usersTable) \
            .where(self.usersTable.ID == user_id) \
            .delete()
        self.execute_query(delete_user_query.get_sql())
        self.commit_to_database()

    def get_all_user_groups(self):
        get_usergroups_query = SQLLiteQuery.from_(self.userGroupsTable) \
            .select("ID", "group_title", "permissions")
        self.execute_query(get_usergroups_query.get_sql())

        return self.cursor.fetchall()

    def get_usergroup_by_id(self, usergroup_id: int):
        get_usergroup_query = SQLLiteQuery.from_(self.userGroupsTable) \
            .select("ID", "group_title", "permissions") \
            .where(self.userGroupsTable.ID == usergroup_id)
        self.execute_query(get_usergroup_query.get_sql())

        return self.cursor.fetchone()

    def get_all_users(self):
        get_users_query = SQLLiteQuery.from_(self.usersTable) \
            .select("ID", "username", "usergroup")
        self.execute_query(get_users_query.get_sql())

        return self.cursor.fetchall()

    def get_ticket(self, ticket_id: int):
        get_tickets_query = SQLLiteQuery.from_(self.ticketsTable) \
            .select("ID", "creator", "title", "description", "state") \
            .where(self.ticketsTable.ID == ticket_id)

        self.execute_query(get_tickets_query.get_sql())

        return self.cursor.fetchone()

    def delete_ticket(self, ticket_id: int):
        delete_ticket_query = SQLLiteQuery.from_(self.ticketsTable) \
            .where(self.ticketsTable.ID == ticket_id) \
            .delete()

        self.execute_query(delete_ticket_query.get_sql())
        self.commit_to_database()

    def update_ticket(self, ticket_id: int, title: str, description: str):
        update_title_query = SQLLiteQuery.update(self.ticketsTable) \
            .set(self.ticketsTable.Title, title) \
            .where(self.ticketsTable.ID == ticket_id)
        update_desc_query = SQLLiteQuery.update(self.ticketsTable) \
            .set(self.ticketsTable.description, description) \
            .where(self.ticketsTable.ID == ticket_id)

        self.execute_query(update_title_query.get_sql())
        self.execute_query(update_desc_query.get_sql())
        self.commit_to_database()

    def update_ticket_status(self, ticket_id: int, status: str):
        update_ticket_status_query = SQLLiteQuery.update(self.ticketsTable) \
            .set(self.ticketsTable.State, status) \
            .where(self.ticketsTable.ID == ticket_id)
        self.execute_query(update_ticket_status_query.get_sql())

        self.commit_to_database()

    def set_superuser_consts(self):
        self.SUPERUSER_USERNAME = self.config.get("superuser", "username")
        self.SUPERUSER_USER_ID = self.get_user_id_by_name(self.SUPERUSER_USERNAME)
        self.SUPERUSER_GROUP_ID = self.get_usergroup_id_by_name("superuser")

    def execute_query(self, sql: str):
        # self.logger.debug(f"Executing query: {sql}")
        self.cursor.execute(sql)

    def commit_to_database(self):
        self.logger.debug("Committing changes to database")
        self.connection.commit()

    def get_username_from_id(self, user_id: int):
        username_lookup = SQLLiteQuery.from_(self.usersTable) \
            .select("username") \
            .where(self.usersTable.ID == user_id)
        self.execute_query(username_lookup.get_sql())
        return self.cursor.fetchone()

    def get_user_from_username(self, username: str):
        userdata_lookup = SQLLiteQuery.from_(self.usersTable) \
            .select("*") \
            .where(self.usersTable.username == username)

        self.execute_query(userdata_lookup.get_sql())

        response = self.cursor.fetchall()

        if len(response) > 1:
            self.logger.critical(f"Username {username} is duplicated in the users table")
            raise ValueError

        return response[0] if len(response) != 0 else False

    def get_user_from_ID(self, user_id: int):
        id_lookup = SQLLiteQuery.from_(self.usersTable) \
            .select("*") \
            .where(self.usersTable.ID == user_id)

        self.execute_query(id_lookup.get_sql())

        response = self.cursor.fetchone()

        if response is None:
            return False

        return response if len(response) != 0 else False

    def check_invite_code(self, code: str=None, code_id: int=None):
        if code is not None:
            invite_lookup = SQLLiteQuery.from_(self.inviteCodesTable) \
                .select("*") \
                .where(self.inviteCodesTable.code == code)
        elif code_id is not None:
            invite_lookup = SQLLiteQuery.from_(self.inviteCodesTable) \
                .select("*") \
                .where(self.inviteCodesTable.ID == code_id)
        else:
            raise ValueError

        self.execute_query(invite_lookup.get_sql())

        response = self.cursor.fetchone()

        if response[4] is None and response[3] == 0:
            return True
        else:
            return False

    def consume_invite_code(self, code: str, used_by: str):
        update_invite_code = SQLLiteQuery.update(self.inviteCodesTable) \
            .set(self.inviteCodesTable.used_by, used_by) \
            .where(self.inviteCodesTable.code == code)
        self.execute_query(update_invite_code.get_sql())
        self.commit_to_database()

    def revoke_invite_code(self, code_id: int):
        update_invite_code = SQLLiteQuery.update(self.inviteCodesTable) \
            .set(self.inviteCodesTable.revoked, True) \
            .where(self.inviteCodesTable.ID == code_id)
        self.execute_query(update_invite_code.get_sql())
        self.commit_to_database()

    def update_user_password(self, user_id: str, password_hash: str, salt: str):
        update_password_query = SQLLiteQuery.update(self.usersTable) \
            .set(self.usersTable.password, password_hash) \
            .where(self.usersTable.ID == user_id)

        update_salt_query = SQLLiteQuery.update(self.usersTable) \
            .set(self.usersTable.salt, salt) \
            .where(self.usersTable.ID == user_id)

        self.execute_query(update_password_query.get_sql())
        self.execute_query(update_salt_query.get_sql())

        self.commit_to_database()

    def register_new_user(self, username: str, password_hash: str, salt: str):
        usergroup = self.get_usergroup_id_by_name("default")
        new_user_creation_query = SQLLiteQuery.into(self.usersTable) \
            .columns("username", "password", "salt", "usergroup") \
            .insert(
            username,
            password_hash,
            salt,
            usergroup
        )
        try:
            self.execute_query(new_user_creation_query.get_sql())
            self.commit_to_database()
        except sqlite3.Error as e:
            self.logger.warning(f"Failed to add new user {username} with {e}", exc_info=True)
            return False
        return True

    def get_usergroup_id_by_name(self, usergroup_name: str):
        group_name_query = SQLLiteQuery.from_(self.userGroupsTable) \
            .select("ID") \
            .where(self.userGroupsTable.group_title == usergroup_name)
        self.execute_query(group_name_query.get_sql())

        usergroup_id = self.cursor.fetchone()

        if usergroup_id is None:
            return False
        else:
            return usergroup_id[0]

    def get_user_id_by_name(self, username: str):
        user_id_query = SQLLiteQuery.from_(self.usersTable) \
            .select("ID") \
            .where(self.usersTable.username == username)
        self.execute_query(user_id_query.get_sql())

        user_id = self.cursor.fetchone()
        if user_id is None:
            return False
        else:
            return user_id[0]

    def create_invite_code(self, creator_id: int):
        code = InviteCodes.create_invite_code(self.config)

        new_invite_code_query = SQLLiteQuery.into(self.inviteCodesTable) \
            .columns("code", "creator", "revoked", "used_by") \
            .insert(
            code,
            creator_id,
            False,
            None
        )

        self.execute_query(new_invite_code_query.get_sql())
        self.commit_to_database()

    def get_permission_group_object(self, group_id: int):
        get_group_permission_query = SQLLiteQuery.from_(self.userGroupsTable) \
            .select("group_title", "permissions") \
            .where(self.userGroupsTable.ID == group_id)

        self.execute_query(get_group_permission_query.get_sql())
        permissions = self.cursor.fetchone()

        group = PermissionGroupObject(self.config, permissions[0], permissions[1])
        group.DATABASE_GROUP_ID = group_id

        return group

    def return_prettier_table_names(self) -> dict:
        with open("databaseHandler/staticQueries/index.json", "r") as f:
            index_file = json.loads(f.read())

        return index_file["prettierTablenames"]
