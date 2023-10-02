from configparser import ConfigParser
import logging
import secrets

from flask import request


class SessionHandler(object):
    activeSessions = {}

    config = None

    logger = None

    def __init__(self, config: ConfigParser):
        self.config = config
        self.logger = logging.getLogger(f"{config.get('logger', 'logger_name')}.SessionHandler")

    def new_session(self, user_id: int):
        self.logger.info(f"Generating new session for {str(user_id)}")
        if user_id in list(self.activeSessions.keys()):
            self.logger.warning(
                f"Session already exists for {str(user_id)} revoking old session and providing a new one")
            del self.activeSessions[user_id]

        session_token = secrets.token_urlsafe()
        self.activeSessions[user_id] = session_token

        self.logger.info(f"Successfully created a new session for {str(user_id)} with token {session_token}")

        return session_token

    def delete_session(self, user_id: int):
        self.logger.info(f"Deleting session for {str(user_id)} if session exists")
        if user_id in list(self.activeSessions.keys()):
            del self.activeSessions[user_id]
            self.logger.info(f"Successfully deleted session for {str(user_id)}")
        else:
            self.logger.warning(f"No session exists for {str(user_id)}")

    def check_session_token(self, session_token: str=None):
        if session_token is None:
            session_token = request.cookies.get("session_token")
        self.logger.info(f"Checking for session with token {session_token}")
        if session_token not in list(self.activeSessions.values()):
            self.logger.warning(f"No active session found for {session_token}")
            return False

        active_session_users = list(self.activeSessions.keys())
        active_session_tokens = list(self.activeSessions.values())

        user_id = active_session_users[active_session_tokens.index(session_token)]

        self.logger.info(f"Session found for {session_token} user is {user_id}")

        return user_id

    def is_valid_session(self):
        session_cookie = request.cookies.get("session_token")
        if session_cookie is not None:
            return self.check_session_token(session_cookie)
        else:
            return False


