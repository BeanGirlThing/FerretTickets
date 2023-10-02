import configparser
import os
import sys
import secrets
from functools import wraps

from flask import Flask, redirect, make_response, render_template, request, abort
import logging
import datetime
from django.utils.text import slugify
from IPy import IP

from flask_bootstrap import Bootstrap5

from flask_wtf import CSRFProtect

from databaseHandler import DatabaseHandler
from passwordHandler import PasswordHandler
from sessionHandler import SessionHandler
from permissionsHandler import PermissionGroupObject
from serverForms import LoginForm, RegisterForm, CreateTicketForm, UpdateTicketForm

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(16)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

bootstrap = Bootstrap5(app)
csrf = CSRFProtect(app)

dbHandler = None
config = configparser.ConfigParser()
session_handler = None


# def login_required():
#     def wrapper(f):
#         @wraps(f)
#         def decorator(*args, **kwargs):
#             rule = request.url_rule
#
#             print("Test test")
#
#             user_id = session_handler.is_valid_session()
#             if user_id is None:
#                 print("Aborting 401")
#                 abort(401)
#
#             user_group = dbHandler.get_user_from_ID(user_id)[4]
#             user_permissions = dbHandler.get_permission_group_object(user_group)
#             allowed_page = get_allowed_page_by_permission(user_permissions)
#             username = dbHandler.get_user_from_ID(user_id)[1]
#
#             print(rule)
#
#             return f(user_id, user_permissions, username, *args, **kwargs)
#
#         return decorator
#     return wrapper


@app.route('/login', methods=['POST', 'GET'])
def login():
    login_form = LoginForm()

    userID = session_handler.is_valid_session()

    if userID is not False:
        return redirect("/")

    if login_form.validate_on_submit():
        username = login_form.username.data
        password = login_form.password.data

        user_data = dbHandler.get_user_from_username(username)

        logger.info(user_data)

        if user_data is not False:
            is_password_valid = PasswordHandler.check_password(password, salt=user_data[3], hash=user_data[2])

            if is_password_valid:
                logger.info(f"Verified user {username}, creating session")
                response = make_response(redirect("/"))
                response.set_cookie("session_token", session_handler.new_session(user_id=user_data[0]))
                return response

        login_form.password.data = ""
        response = make_response(
            render_template("login.html", message="Username or Password incorrect", form=login_form)
        )
        response.set_cookie("session_token", "", expires=0)
        return response

    response = make_response(render_template("login.html", form=login_form, message=""))
    response.set_cookie("session_token", "", expires=0)
    return response


@app.route("/register", methods=['POST', 'GET'])
def register():
    register_form = RegisterForm()

    userID = session_handler.is_valid_session()

    if userID is not False:
        return redirect("/")

    if register_form.validate_on_submit():

        if register_form.password.data != register_form.confirm_password.data:
            register_form.password.data = ""
            register_form.confirm_password.data = ""
            response = make_response(
                render_template("register.html", message="Passwords do not match!", form=register_form)
            )
            return response

        if not dbHandler.check_invite_code(register_form.invite_code.data):
            register_form.password.data = ""
            register_form.confirm_password.data = ""
            response = make_response(
                render_template("register.html", message="Invalid Invite Code! It may have already been used",
                                form=register_form)
            )
            return response
        password_hash, salt = PasswordHandler.hash_password(register_form.password.data)
        new_user_successful = dbHandler.register_new_user(
            register_form.username.data,
            password_hash,
            salt
        )
        if new_user_successful:
            dbHandler.consume_invite_code(register_form.invite_code.data, register_form.username.data)
            response = make_response(
                render_template("register.html", form=register_form, message="Registration successful, redirecting..."))
            return response, {"Refresh": "3; url=/login"}
        else:
            register_form.password.data = ""
            register_form.confirm_password.data = ""
            response = make_response(render_template("register.html", form=register_form,
                                                     message="Registration failed for an unknown reason, please contact admin"))
            return response

    response = make_response(render_template("register.html", form=register_form, message=""))
    return response


@app.route("/", methods=['POST', 'GET'])
def index():
    user_id = session_handler.is_valid_session()
    logger.info(user_id)
    if user_id is False:
        return redirect("/login")

    user_group = dbHandler.get_user_from_ID(user_id)[4]
    user_permissions = dbHandler.get_permission_group_object(user_group)
    allowed_page = get_allowed_page_by_permission(user_permissions)
    username = dbHandler.get_user_from_ID(user_id)[1]
    if allowed_page is None:
        response = make_response(render_template("permission-failed.html", username=username))
        return response, {"Refresh": "3; url=/"}
    elif allowed_page != "/":
        return redirect(allowed_page)

    table_list = generate_table_list(user_permissions, "/")

    all_tickets = dbHandler.get_all_tickets()
    display_list = []
    for ticket in all_tickets:
        pretty_ticket_state, ticket_state_background_colour = get_pretty_ticket_state(ticket[4])
        ticket_creator = dbHandler.get_username_from_id(ticket[1])[0]
        display_list.append(render_template("ticket-accordion.html",
                                            ticket_id=ticket[0],
                                            ticket_title=ticket[2],
                                            ticket_description=ticket[3],
                                            ticket_creator=ticket_creator,
                                            ticket_state=pretty_ticket_state,
                                            badge_background_colour=ticket_state_background_colour
                                            ))

    response = make_response(render_template("main.html",
                                             ticket_count=len(display_list),
                                             tickets_list=display_list,
                                             table_count=len(table_list),
                                             table_list=table_list,
                                             username=username))
    return response


@app.route("/ticket", methods=['POST', 'GET'])
def ticket_details():
    query_parameters = request.args.to_dict()

    update_ticket_form = UpdateTicketForm()

    update_disabled = ""
    delete_disabled = ""
    status_disabled = ""

    user_id = session_handler.is_valid_session()
    if user_id is False:
        return redirect("/login")

    if not "t" in query_parameters:
        return redirect("/")

    ticket = dbHandler.get_ticket(int(query_parameters["t"]))
    ticket_creator = ticket[1]

    user_group = dbHandler.get_user_from_ID(user_id)[4]
    user_permissions = dbHandler.get_permission_group_object(user_group)
    if not user_permissions.has_permission("READ_TICKETS"):
        response = make_response(render_template("permission-failed.html"))
        return response, {"Refresh": "3; url=/"}

    if not user_permissions.has_permission("UPDATE_TICKETS"):
        update_disabled = "disabled"
    if not user_permissions.has_permission("DELETE_TICKETS"):
        delete_disabled = "disabled"
    if not user_permissions.has_permission("RESOLVE_OTHERS_TICKETS"):
        if user_permissions.has_permission("RESOLVE_OWN_TICKETS"):
            if not user_id == ticket_creator:
                status_disabled = "disabled"
        else:
            status_disabled = "disabled"

    ticket_creator = dbHandler.get_username_from_id(ticket[1])[0]
    pretty_ticket_name, ticket_badge_background_colour = get_pretty_ticket_state(ticket[4])

    username = dbHandler.get_username_from_id(user_id)[0]

    if query_parameters.get("deleteticket"):
        if not user_permissions.has_permission("DELETE_TICKETS"):
            return make_response(render_template("permission-failed.html", username=username)), {"Refresh": "3; url=/"}
        dbHandler.delete_ticket(ticket[0])
        response = make_response(render_template("ticket-page.html",
                                                 ticket_title=ticket[2],
                                                 ticket_creator=ticket_creator,
                                                 ticket_description=ticket[3],
                                                 ticket_id=ticket[0],
                                                 ticket_state=pretty_ticket_name,
                                                 badge_background_colour=ticket_badge_background_colour,
                                                 update_disabled=update_disabled,
                                                 delete_disabled=delete_disabled,
                                                 status_disabled=status_disabled,
                                                 username=username,
                                                 message="Ticket Deleted, Redirecting..."))
        return response, {"Refresh": f"3; url=/"}

    if update_ticket_form.validate_on_submit():
        dbHandler.update_ticket(ticket[0], update_ticket_form.title.data, update_ticket_form.description.data)
        response = make_response(
            render_template("update-ticket.html", form=update_ticket_form, message="Updated, Redirecting...",
                            username=username))
        return response, {"Refresh": f"3; url=/ticket?t={ticket[0]}"}

    if len(query_parameters) == 1:
        response = make_response(
            render_template(
                "ticket-page.html",
                ticket_title=ticket[2],
                ticket_creator=ticket_creator,
                ticket_description=ticket[3],
                ticket_id=ticket[0],
                ticket_state=pretty_ticket_name,
                badge_background_colour=ticket_badge_background_colour,
                update_disabled=update_disabled,
                delete_disabled=delete_disabled,
                status_disabled=status_disabled,
                username=username
            )
        )
        return response
    else:
        if query_parameters.get("updateticket"):
            if not user_permissions.has_permission("UPDATE_TICKETS"):
                return make_response(render_template("permission-failed.html", username=username))
            update_ticket_form.title.data = ticket[2]
            update_ticket_form.description.data = ticket[3]
            response = make_response(render_template("update-ticket.html", username=username, form=update_ticket_form))
            return response
        if query_parameters.get("updatestatus"):
            valid_ticket_states = ["backlog", "indev", "done"]
            can_resolve = True
            if not user_permissions.has_permission("RESOLVE_OTHERS_TICKETS"):
                if user_permissions.has_permission("RESOLVE_OWN_TICKETS"):
                    if not user_id == ticket_creator:
                        can_resolve = False
                else:
                    can_resolve = False

            if can_resolve:
                if not query_parameters.get("updatestatus") in valid_ticket_states:
                    response = make_response(render_template("invalid-operation.html", username=username))
                    return response, {"Refresh": "3; url=/"}
                dbHandler.update_ticket_status(ticket[0], query_parameters.get("updatestatus"))
                response = make_response(render_template("ticket-page.html",
                                                         ticket_title=ticket[2],
                                                         ticket_creator=ticket_creator,
                                                         ticket_description=ticket[3],
                                                         ticket_id=ticket[0],
                                                         ticket_state=pretty_ticket_name,
                                                         badge_background_colour=ticket_badge_background_colour,
                                                         update_disabled=update_disabled,
                                                         delete_disabled=delete_disabled,
                                                         status_disabled=status_disabled,
                                                         username=username,
                                                         message="Status updated, Redirecting..."))
                return response, {"Refresh": f"3; url=/ticket?t={ticket[0]}"}
            else:
                response = make_response(render_template("permission-failed.html", username=username))
                return response, {"Refresh": "3; url=/"}


@app.route("/createticket", methods=['POST', 'GET'])
def create_ticket():
    create_ticket_form = CreateTicketForm()

    user_id = session_handler.is_valid_session()
    if user_id is False:
        return redirect("/login")

    user_group = dbHandler.get_user_from_ID(user_id)[4]
    user_permissions = dbHandler.get_permission_group_object(user_group)
    if not user_permissions.has_permission("CREATE_TICKETS"):
        response = make_response(
            render_template("permission-failed.html", username=dbHandler.get_username_from_id(user_id)))
        return response, {"Refresh": "3; url=/"}

    if create_ticket_form.validate_on_submit():
        dbHandler.create_ticket(user_id,
                                create_ticket_form.title.data,
                                create_ticket_form.description.data,
                                create_ticket_form.state.data
                                )
        response = make_response(render_template("create-ticket.html", form=create_ticket_form,
                                                 message="Ticket created successfully, redirecting..."))
        return response, {"Refresh": "3; url=/"}

    response = make_response(render_template("create-ticket.html", form=create_ticket_form, message=""))
    return response


@app.route("/inviteCodes", methods=['POST', 'GET'])
def invite_codes():
    user_id = session_handler.is_valid_session()
    if user_id is False:
        return redirect("/login")

    user_group = dbHandler.get_user_from_ID(user_id)[4]
    user_permissions = dbHandler.get_permission_group_object(user_group)

    allowed_page = get_allowed_page_by_permission(user_permissions)
    username = dbHandler.get_user_from_ID(user_id)[1]
    if allowed_page is None:
        response = make_response(render_template("permission-failed.html", username=username))
        return response, {"Refresh": "3; url=/"}
    elif allowed_page != "/inviteCodes":
        return redirect(allowed_page)

    table_list = generate_table_list(user_permissions, "inviteCodes")


@app.before_request
def before_request():
    user_id = session_handler.is_valid_session()
    if user_id is False:
        return redirect("/login")


def get_allowed_page_by_permission(permission_group: PermissionGroupObject):
    if permission_group.has_permission("READ_TICKETS"):
        return "/"
    if permission_group.has_permission("READ_CODES"):
        return "/inviteCodes"
    if permission_group.has_permission("READ_USERGROUPS"):
        return "/usergroups"
    if permission_group.has_permission("READ_USERS"):
        return "/users"
    return None


def generate_table_list(permission_group: PermissionGroupObject, current_page: str):
    visible_tables = []
    if permission_group.has_permission("READ_TICKETS"):
        visible_tables.append("tickets")
    if permission_group.has_permission("READ_CODES"):
        visible_tables.append("inviteCodes")
    if permission_group.has_permission("READ_USERGROUPS"):
        visible_tables.append("usergroups")
    if permission_group.has_permission("READ_USERS"):
        visible_tables.append("users")

    pretty_names = dbHandler.return_prettier_table_names()

    rendered_table_items = []
    for table in zip(visible_tables, pretty_names.values()):
        if current_page == "/" and table[0] == "tickets":
            rendered_table_items.append(render_template("table-active-item.html", table_name=table[1], destination="/"))
        elif current_page == table[0]:
            rendered_table_items.append(
                render_template("table-active-item.html", table_name=table[1], destination=f"/{table[0]}"))
        else:
            rendered_table_items.append(
                render_template("table-item.html", table_name=table[1], destination=f"/{table[0]}"))
    return rendered_table_items


@app.route("/logout")
def logout():
    userID = session_handler.check_session_token()
    session_handler.delete_session(userID)

    response = make_response(redirect("/login"))
    response.set_cookie("session_token", "", expires=0)

    return response


# @app.errorhandler(401)
# def no_token():
#     print("Gaming")
#     response = make_response(redirect("/login"))
#     response.set_cookie("session_token", "", expires=0)
#     return response
#
#
# @app.errorhandler(403)
# def permission_failure():
#     return redirect("/")


def get_pretty_ticket_state(state: str):
    if state == "backlog":
        return "Backlog", "text-bg-secondary"
    if state == "indev":
        return "In Dev", "text-bg-warning"
    if state == "done":
        return "Complete", "text-bg-success"


def get_logfile_absolute_path(path: str = None):
    if path is None:
        path = os.getcwd()
    if not os.path.exists(path):
        os.makedirs(f"{path}/logs")
    time_component = slugify(str(datetime.datetime.now().strftime("%m-%d-%Y--%H-%M-%S")))
    return f"{path}/logs/app-{time_component}.log"


def get_logger_level_from_config():
    try:
        level = int(config.get("logger", "logger_level"))
    except ValueError:
        logger.warning("Error getting logger_level from config. Defaulting to DEBUG")
        return logging.DEBUG

    match level:
        case 0:
            return logging.NOTSET
        case 1:
            return logging.DEBUG
        case 2:
            return logging.INFO
        case 3:
            return logging.WARN
        case 4:
            return logging.ERROR
        case 5:
            return logging.CRITICAL


if __name__ == '__main__':
    config.read("config.ini")

    logger = logging.getLogger(config.get("logger", "logger_name"))
    logger.setLevel(get_logger_level_from_config())

    loggingFileHandler = logging.FileHandler(get_logfile_absolute_path())
    loggingFileHandler.setLevel(get_logger_level_from_config())

    loggingStreamHandler = logging.StreamHandler(sys.stdout)
    loggingStreamHandler.setLevel(get_logger_level_from_config())

    loggingFormatter = logging.Formatter(
        fmt='[%(asctime)s][%(levelname)s][%(name)s] - %(message)s',
        datefmt='%d-%b-%y %H:%M:%S'
    )
    loggingFileHandler.setFormatter(loggingFormatter)
    loggingStreamHandler.setFormatter(loggingFormatter)

    logger.addHandler(loggingFileHandler)
    logger.addHandler(loggingStreamHandler)

    logger.info("Starting up!")

    host_address = config.get("webserver", "host_address")
    try:
        IP(host_address)
    except ValueError:
        logger.warning("Config host_address is not a valid IP address, defaulting to 0.0.0.0")
        host_address = "0.0.0.0"

    port = config.get("webserver", "port")
    try:
        port = int(port)
        if port > 65535 or port <= 0:
            logger.warning("Config port is not within valid port range, defaulting to 5000")
            port = 5000
    except ValueError:
        logger.warning("Config port is not a valid integer, defaulting to 5000")
        port = 5000

    try:
        debug_mode = config.getboolean("webserver", "debug_mode")
    except ValueError:
        logger.warning("Config debug_mode is not valid boolean, defaulting to True")
        debug_mode = True

    try:
        use_reloader = config.getboolean("webserver", "use_reloader")
    except ValueError:
        logger.warning("Config use_reloader is not valid boolean, defaulting to True")
        use_reloader = True

    session_handler = SessionHandler(config)

    with DatabaseHandler(config) as dbHandler:
        app.run(debug=debug_mode, use_reloader=use_reloader, host=host_address, port=port)
