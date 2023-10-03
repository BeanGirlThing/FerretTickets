import configparser
import os
import sys
import secrets
from functools import wraps

from flask import Flask, redirect, make_response, render_template, request, abort, url_for
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

####
# Application Setup
####

app = Flask("FerretTickets")
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

####
# Decorators
####


def login_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        rule = request.url_rule

        user_id = session_handler.is_valid_session()
        if user_id is None or user_id is False:
            abort(401)

        user_group = dbHandler.get_user_from_ID(user_id)[4]
        user_permissions = dbHandler.get_permission_group_object(user_group)
        allowed_page = get_allowed_page_by_permission(user_permissions)
        username = dbHandler.get_user_from_ID(user_id)[1]

        if allowed_page is None:
            abort(409, username)

        match rule:
            case "/" | "/ticket":
                if not user_permissions.has_permission("READ_TICKETS"):
                    abort(403, allowed_page)
            case "/inviteCodes":
                if not user_permissions.has_permission("READ_CODES"):
                    abort(403, allowed_page)
            case "/usergroups":
                if not user_permissions.has_permission("READ_USERGROUPS"):
                    abort(403, allowed_page)
            case "/users":
                if not user_permissions.has_permission("READ_USERS"):
                    abort(403, allowed_page)

        return f(user_id, user_permissions, username, *args, **kwargs)

    return decorator


####
# Pages
####

@app.route('/login', methods=['POST', 'GET'])
def login():
    login_form = LoginForm()

    user_id = session_handler.is_valid_session()

    if user_id is not False:
        return redirect(url_for("index"))

    if login_form.validate_on_submit():
        username = login_form.username.data
        password = login_form.password.data

        user_data = dbHandler.get_user_from_username(username)

        logger.info(user_data)

        if user_data is not False:
            is_password_valid = PasswordHandler.check_password(password, salt=user_data[3], hash=user_data[2])

            if is_password_valid:
                logger.info(f"Verified user {username}, creating session")
                response = make_response(redirect(url_for("index")))
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

    user_id = session_handler.is_valid_session()

    if user_id is not False:
        return redirect(url_for("index"))

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
            return response, {"Refresh": f"3; url={url_for('login')}"}
        else:
            register_form.password.data = ""
            register_form.confirm_password.data = ""
            response = make_response(render_template("register.html", form=register_form,
                                                     message="Registration failed for an unknown reason, please contact admin"))
            return response

    response = make_response(render_template("register.html", form=register_form, message=""))
    return response


@app.route("/", methods=['POST', 'GET'])
@login_required
def index(user_id, user_permission_group, username):
    table_list = generate_table_list(user_permission_group)
    print(table_list)

    all_tickets = dbHandler.get_all_tickets()
    display_list = []

    create_ticket_button_disabled = "disabled"
    if user_permission_group.has_permission("CREATE_TICKETS"):
        create_ticket_button_disabled = ""

    create_ticket_button = render_template("elements/function-button.html",
                                           href=url_for("create_ticket"),
                                           title="Create Ticket",
                                           disabled=create_ticket_button_disabled
                                           )

    for ticket in all_tickets:
        pretty_ticket_state, ticket_state_background_colour = get_pretty_ticket_state(ticket[4])
        ticket_creator = dbHandler.get_username_from_id(ticket[1])[0]
        display_list.append(render_template("elements/ticket-accordion.html",
                                            ticket_id=ticket[0],
                                            ticket_title=ticket[2],
                                            ticket_description=ticket[3],
                                            ticket_creator=ticket_creator,
                                            ticket_state=pretty_ticket_state,
                                            badge_background_colour=ticket_state_background_colour
                                            ))

    response = make_response(render_template("main.html",
                                             items_list=display_list,
                                             table_list=table_list,
                                             function_buttons_list=[create_ticket_button],
                                             username=username))
    return response


@app.route("/ticket", methods=['POST', 'GET'])
@login_required
def ticket_details(user_id, user_permission_group, username):
    query_parameters = request.args.to_dict()

    update_ticket_form = UpdateTicketForm()

    update_disabled = ""
    delete_disabled = ""
    status_disabled = ""

    if "t" not in query_parameters:
        return redirect(url_for("index"))

    ticket = dbHandler.get_ticket(int(query_parameters["t"]))
    ticket_creator = ticket[1]

    if not user_permission_group.has_permission("UPDATE_TICKETS"):
        update_disabled = "disabled"
    if not user_permission_group.has_permission("DELETE_TICKETS"):
        delete_disabled = "disabled"
    if not user_permission_group.has_permission("RESOLVE_OTHERS_TICKETS"):
        if user_permission_group.has_permission("RESOLVE_OWN_TICKETS"):
            if not user_id == ticket_creator:
                status_disabled = "disabled"
        else:
            status_disabled = "disabled"

    ticket_creator = dbHandler.get_username_from_id(ticket[1])[0]
    pretty_ticket_name, ticket_badge_background_colour = get_pretty_ticket_state(ticket[4])

    if query_parameters.get("deleteticket"):
        if not user_permission_group.has_permission("DELETE_TICKETS"):
            return make_response(render_template("permission-failed.html", username=username)), {
                "Refresh": f"3; url={url_for('index')}"}
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
        return response, {"Refresh": f"3; url={url_for('index')}"}

    if update_ticket_form.validate_on_submit():
        dbHandler.update_ticket(ticket[0], update_ticket_form.title.data, update_ticket_form.description.data)
        response = make_response(
            render_template("update-ticket.html", form=update_ticket_form, message="Updated, Redirecting...",
                            username=username))
        return response, {"Refresh": f"3; url={url_for('ticket_details', t=ticket[0])}"}

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
            if not user_permission_group.has_permission("UPDATE_TICKETS"):
                return make_response(render_template("permission-failed.html", username=username))
            update_ticket_form.title.data = ticket[2]
            update_ticket_form.description.data = ticket[3]
            response = make_response(render_template("update-ticket.html", username=username, form=update_ticket_form))
            return response
        if query_parameters.get("updatestatus"):
            valid_ticket_states = ["backlog", "indev", "done"]
            can_resolve = True
            if not user_permission_group.has_permission("RESOLVE_OTHERS_TICKETS"):
                if user_permission_group.has_permission("RESOLVE_OWN_TICKETS"):
                    if not user_id == ticket_creator:
                        can_resolve = False
                else:
                    can_resolve = False

            if can_resolve:
                if not query_parameters.get("updatestatus") in valid_ticket_states:
                    response = make_response(render_template("invalid-operation.html", username=username))
                    return response, {"Refresh": f"3; url={url_for('index')}"}
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
                return response, {"Refresh": f"3; url={url_for('ticket_details', t=ticket[0])}"}
            else:
                response = make_response(render_template("permission-failed.html", username=username))
                return response, {"Refresh": f"3; url={url_for('index')}"}


@app.route("/createticket", methods=['POST', 'GET'])
@login_required
def create_ticket(user_id, user_permission_group, username):
    create_ticket_form = CreateTicketForm()

    if not user_permission_group.has_permission("CREATE_TICKETS"):
        response = make_response(
            render_template("permission-failed.html", username=username))
        return response, {"Refresh": f"3; url={url_for('index')}"}

    if create_ticket_form.validate_on_submit():
        dbHandler.create_ticket(user_id,
                                create_ticket_form.title.data,
                                create_ticket_form.description.data,
                                create_ticket_form.state.data
                                )
        response = make_response(render_template("create-ticket.html", form=create_ticket_form,
                                                 message="Ticket created successfully, redirecting..."))
        return response, {"Refresh": f"3; url={url_for('index')}"}

    response = make_response(render_template("create-ticket.html", form=create_ticket_form, message=""))
    return response


@app.route("/inviteCodes", methods=['POST', 'GET'])
@login_required
def invite_codes(user_id, user_permission_group, username):
    table_list = generate_table_list(user_permission_group)

    create_invite_code_button_disabled = "disabled"
    if user_permission_group.has_permission("CREATE_CODES"):
        create_invite_code_button_disabled = ""

    create_invite_button = [
        render_template("elements/function-button.html",
                        href=url_for("new_invite_code"),
                        title="Create New Invite Code",
                        disabled=create_invite_code_button_disabled
                        )
    ]

    response = make_response(render_template("main.html",
                                             items_list="Hello World",
                                             table_list=table_list,
                                             function_buttons_list=create_invite_button,
                                             username=username))
    return response


@app.route("/createCode")
@login_required
def new_invite_code(user_id, user_permission_group, username):
    return "Hello world"


@app.route("/usergroups", methods=['POST', 'GET'])
@login_required
def user_groups(user_id, user_permission_group, username):
    table_list = generate_table_list(user_permission_group)

    create_user_group_button_disabled = "disabled"
    if user_permission_group.has_permission("CREATE_CODES"):
        create_user_group_button_disabled = ""

    create_group_button = [
        render_template("elements/function-button.html",
                        href=url_for("new_user_group"),
                        title="Create New UserGroup",
                        disabled=create_user_group_button_disabled
                        )
    ]

    response = make_response(render_template("main.html",
                                             items_list="Hello World",
                                             table_list=table_list,
                                             function_buttons_list=create_group_button,
                                             username=username))
    return response

@app.route("/createGroup")
@login_required
def new_user_group(user_id, user_permission_group, username):
    return "Hello world"


@app.route("/users", methods=['POST', 'GET'])
@login_required
def users(user_id, user_permission_group, username):
    table_list = generate_table_list(user_permission_group)

    # create_user_group_button_disabled = "disabled"
    # if user_permission_group.has_permission("CREATE_CODES"):
    #     create_user_group_button_disabled = ""
    #
    # create_group_button = [
    #     render_template("elements/function-button.html",
    #                     href=url_for("new_user_group"),
    #                     title="Create New UserGroup",
    #                     disabled=create_user_group_button_disabled
    #                     )
    # ]

    response = make_response(render_template("main.html",
                                             items_list="Hello World",
                                             table_list=table_list,
                                             function_buttons_list=[],
                                             username=username))
    return response

@app.route("/logout")
def logout():
    userID = session_handler.check_session_token()
    session_handler.delete_session(userID)

    response = make_response(redirect(url_for("login")))
    response.set_cookie("session_token", "", expires=0)

    return response


####
# Helper Functions
####


def get_allowed_page_by_permission(permission_group: PermissionGroupObject):
    if permission_group.has_permission("READ_TICKETS"):
        return url_for("index")
    if permission_group.has_permission("READ_CODES"):
        return url_for("invite_codes")
    if permission_group.has_permission("READ_USERGROUPS"):
        return url_for("user_groups")
    if permission_group.has_permission("READ_USERS"):
        return url_for("users")
    return None


def generate_table_list(permission_group: PermissionGroupObject):
    visible_tables = []
    if permission_group.has_permission("READ_TICKETS"):
        visible_tables.append(url_for("index"))
    if permission_group.has_permission("READ_CODES"):
        visible_tables.append(url_for("invite_codes"))
    if permission_group.has_permission("READ_USERGROUPS"):
        visible_tables.append(url_for("user_groups"))
    if permission_group.has_permission("READ_USERS"):
        visible_tables.append(url_for("users"))

    pretty_names = dbHandler.return_prettier_table_names()

    current_url = request.url_rule

    rendered_table_items = []
    for table in zip(visible_tables, pretty_names.values()):
        if str(current_url) == table[0]:
            rendered_table_items.append(
                render_template("elements/table-active-item.html", table_name=table[1], destination=table[0]))
        else:
            rendered_table_items.append(
                render_template("elements/table-item.html", table_name=table[1], destination=table[0]))
    return rendered_table_items


def get_pretty_ticket_state(state: str):
    if state == "backlog":
        return "Backlog", "text-bg-secondary"
    if state == "indev":
        return "In Dev", "text-bg-warning"
    if state == "done":
        return "Complete", "text-bg-success"


def get_logfile_absolute_path(path: str = None):
    if path is None:
        path = os.getcwd() + "/logs"
    if not os.path.exists(path):
        os.makedirs(path)
    time_component = slugify(str(datetime.datetime.now().strftime("%m-%d-%Y--%H-%M-%S")))
    return f"{path}/app-{time_component}.log"


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

####
# Error Code Fallbacks
####


@app.errorhandler(401)
def no_token(*args):
    response = make_response(redirect(url_for("login")))
    response.set_cookie("session_token", "", expires=0)
    return response


@app.errorhandler(403)
def permission_failure(code, allowed_page):
    return redirect(allowed_page)


@app.errorhandler(409)
def no_visible_page(code, username):
    response = make_response(render_template("permission-failed.html", username=username))
    return response, {"Refresh": f"3; url={url_for('index')}"}


####
# Application Entrypoint
####

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
