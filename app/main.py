import atexit
import configparser
import datetime
import logging
import os
import secrets
import sys
from functools import wraps
from collections import namedtuple

from IPy import IP
from django.utils.text import slugify
from flask import Flask, redirect, make_response, render_template, request, abort, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_wtf import CSRFProtect

import permissionsHandler
from databaseHandler import DatabaseHandler
from passwordHandler import PasswordHandler
from permissionsHandler import PermissionGroupObject
from serverForms import LoginForm, RegisterForm, CreateTicketForm, UpdateTicketForm, CreateUserGroupForm, \
    UpdateUserGroupForm, UpdateUserForm
from sessionHandler import SessionHandler

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

system_dependant_users = {}
system_dependant_usergroups = {}


####
# Decorators
####

def permission_required(permissions: list, page_to_redirect_on_failure: str):
    def wrapper(f):
        @wraps(f)
        def decorator(*args, **kwargs):
            user_id = session_handler.is_valid_session()
            user_group = dbHandler.get_user_from_ID(user_id)[4]
            user_permissions = dbHandler.get_permission_group_object(user_group)
            username = dbHandler.get_user_from_ID(user_id)[1]
            for permission in permissions:
                if not user_permissions.has_permission(permission):
                    return make_response(
                        render_template(
                            "permission-failed.html",
                            username=username
                        )
                    ), {"Refresh": f"3; url={url_for(page_to_redirect_on_failure)}"}
            return f(*args, **kwargs)

        return decorator

    return wrapper


def root_page_permission_redirect_fallback(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        user_id = session_handler.is_valid_session()

        user_permission_group_id = dbHandler.get_user_from_ID(user_id)[4]
        user_group = dbHandler.get_permission_group_object(user_permission_group_id)
        allowed_page = get_allowed_page_by_permission(user_group)

        if allowed_page is None:
            return redirect(
                url_for("no_permitted_page")
            )

        if allowed_page != "/":
            return redirect(
                allowed_page
            )

        return f(*args, **kwargs)

    return decorator


def login_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        user_id = session_handler.is_valid_session()
        if user_id is None or user_id is False:
            abort(401)

        user_permission_group_id = dbHandler.get_user_from_ID(user_id)[4]
        print(user_permission_group_id)
        user_group = dbHandler.get_permission_group_object(user_permission_group_id)
        username = dbHandler.get_user_from_ID(user_id)[1]

        return f(user_id, user_group, username, *args, **kwargs)

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
@root_page_permission_redirect_fallback
def index(user_id, user_permission_group, username):
    table_list = generate_table_list(user_permission_group)

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
@permission_required(["READ_TICKETS"], "index")
def ticket_details(user_id, user_permission_group, username):
    query_parameters = request.args.to_dict()

    update_ticket_form = UpdateTicketForm()

    update_disabled = ""
    delete_disabled = ""
    status_disabled = ""

    if "t" not in query_parameters.keys():
        return make_response(
            render_template("invalid-operation.html",
                            username=username)
        ), {"Refresh": f"3; url={url_for('index')}"}

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
@permission_required(["CREATE_TICKETS"], "index")
def create_ticket(user_id, user_permission_group, username):
    create_ticket_form = CreateTicketForm()

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
@permission_required(["READ_CODES"], "index")
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

    invite_codes = dbHandler.get_all_invite_codes()

    revoke_disabled = "disabled"
    if user_permission_group.has_permission("REVOKE_CODES"):
        revoke_disabled = ""

    invite_code_accordians = []
    for code in invite_codes:
        specific_code_revoke_button = revoke_disabled
        badge_text, badge_background = get_pretty_invite_code_state(bool(code[3]), code[4])
        creator_username = dbHandler.get_username_from_id(code[2])[0]
        is_active = dbHandler.check_invite_code(code_id=int(code[0]))
        if not is_active:
            specific_code_revoke_button = "disabled"
        invite_code_accordians.append(
            render_template("elements/invite-code-accordion.html",
                            invite_code_id=code[0],
                            invite_code=code[1],
                            invite_code_creator=creator_username,
                            badge_background_colour=badge_background,
                            invite_code_state=badge_text,
                            revoke_disabled=specific_code_revoke_button,
                            revoke_invite_tooltip="Cannot revoke used code" if not is_active else ""
                            )
        )

    response = make_response(render_template("main.html",
                                             items_list=invite_code_accordians,
                                             table_list=table_list,
                                             function_buttons_list=create_invite_button,
                                             username=username))
    return response


@app.route("/createCode")
@login_required
@permission_required(["CREATE_CODES"], "invite_codes")
def new_invite_code(user_id, user_permission_group, username):
    if user_permission_group.has_permission("CREATE_CODES"):
        dbHandler.create_invite_code(user_id)
        flash("Code successfully created!")
        return redirect(url_for("invite_codes"))
    else:
        return make_response(
            render_template("permission-failed.html", username=username)
        ), {"Refresh": f"3; url={url_for('invite_codes')}"}


@app.route("/revokeCode")
@login_required
@permission_required(["REVOKE_CODES"], "invite_codes")
def revoke_invite_code(user_id, user_permission_group, username):
    if not user_permission_group.has_permission("REVOKE_CODES"):
        return make_response(
            render_template("permission-failed.html", username=username)
        ), {"Refresh": f"3; url={url_for('invite_codes')}"}

    query_parameters = request.args.to_dict()
    if "c" not in query_parameters.keys():
        return make_response(
            render_template("invalid-operation.html", username=username)
        ), {"Refresh": f"3; url={url_for('invite_codes')}"}

    try:
        code_id = int(query_parameters["c"])
    except ValueError:
        return make_response(
            render_template("invalid-operation.html", username=username)
        ), {"Refresh": f"3; url={url_for('invite_codes')}"}

    if not dbHandler.check_invite_code(code_id=code_id):
        return make_response(
            render_template("invalid-operation.html", username=username)
        ), {"Refresh": f"3; url={url_for('invite_codes')}"}

    dbHandler.revoke_invite_code(code_id)
    return redirect(url_for("invite_codes"))


@app.route("/usergroups", methods=['POST', 'GET'])
@login_required
@permission_required(["READ_USERGROUPS"], "index")
def user_groups(user_id, user_permission_group, username):
    table_list = generate_table_list(user_permission_group)

    create_user_group_button_disabled = "disabled"
    if user_permission_group.has_permission("CREATE_USERGROUPS"):
        create_user_group_button_disabled = ""

    create_group_button = [
        render_template("elements/function-button.html",
                        href=url_for("new_user_group"),
                        title="Create New UserGroup",
                        disabled=create_user_group_button_disabled
                        )
    ]

    all_usergroups = dbHandler.get_all_user_groups()
    all_users = dbHandler.get_all_users()
    usergroups_list = []
    for group in all_usergroups:
        usergroups_list.append(permissionsHandler.PermissionsParser.get_group_object_from_sql_response(config, group))

    usergroup_accordion = []
    for group in usergroups_list:

        group_use_count = 0
        group_users_list_item = []
        for user in all_users:
            if user[2] == group.DATABASE_GROUP_ID:
                group_users_list_item.append(
                    render_template("elements/list-display-item.html",
                                    active="",
                                    item_description="",
                                    item_name=user[1]
                                    )
                )
                group_use_count += 1

        administrator_badge_visibility = "invisible"
        if group.is_administrator():
            administrator_badge_visibility = ""

        permission_display_items = {}

        for category in group.PERMISSION_CATEGORIES:
            permission_display_items[category] = []
            for permission, value in group.PERMISSIONS[category].items():
                permission_display_items[category].append(
                    render_template("elements/list-display-item.html",
                                    active="list-group-item-success" if value or group.is_administrator() else "",
                                    item_description=group.get_description_by_permission(permission),
                                    item_name=permission
                                    )
                )

        usergroup_accordion.append(render_template("elements/usergroup-accordion.html",
                                                   usergroup_id=group.DATABASE_GROUP_ID,
                                                   usergroup_name=group.GROUP_TITLE,
                                                   admin_badge_visibility=administrator_badge_visibility,
                                                   used_count=group_use_count,
                                                   ticket_permissions=permission_display_items["TICKETS"],
                                                   invite_permissions=permission_display_items["INVITECODES"],
                                                   account_permissions=permission_display_items["USERACCOUNTS"],
                                                   usergroup_permissions=permission_display_items["USERGROUPS"],
                                                   group_users=group_users_list_item,
                                                   update_usergroup_page=url_for("update_existing_group",
                                                                                 g=group.DATABASE_GROUP_ID),
                                                   update_usergroup_disabled="" if user_permission_group.has_permission(
                                                       "UPDATE_USERGROUPS") and not group.DATABASE_GROUP_ID ==
                                                                                    system_dependant_usergroups[
                                                                                        "supergroup"] else "disabled",
                                                   update_usergroup_tooltip=f"Cannot change permissions on system dependant group {group.GROUP_TITLE}" if group.DATABASE_GROUP_ID ==
                                                                                                                                                          system_dependant_usergroups[
                                                                                                                                                              "supergroup"] else "",
                                                   delete_group_page=url_for("delete_usergroups",
                                                                             g=group.DATABASE_GROUP_ID),
                                                   delete_disabled="disabled" if group.DATABASE_GROUP_ID in system_dependant_usergroups.values() or not user_permission_group.has_permission(
                                                       "DELETE_USERGROUPS") else "",
                                                   delete_usergroup_tooltip=f"Cannot delete system dependant UserGroup" if group.DATABASE_GROUP_ID in system_dependant_usergroups.values() else ""
                                                   )
                                   )

    response = make_response(render_template("main.html",
                                             items_list=usergroup_accordion,
                                             table_list=table_list,
                                             function_buttons_list=create_group_button,
                                             username=username))
    return response


@app.route("/deleteGroup")
@login_required
@permission_required(["DELETE_USERGROUPS"], "user_groups")
def delete_usergroups(user_id, user_permission_group, username):
    logger.info(f"Attempting to delete group {request.args.get('g')}")
    all_usergroups = dbHandler.get_all_user_groups()
    all_users = dbHandler.get_all_users()
    try:
        group_id = int(request.args.get("g"))
    except ValueError:
        logger.warning(f"{request.args.get('g')} Not a valid group ID")
        return make_response(
            render_template(
                "invalid-operation.html",
                username=username
            )
        ), {"Refresh": f"3; url={url_for('user_groups')}"}

    group_to_delete = None
    for group in all_usergroups:
        if group[0] == group_id:
            group_to_delete = group

    if group_to_delete is None:
        logger.warning(f"Group {group_id} is not a valid group")
        return make_response(
            render_template(
                "invalid-operation.html",
                username=username
            )
        ), {"Refresh": f"3; url={url_for('user_groups')}"}

    if group_to_delete[0] in system_dependant_usergroups.values():
        logger.warning(f"Cannot delete system dependant group {group_to_delete[1]}")
        return make_response(
            render_template(
                "invalid-operation.html",
                username=username
            )
        ), {"Refresh": f"3; url={url_for('user_groups')}"}

    users_to_reassign = []
    for user in all_users:
        if user[2] == group_id:
            users_to_reassign.append(user)

    logger.warning(
        f"Usergroup {group_to_delete[1]} is being deleted {len(users_to_reassign)} user(s) are being reassigned to group default")
    for user in users_to_reassign:
        dbHandler.set_user_usergroup(user[0], system_dependant_usergroups["default"])
        logger.info(f"User {user[1]} has been assigned to group default")

    dbHandler.delete_usergroup(group_to_delete[0])
    logger.info(f"Group {group_to_delete[1]} deleted!")

    return redirect(
        url_for("user_groups")
    )


@app.route("/updateGroup", methods=['POST', 'GET'])
@login_required
@permission_required(["UPDATE_USERGROUPS"], "user_groups")
def update_existing_group(user_id, user_permission_group, username):
    permission_tuple = namedtuple("Permission", ["permission_selection_field", "permission_value"])
    try:
        group_id = int(request.args.get("g"))
    except ValueError:
        logger.warning(f"{request.args.get('g')} Not a valid group ID")
        return make_response(
            render_template(
                "invalid-operation.html",
                username=username
            )
        ), {"Refresh": f"3; url={url_for('user_groups')}"}
    group_to_update = permissionsHandler.PermissionsParser.get_group_object_from_sql_response(config,
                                                                                              dbHandler.get_usergroup_by_id(
                                                                                                  group_id))

    data = {
        "permissions": []
    }

    if group_id == system_dependant_usergroups["supergroup"]:
        logger.warning("Cannot change permissions on supergroup!")
        return make_response(
            render_template(
                "invalid-operation.html",
                username=username
            )
        ), {"Refresh": f"3; url={url_for('user_groups')}"}

    if group_to_update.is_administrator():
        data["permissions"].append(permission_tuple("ADMIN", "True"))
    else:
        for category in group_to_update.PERMISSION_CATEGORIES:
            has_whole_category = True
            for value in group_to_update.PERMISSIONS[category].values():
                if value is False:
                    has_whole_category = False
            if has_whole_category:
                data["permissions"].append(permission_tuple(category, str(has_whole_category)))
            else:
                for permission, value in group_to_update.PERMISSIONS[category].items():
                    if value:
                        data["permissions"].append(permission_tuple(permission, str(value)))

    update_usergroup_form = UpdateUserGroupForm(data=data)

    if update_usergroup_form.validate_on_submit():
        if update_usergroup_form.additional_permission_button.data:
            update_usergroup_form.permissions.append_entry()
            return make_response(
                render_template(
                    "update-usergroup.html",
                    form=update_usergroup_form,
                    username=username,
                    group_title=group_to_update.GROUP_TITLE,
                    message="Please fill required data"
                )
            )
        else:
            permission_list = {}
            new_permissions = []
            for i, field in enumerate(update_usergroup_form.permissions.data):
                if field["remove_permission"]:
                    del update_usergroup_form.permissions.entries[i]
                    update_usergroup_form.permissions.last_index -= 1
                    return make_response(
                        render_template(
                            "update-usergroup.html",
                            form=update_usergroup_form,
                            username=username,
                            group_title=group_to_update.GROUP_TITLE,
                            message="Please fill required data"
                        )
                    )
                if field["permission_selection_field"] == "NOTSET":
                    return make_response(
                        render_template(
                            "update-usergroup.html",
                            form=update_usergroup_form,
                            username=username,
                            group_title=group_to_update.GROUP_TITLE,
                            message="Please ensure all permissions are selected"
                        )
                    )
                permission_value = True if field["permission_value"] == "True" else False
                permission_list[field["permission_selection_field"]] = permission_value
                new_permissions.append(permission_tuple(
                    field["permission_selection_field"],
                    True if field["permission_value"] == "True" else False
                ))

            for old_permission_tuple in data["permissions"]:
                found_permission = False
                for new_permission_tuple in new_permissions:
                    if new_permission_tuple.permission_selection_field == old_permission_tuple.permission_selection_field:
                        found_permission = True
                if not found_permission:
                    permission_list[old_permission_tuple.permission_selection_field] = False

            group_to_update.update_permissions(permission_list)
            dbHandler.update_usergroup(group_to_update)

            return make_response(
                render_template(
                    "update-usergroup.html",
                    form=update_usergroup_form,
                    username=username,
                    group_title=group_to_update.GROUP_TITLE,
                    message="Group updated, Redirecting..."
                )
            ), {"Refresh": f"3; url={url_for('user_groups')}"}

    else:
        return make_response(
            render_template(
                "update-usergroup.html",
                form=update_usergroup_form,
                username=username,
                group_title=group_to_update.GROUP_TITLE,
                message="Please fill required data"
            )
        )


@app.route("/createGroup", methods=['POST', 'GET'])
@login_required
@permission_required(["CREATE_USERGROUPS"], "user_groups")
def new_user_group(user_id, user_permission_group, username):
    create_group_form = CreateUserGroupForm()
    all_existing_groups = dbHandler.get_all_user_groups()

    if create_group_form.validate_on_submit():
        if create_group_form.additional_permission_button.data:
            create_group_form.permissions.append_entry()
            return make_response(
                render_template(
                    "create-usergroup.html",
                    form=create_group_form,
                    username=username,
                    message="Please fill required data"
                )
            )
        else:
            for group in all_existing_groups:
                if create_group_form.title.data == group[1]:
                    return make_response(
                        render_template(
                            "create-usergroup.html",
                            form=create_group_form,
                            username=username,
                            message="Group Name cannot be the same as another existing group"
                        )
                    )

            created_group = PermissionGroupObject(config, create_group_form.title.data)
            permission_list = {}
            for i, field in enumerate(create_group_form.permissions.data):
                if field["remove_permission"]:
                    del create_group_form.permissions.entries[i]
                    create_group_form.permissions.last_index -= 1
                    return make_response(
                        render_template(
                            "create-usergroup.html",
                            form=create_group_form,
                            username=username,
                            message="Please fill required data"
                        )
                    )
                if field["permission_selection_field"] == "NOTSET":
                    return make_response(
                        render_template(
                            "create-usergroup.html",
                            form=create_group_form,
                            username=username,
                            message="Please ensure all permissions are selected"
                        )
                    )
                permission_value = True if field["permission_value"] == "True" else False
                permission_list[field["permission_selection_field"]] = permission_value

            created_group.update_permissions(permission_list)
            dbHandler.create_usergroup(created_group)

            return make_response(
                render_template(
                    "create-usergroup.html",
                    form=create_group_form,
                    username=username,
                    message="Group created, Redirecting..."
                )
            ), {"Refresh": f"3; url={url_for('user_groups')}"}

    else:
        return make_response(
            render_template(
                "create-usergroup.html",
                form=create_group_form,
                username=username,
                message="Please fill required data"
            )
        )


@app.route("/users", methods=['POST', 'GET'])
@login_required
@permission_required(["READ_USERS"], "index")
def users(user_id, user_permission_group, username):
    table_list = generate_table_list(user_permission_group)
    all_users = dbHandler.get_all_users()

    users_accordions = []
    for user in all_users:
        user_group_for_account = permissionsHandler.PermissionsParser.get_group_object_from_sql_response(config,
                                                                                                         dbHandler.get_usergroup_by_id(
                                                                                                             user[2]))
        users_accordions.append(
            render_template(
                "elements/user-accordion.html",
                user_id=user[0],
                username=user[1],
                usergroup_name=user_group_for_account.GROUP_TITLE,
                update_user_tooltip=f"Cannot update user data for system dependant user {user[1]}" if user[0] ==
                                                                                                      system_dependant_users[
                                                                                                          "superuser"] else "",
                update_disabled="disabled" if user[0] == system_dependant_users[
                    "superuser"] or not user_permission_group.has_permission("UPDATE_USERS") else "",
                update_user_page=url_for("update_user_account", u=user[0]),
                delete_user_tooltip=f"Cannot delete system dependant user {user[1]}" if user[0] ==
                                                                                        system_dependant_users[
                                                                                            "superuser"] else "",
                delete_disabled="disabled" if user[0] == system_dependant_users[
                    "superuser"] or not user_permission_group.has_permission("DELETE_USERS") else "",
                delete_user_page=url_for("delete_user_account", u=user[0]),
                administrator_badge_visibility="" if user_group_for_account.is_administrator() else "invisible"
            )
        )

    response = make_response(render_template("main.html",
                                             items_list=users_accordions,
                                             table_list=table_list,
                                             function_buttons_list=[],
                                             username=username))
    return response


@app.route("/updateUser", methods=["POST", "GET"])
@login_required
@permission_required(["UPDATE_USERS"], "users")
def update_user_account(user_id, user_permission_group, username):
    all_groups = dbHandler.get_all_user_groups()
    update_user_form = UpdateUserForm()
    try:
        user_to_update_id = int(request.args.get("u"))
    except ValueError:
        logger.warning(f"{request.args.get('g')} Not a valid group ID")
        return make_response(
            render_template(
                "invalid-operation.html",
                username=username
            )
        ), {"Refresh": f"3; url={url_for('users')}"}

    if user_to_update_id == system_dependant_users["superuser"]:
        logger.warning("Cannot delete system dependant usergroup!")
        return make_response(
            render_template(
                "invalid-operation.html",
                username=username
            )
        ), {"Refresh": f"3; url={url_for('users')}"}

    user_to_update_data = dbHandler.get_user_from_ID(user_to_update_id)

    user_group_selection = []
    for group in all_groups:
        if group[0] == user_to_update_data[4]:
            user_group_selection.insert(0, (group[0], group[1]))
        else:
            user_group_selection.append((group[0], group[1]))

    update_user_form.user_group.choices = user_group_selection

    if update_user_form.validate_on_submit():
        user_new_user_group = update_user_form.user_group.data
        dbHandler.set_user_usergroup(user_to_update_id, user_new_user_group)
        return make_response(
            render_template(
                "update-user.html",
                form=update_user_form,
                username=username,
                user_to_update_username=user_to_update_data[1],
                message="User updated, Redirecting..."
            )
        ), {"Refresh": f"3; url={url_for('users')}"}

    return make_response(
        render_template(
            "update-user.html",
            form=update_user_form,
            username=username,
            user_to_update_username=user_to_update_data[1],
            message=""
        )
    ), {"Refresh": f"3; url={url_for('users')}"}


@app.route("/deleteUser", methods=["POST", "GET"])
@login_required
@permission_required(["DELETE_USERS"], "users")
def delete_user_account(user_id, user_permission_group, username):
    try:
        user_to_delete_id = int(request.args.get("u"))
    except ValueError:
        logger.warning(f"{request.args.get('g')} Not a valid group ID")
        return make_response(
            render_template(
                "invalid-operation.html",
                username=username
            )
        ), {"Refresh": f"3; url={url_for('users')}"}

    if user_to_delete_id == system_dependant_users["superuser"]:
        logger.warning("Cannot delete system dependant usergroup!")
        return make_response(
            render_template(
                "invalid-operation.html",
                username=username
            )
        ), {"Refresh": f"3; url={url_for('users')}"}

    dbHandler.delete_user(user_to_delete_id)
    logger.warning(f"User {user_to_delete_id} deleted!")

    return redirect("users")


@app.route("/noPermittedPage")
@login_required
def no_permitted_page(user_id, user_permission_group, username):
    return make_response(
        render_template(
            "permission-failed.html",
            username=username
        )
    )


@app.route("/logout")
@login_required
def logout(user_id, user_permission_group, username):
    session_handler.delete_session(user_id)

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


def get_pretty_invite_code_state(revoked: bool, used_by: str = None):
    if used_by is None:
        if revoked:
            return "Revoked", "text-bg-danger"
        else:
            return "Active", "text-bg-success"
    else:
        return f"Used By: {used_by}", "text-bg-info"


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


#
# @app.errorhandler(403)
# def permission_failure(code, allowed_page):
#     return redirect(allowed_page)
#
#
# @app.errorhandler(409)
# def no_visible_page(code, username):
#     response = make_response(render_template("permission-failed.html", username=username))
#     return response, {"Refresh": f"3; url={url_for('index')}"}


####
# Application Entrypoint
####
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

host_address = config.get("development_webserver", "host_address")
try:
    IP(host_address)
except ValueError:
    logger.warning("Config host_address is not a valid IP address, defaulting to 0.0.0.0")
    host_address = "0.0.0.0"

port = config.get("development_webserver", "port")
try:
    port = int(port)
    if port > 65535 or port <= 0:
        logger.warning("Config port is not within valid port range, defaulting to 5000")
        port = 5000
except ValueError:
    logger.warning("Config port is not a valid integer, defaulting to 5000")
    port = 5000

try:
    debug_mode = config.getboolean("development_webserver", "debug_mode")
except ValueError:
    logger.warning("Config debug_mode is not valid boolean, defaulting to True")
    debug_mode = True

try:
    use_reloader = config.getboolean("development_webserver", "use_reloader")
except ValueError:
    logger.warning("Config use_reloader is not valid boolean, defaulting to True")
    use_reloader = True

session_handler = SessionHandler(config)

# Cleanup function for docker production environment, registered by atexit to ensure it runs when interpreter shuts down
def production_exit_cleanup():
    dbHandler.no_resource_manager_exit()
    logger.info("Successfully shutdown with cleanup!")

if __name__ == '__main__':
    # Only used for development operation, docker production image will import the app instead
    with DatabaseHandler(config) as dbHandler:
        system_dependant_usergroups["supergroup"] = dbHandler.get_usergroup_id_by_name(
            config.get("system_groups", "supergroup_name"))
        system_dependant_usergroups["default"] = dbHandler.get_usergroup_id_by_name(
            config.get("system_groups", "default_name"))

        system_dependant_users["superuser"] = dbHandler.get_user_id_by_name(config.get("superuser", "username"))

        app.run(debug=debug_mode, use_reloader=use_reloader, host=host_address, port=port)
else:
    dbHandler = DatabaseHandler(config)
    dbHandler.no_resource_manager_entry()

    system_dependant_usergroups["supergroup"] = dbHandler.get_usergroup_id_by_name(
        config.get("system_groups", "supergroup_name"))
    system_dependant_usergroups["default"] = dbHandler.get_usergroup_id_by_name(
        config.get("system_groups", "default_name"))

    system_dependant_users["superuser"] = dbHandler.get_user_id_by_name(config.get("superuser", "username"))

    # Register cleanup function
    atexit.register(production_exit_cleanup)
