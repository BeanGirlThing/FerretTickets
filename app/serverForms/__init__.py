from flask_wtf import FlaskForm, Form
from wtforms import SubmitField, StringField, PasswordField, TextAreaField, SelectField, BooleanField, FieldList, FormField, Label
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    username = StringField("Username",  validators=[DataRequired(), Length(3, 20)])
    password = PasswordField("Password", validators=[DataRequired(), Length(3, 100)])
    submit = SubmitField("Login")

class RegisterForm(FlaskForm):
    invite_code = StringField("Invite Code", validators=[DataRequired(), Length(36, 36)])
    username = StringField("Username", validators=[DataRequired(), Length(3, 20)])
    password = PasswordField("Password", validators=[DataRequired(), Length(3, 100)])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), Length(3, 100)])
    submit = SubmitField("Register")

class CreateTicketForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(1, 100)])
    description = TextAreaField("Description", validators=[DataRequired()])
    state = SelectField("Ticket State", choices=[("backlog", "Backlog"), ("indev", "In Development"), ("Complete", "done")])
    submit = SubmitField("Create Ticket")

class UpdateTicketForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(1, 100)])
    description = TextAreaField("Description", validators=[DataRequired()])
    submit = SubmitField("Update Ticket")

class UserGroupPermissionSelection(Form):
    permission_selection_field = SelectField("Permission Name", choices=[
        ("NOTSET", "Make a Selection"),
        ("TICKETS", "All Ticket Permissions"),
        ("READ_TICKETS", "Read Tickets"),
        ("CREATE_TICKETS", "Create Tickets"),
        ("UPDATE_TICKETS", "Update Tickets"),
        ("DELETE_TICKETS", "Delete Tickets"),
        ("RESOLVE_OWN_TICKETS", "Resolve Own Tickets"),
        ("RESOLVE_OTHERS_TICKETS", "Resolve Others Tickets"),
        ("INVITECODES", "All Invite Code Permissions"),
        ("READ_CODES", "Read Invite Codes"),
        ("CREATE_CODES", "Create Invite Codes"),
        ("REVOKE_CODES", "Revoke Invite Codes"),
        ("USERACCOUNTS", "All User Accounts Permissions"),
        ("READ_USERS", "Read User Accounts"),
        ("UPDATE_USERS", "Update User Accounts"),
        ("DELETE_USERS", "Delete User Accounts"),
        ("USERGROUPS", "All UserGroup Permissions"),
        ("READ_USERGROUPS", "Read UserGroups"),
        ("CREATE_USERGROUPS", "Create UserGroups"),
        ("UPDATE_USERGROUPS", "Update UserGroups"),
        ("DELETE_USERGROUPS", "Delete UserGroups"),
        ("ADMIN", "Administrator")
    ])
    permission_value = SelectField("Permission Value", choices=[
        (True, "True"),
        (False, "False")
    ])
    remove_permission = SubmitField("Remove Permission")

class CreateUserGroupForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(1, 100)])

    permissions = FieldList(FormField(UserGroupPermissionSelection, 'Permission'), "Selected Permissions:", min_entries=1, max_entries=50)
    additional_permission_button = SubmitField("Add Permission")
    create_group_submit = SubmitField("Create Group")

class UpdateUserGroupForm(FlaskForm):
    permissions = FieldList(FormField(UserGroupPermissionSelection, 'Permission'), "Selected Permissions:", min_entries=1, max_entries=50)
    additional_permission_button = SubmitField("Add Permission")
    create_group_submit = SubmitField("Update Group")

class UpdateUserForm(FlaskForm):
    user_group = SelectField("Select Permission Group", choices=[], coerce=int)
    update_user_submit = SubmitField("Update User")

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField("Current Password", validators=[DataRequired(), Length(3, 100)])
    new_password = PasswordField("New Password", validators=[DataRequired(), Length(3, 100)])
    new_password_confirm = PasswordField("Confirm New Password", validators=[DataRequired(), Length(3, 100)])
    update_password_submit = SubmitField("Change Password")
