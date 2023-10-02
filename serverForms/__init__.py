from flask_wtf import FlaskForm
from wtforms import SubmitField, StringField, PasswordField, TextAreaField, SelectField
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
