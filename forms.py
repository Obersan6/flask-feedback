"""User forms."""

from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, PasswordField, EmailField, TextAreaField
from wtforms.validators import InputRequired, Optional, Email, DataRequired, Length


# Classes

# Class to register a new user
class RegisterUserForm(FlaskForm):
    """
    Form to register a new user.
    Make sure that password input hides characters that user is typing.
    """
    username = StringField('Username', validators=[DataRequired(), Length(max=30)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])

# Class for user login
class LoginForm(FlaskForm):
    """
    Form to login a user.
    Make sure that password input hides characters that user is typing.
    """
    username = StringField('Username', validators=[DataRequired(), Length(max=30)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])

# Class for user to add a feedback
class AddFeedbackForm(FlaskForm):
    """Form for user to add a feedback."""
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    content= TextAreaField('Content', validators=[DataRequired()])

# Class for user to edit a feedback
class EditFeedbackForm(FlaskForm):
    """Form for user to edit a feedback."""
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Content', validators=[DataRequired()])
    



