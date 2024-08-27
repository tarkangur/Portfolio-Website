from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField('SIGN ME UP!')


class AddProject(FlaskForm):
    title = StringField("Project Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    url = StringField("Project URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Project Content", validators=[DataRequired()])
    submit = SubmitField("Submit Project")
