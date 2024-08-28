from flask import Flask, render_template, url_for, redirect, flash, abort
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegisterForm, LoginForm, AddProject, ContactForm
import smtplib

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
ckeditor = CKEditor(app)
Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    name: Mapped[str] = mapped_column(String(1000))
    password: Mapped[str] = mapped_column(String(100))


class Project(db.Model):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(100), nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str] = mapped_column(String(250), nullable=False)


with app.app_context():
    db.create_all()


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        name = form.name.data
        if User.query.filter_by(email=email).first():
            flash("Bu email kayitli. Lutfen giris yapin.", 'danger')
            return redirect(url_for('login'))
        else:
            hash_and_salted_password = generate_password_hash(
                password=password,
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                email=email,
                password=hash_and_salted_password,
                name=name
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)

            return redirect(url_for('home'))
    return render_template('register.html', form=form, current_user=current_user)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(password=password, pwhash=user.password):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash('Parolaniz yanlis. Lutfen tekrar deneyin.', 'danger')
                return redirect(url_for('login'))
        else:
            flash('Bu email kayitli degil. Lutfen tekrar deneyin.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html', form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
def home():
    result = db.session.execute(db.select(Project))
    projects = result.scalars().all()
    return render_template('index.html', all_projects=projects, current_user=current_user)


@app.route("/add-project", methods=['GET', 'POST'])
@admin_only
def add_project():
    form = AddProject()
    if form.validate_on_submit():
        new_project = Project(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            url=form.url.data
        )
        db.session.add(new_project)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('add_project.html', form=form, current_user=current_user)


@app.route("/edit-project<int:project_id>", methods=["GET", "POST"])
@admin_only
def edit_project(project_id):
    project = db.get_or_404(Project, project_id)
    edit_form = AddProject(
        title=project.title,
        subtitle=project.subtitle,
        url=project.url,
        body=project.body
    )
    if edit_form.validate_on_submit():
        project.title = edit_form.title.data
        project.subtitle = edit_form.subtitle.data
        project.url = edit_form.url.data
        project.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for('home'))
    return render_template("add_project.html", form=edit_form)


@app.route("/delete/<int:project_id>")
@admin_only
def delete_project(project_id):
    project_to_delete = db.get_or_404(Project, project_id)
    db.session.delete(project_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


@app.route("/contact", methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
            connection.starttls()
            connection.login(user="", password="")
            connection.sendmail(
                from_addr="",
                to_addrs="to me",
                msg=f"Subject:Website message!{current_user}\n\n{form.message.data}".encode('utf-8')
            )
        flash('Your message has been sent!', 'success')
        return redirect(url_for('home'))
    return render_template('contact.html', form=form)


@app.route("/project/<int:project_id>")
def show_project(project_id):
    project = Project.query.get_or_404(project_id)
    return render_template('project.html', project=project)


@app.route("/about")
def about():
    return render_template('about.html')


if __name__ == "__main__":
    app.run(debug=True)
