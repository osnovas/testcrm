#coding: utf-8
from flask import Flask, render_template, url_for, request, flash, redirect, Blueprint
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from clients import *
import sys
from models.clients_model import db as root_db

app = Flask(__name__)

app.secret_key = 'jhzdfjhJGdfjgvJGjgvsdfjhvJGVjvgdfhm'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mainbase.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
manager = LoginManager(app)

root_db.init_app(app)
with app.app_context():
    root_db.create_all()

app.register_blueprint(clients)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    surname = db.Column(db.String(50), nullable=False)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)


@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)



#регистрация нового пользователя
@app.route("/register", methods=["POST", "GET"])
def register():
    name = request.form.get("name")
    surname = request.form.get("surname")
    login = request.form.get("login")
    password = request.form.get('password')
    password2 = request.form.get('password2')
    if request.method == "POST":
        if not (name or surname or login or password or password2):
            flash("Пожалуйста заполните все поля")
        elif password != password2:
            flash("Пароли не совпадают")
        else:
            hash_pwd = generate_password_hash(password)
            newuseradd = User(name=name, surname=surname, login=login, password=hash_pwd)
            try:
                db.session.add(newuseradd)
                db.session.commit()
                return redirect('/')
            except:
                flash("Ошибка")
    else:
        return render_template('/register.html')

#тут пишем роуты

@app.route('/', methods=['GET','POST'])
def login():
    if current_user is not None and current_user.is_authenticated:
        return redirect("/main")
    login = request.form.get('login')
    password = request.form.get('password')
    if login and password:
        user = User.query.filter_by(login=login).first()
        if user is not None:
            if check_password_hash(user.password, password):
                login_user(user)
                #next_page = request.args.get('next')
                return redirect("/main")
            else:
                flash("Логин или пароль не корректные")
                return render_template('login.html')
        else:
            flash("Логин или пароль не корректные")
            return render_template('login.html')
    else:
        flash("Введите логин и пароль")
        return render_template('login.html')


@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route('/main-lead-append', methods=['GET', 'POST'])
@login_required
def main_lead_append():
    return render_template("main-lead-append.html")


#@app.route("/main")
#@login_required
#def index():
#    return render_template("main.html")

@app.route('/debitor', methods=['GET', 'POST'])
@login_required
def debitor():
    return render_template("debitor.html")


@app.route('/workspace', methods=["GET", "POST"])
@login_required
def workspace():
    return render_template("workspace.html")

@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for("login") + '?next' + request.url)
    return response


















if __name__ == "__main__":
    app.run(debug=True)
