#coding: utf-8
from flask import Flask, render_template, url_for, request, flash, redirect
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user

app = Flask(__name__)
app.secret_key = 'jhzdfjhJGdfjgvJGjgvsdfjhvJGVjvgdfhm'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mainbase.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
manager = LoginManager(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    surname = db.Column(db.String(50), nullable=False)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

class ip_company(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name_company = db.Column(db.String(255), nullable=False)
    inn_company = db.Column(db.String(50), nullable=False)
    ogrnip = db.Column(db.String(128), nullable=False, unique=True)
    fio = db.Column(db.String(255), nullable=False)
    sis_nalog = db.Column(db.String(10), nullable=False)
    vid_uslugi = db.Column(db.String(255), nullable=False)
    vid_rabot = db.Column(db.String(255), nullable=False)
    tel_number = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    comment = db.Column(db.Text(500), nullable=False)
    date_create = db.Column(db.DateTime, default=datetime.utcnow)



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
    login = request.form.get('login')
    password = request.form.get('password')
    if login and password:
        user = User.query.filter_by(login=login).first()

        if check_password_hash(user.password, password):
            login_user(user)
            #next_page = request.args.get('next')
            return redirect("/main")
        else:
            flash("Логин или пароль не корректные")
    else:
        flash("Введите логин и пароль")
        return render_template('login.html')


@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/main")
@login_required
def index():

    return render_template("main.html")
    #usluga_list = request.form.getlist('get_usluga_ooo_razoviy')

@app.route("/ip_append", methods=['GET','POST'])
@login_required
def ip_append():
    if request.method == "POST":
        name_company = request.form['name_company']
        inn_company = request.form['inn_company']
        ogrnip = request.form['ogrnip']
        fio = request.form['fio']
        sis_nalog = request.form['sis_nalog']
        vid_uslugi = request.form['vid_uslugi']
        vid_rabot = request.form['vid_rabot']
        tel_number = request.form['tel_number']
        email = request.form['email']
        comment = request.form['comment']
        append_ip = ip_company(name_company=name_company, inn_company=inn_company, ogrnip=ogrnip, fio=fio, sis_nalog=sis_nalog,
                               vid_uslugi=vid_uslugi, vid_rabot=vid_rabot, tel_number=tel_number, email=email,comment=comment )
        try:
            db.session.add(append_ip)
            db.session.commit()
            return redirect('/main')
        except:
            return "При добавлении получилась ошибка"
    else:
        return render_template('main.html')

@app.route('/debitor', methods=['GET', 'POST'])
@login_required
def debitor():
    return render_template("debitor.html")


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for("login") + '?next' + request.url)
    return response


















if __name__ == "__main__":
    app.run(debug=True)
