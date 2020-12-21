from database import db
from flask_login import UserMixin
from datetime import datetime

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    surname = db.Column(db.String(50), nullable=False)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

class ip_company_vedenie(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name_company = db.Column(db.String(255), nullable=False)
    kolvo_sotr = db.Column(db.String(255), nullable=False)
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

class ip_company_razoviy(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name_company = db.Column(db.String(255), nullable=False)
    kolvo_sotr = db.Column(db.String(255), nullable=False)
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



class ooo_company_vedenie(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name_company = db.Column(db.String(255), nullable=False)
    #kolvo_sotr = db.Column(db.String(255), nullable=False)
    inn_company = db.Column(db.String(50), nullable=False)
    ogrn = db.Column(db.String(128), nullable=False, unique=True)
    kpp = db.Column(db.String(128), nullable=False, unique=True)
    date_reg = db.Column(db.String(255), nullable=False)
    fio_gen_dir = db.Column(db.String(255), nullable=False)
    fio_contact = db.Column(db.String(255), nullable=False)
    sis_nalog = db.Column(db.String(10), nullable=False)
    vid_uslugi = db.Column(db.String(255), nullable=False)
    vid_rabot = db.Column(db.String(255), nullable=False)
    tel_number = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    comment = db.Column(db.Text(500), nullable=False)
    date_create = db.Column(db.DateTime, default=datetime.utcnow)

class ooo_company_razoviy(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name_company = db.Column(db.String(255), nullable=False)
    #kolvo_sotr = db.Column(db.String(255), nullable=False)
    inn_company = db.Column(db.String(50), nullable=False)
    ogrn = db.Column(db.String(128), nullable=False, unique=True)
    kpp = db.Column(db.String(128), nullable=False, unique=True)
    date_reg = db.Column(db.String(255), nullable=False)
    fio_gen_dir = db.Column(db.String(255), nullable=False)
    fio_contact = db.Column(db.String(255), nullable=False)
    sis_nalog = db.Column(db.String(10), nullable=False)
    vid_uslugi = db.Column(db.String(255), nullable=False)
    vid_rabot = db.Column(db.String(255), nullable=False)
    tel_number = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    comment = db.Column(db.Text(500), nullable=False)
    date_create = db.Column(db.DateTime, default=datetime.utcnow)


class fiz_ved(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    fio = db.Column(db.String(255), nullable=False)
    passport = db.Column(db.String(255), nullable=False)
    pass_vidan = db.Column(db.String(255), nullable=False)
    date_vidan = db.Column(db.String(255), nullable=False)
    kod_podr = db.Column(db.String(255), nullable=False)
    fio_contact = db.Column(db.String(255), nullable=False)
    #vid_uslugi = db.Column(db.String(255), nullable=False)
    tel_number = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    comment = db.Column(db.Text(500), nullable=False)
    date_create = db.Column(db.DateTime, default=datetime.utcnow)


class fiz_raz(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    fio = db.Column(db.String(255), nullable=False)
    passport = db.Column(db.String(255), nullable=False)
    pass_vidan = db.Column(db.String(255), nullable=False)
    date_vidan = db.Column(db.String(255), nullable=False)
    kod_podr = db.Column(db.String(255), nullable=False)
    fio_contact = db.Column(db.String(255), nullable=False)
    #vid_uslugi = db.Column(db.String(255), nullable=False)
    tel_number = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    comment = db.Column(db.Text(500), nullable=False)
    date_create = db.Column(db.DateTime, default=datetime.utcnow)

class debitor(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name_company = db.Column(db.String(255), nullable=False)
    inn_company = db.Column(db.String(50), nullable=False)
    fio_contact = db.Column(db.String(255), nullable=False)
    tel_number = db.Column(db.String(255), nullable=False)
    summ_deb = db.Column(db.String(50), nullable=False)
    kvartal = db.Column(db.String(50), nullable=False)
    god = db.Column(db.String(50), nullable=False)
    comment = db.Column(db.Text(500), nullable=False)