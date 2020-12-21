from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

#class Job(db.Model):
#    __tablename__ = 'job'
#    id = db.Column(db.Integer, primary_key=True)
#    state = db.Column(db.String(120)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    surname = db.Column(db.String(50), nullable=False)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

class IdP(db.Model):
    __tablename__ = 'individual_manager'
    id = db.Column(db.Integer, primary_key=True)
    name_idp = db.Column(db.String(150), nullable=False)
    second_name = db.Column(db.String(150), nullable=False)
    first_name = db.Column(db.String(150), nullable=False)
    patr_name = db.Column(db.String(150), nullable=False)
    inn = db.Column(db.String(50), nullable=False)
    ogrnip = db.Column(db.String(50), nullable=False)
    okpo = db.Column(db.String(50), nullable=False)
    okved = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    address_ph = db.Column(db.Text, nullable=True)
    address_ur = db.Column(db.Text, nullable=True)
    description = db.Column(db.Text, nullable=True)