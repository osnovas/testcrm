from flask import Flask, Blueprint, render_template
from flask_login import login_required, current_user
from models.clients_model import User

clients = Blueprint('clients', __name__ )




class Item(object):
    def __init__(self, name, surname, login):
        self.name = name
        self.surname = surname
        self.login = login

        
#items = [Item('Name1', 'Description1', 'lll'),
#         Item('Name2', 'Description2', 'qqq'),
#         Item('Name3', 'Description3', 'wwww')]

@clients.route('/main')
@login_required
def main():
    #items2 = [dict(name='Name1', surname='1', login='Description1'),
    #        dict(name='Name2', surname='2', login='Description2'),
    #        dict(name='Name3', surname='3', login='Description3')]
    #rows = User.query.all()
    return render_template("main.html", clients = User.query.all())