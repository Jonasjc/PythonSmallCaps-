from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)


@auth.route('/entrar', methods=['GET', 'POST'])
def entrar():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Successfully!', category="success")
                login_user(user, remember=True)
                return redirect(url_for('views.homepage'))
            else:
                flash('Senha incorreta!', category='error')

        else:
            flash('Email não cadastrado', category="error")

    return render_template('entrar.html')


@auth.route('/sair')
@login_required
def sair():
    logout_user()
    return render_template('entrar.html')


@auth.route('/cadastrar', methods=['GET', 'POST'])
def cadastrar():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('name')
        password = request.form.get('password')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Endereço de email já cadastrado!', category="error")
        elif len(email) < 8:
            flash('Endereço de email inválido', category='error')
        elif ' ' not in username:
            flash('Escreva seu nome completo', category='error')
        elif len(password) < 8:
            flash('Senha muito curta', category='error')
        elif password != password2:
            flash('As senhas não coincidem', category='error')
        else:
            novo_usuario = User(email=email, username=username, password=generate_password_hash(password, method='sha256'))
            db.session.add(novo_usuario)
            db.session.commit()
            flash('Conta criada com sucesso', category='success')
            login_user(user, remember=True)
            return redirect(url_for('views.homepage'))

    return render_template('cadastrar.html', user=current_user)
