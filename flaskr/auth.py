import functools

import os

import sqlite3

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, send_file, send_from_directory
)
from werkzeug.security import check_password_hash, generate_password_hash

from werkzeug.utils import secure_filename

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        file = request.files['file']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif not firstname:
            error = 'First Name is required.'
        elif not lastname:
            error = 'Last Name is required.'
        elif not email:
            error = 'Email is required.'

        if error is None:
            user_id = None
            try:
                wordcount = 0
                if file:
                    print(file.filename)
                    filename = secure_filename(username + '.txt')
                    file.save(os.path.join(os.path.dirname(os.getcwd()), filename))
                    f = open(os.path.join(os.path.dirname(os.getcwd()) , filename), 'r')
                    file_content = f.read()
                    if file_content:
                        lines = file_content.split('\n')
                        for line in lines:
                            words = line.split(' ')
                            wordcount = wordcount + len(words)
                    file.close()
                    f.close()
                ret = db.execute(
                    "INSERT INTO user (username, password, firstname, lastname, email, wordcount) VALUES (?, ?, ?, ?, ?, ?)",
                    (username, generate_password_hash(password), firstname, lastname, email, wordcount),
                )
                user_id = ret.lastrowid
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                session.clear()
                session['user_id'] = user_id
                return redirect(url_for('auth.userdetails', username=username))

        flash(error)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('auth.userdetails', username=username))

        flash(error)
    
    return render_template('auth/login.html')


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()



def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view


@bp.route('/userdetails/<username>')
@login_required
def userdetails(username):
    db = get_db()
    
    if username is None:
        user = None
    else:
        user = db.execute(
            'SELECT * from user WHERE username = ?', (username,)
            ).fetchone()
        if 'user_id' in session.keys() and user != None and session['user_id'] != user['id']:
            
            return redirect(url_for('auth.login'))    
    if user is None:
        return redirect(url_for('auth.login'))
    else:
        return render_template('auth/userDetails.html', user=user)


@bp.route('/uploaded_file/<username>')
def uploaded_file(username):
    print('uplos')
    return send_from_directory(os.path.dirname(os.getcwd()), str(username) + '.txt', as_attachment=True)
