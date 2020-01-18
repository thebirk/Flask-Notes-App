import os

from hashlib import scrypt
from functools import wraps
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, session, request, redirect, url_for, render_template, flash

app = Flask("notes")
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///data.db"
db = SQLAlchemy(app)


class Session(db.Model):                                                                            # pylint: disable=no-member
    __tablename__ = 'sessions'
    user_id       = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, primary_key=True) # pylint: disable=no-member
    random_id     = db.Column(db.String, nullable=True, unique=True)                                # pylint: disable=no-member

    def __repr__(self):
        return f"<Session '{self.user.email}'>"


class User(db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True, autoincrement=True) # pylint: disable=no-member
    email         = db.Column(db.String, unique=True, nullable=False)           # pylint: disable=no-member
    password_hash = db.Column(db.String, nullable=False)                        # pylint: disable=no-member
    salt          = db.Column(db.String, nullable=False)                        # pylint: disable=no-member
    notes         = db.relationship('Note', backref='user', lazy='dynamic')     # pylint: disable=no-member
    session       = db.relationship('Session', backref='user', uselist=False)  # pylint: disable=no-member

    def __repr__(self):
        return f"<User '{self.email}''>"


class Note(db.Model):
    __tablename__ = 'notes'
    id      = db.Column(db.Integer, primary_key=True, autoincrement=True) # pylint: disable=no-member
    title   = db.Column(db.Text, nullable=False)                          # pylint: disable=no-member
    note    = db.Column(db.Text, nullable=False)                          # pylint: disable=no-member
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))            # pylint: disable=no-member
    date    = db.Column(db.DateTime, nullable=False)                      # pylint: disable=no-member

    def __repr__(self):
        return f"<Post '{self.title}'>"


def hash_password(password, salt):
    return scrypt(password=bytes(password, encoding='utf-8'), salt=salt, n=16384, r=8, p=1)


def verify_password(user, password):
    password_hash = hash_password(password, user.salt)
    return user.password_hash == password_hash


def require_auth(func):
    "A simple @decorator that checks if the user is authorized before access, if not they get redirected to log in."
    @wraps(func)
    def decorator(*args, **kwargs):
        if session.get('sid') is None:
            if request.method == 'GET':
                session['after_login_dest'] = request.url
            return redirect(url_for('login'))
        else:
            return func(*args, **kwargs)

    return decorator


def create_new_session_for_user(user):
    old_session = Session.query.filter_by(user_id=user.id).scalar()
    if old_session is not None:
        db.session.delete(old_session) # pylint: disable=no-member
        db.session.commit()            # pylint: disable=no-member

    sid = os.urandom(8)
    s = Session(user=user, random_id=sid)
    db.session.add(s)   # pylint: disable=no-member
    db.session.commit() # pylint: disable=no-member

    return sid


@app.route('/')
@require_auth
def index():
    user = Session.query.filter_by(random_id = session['sid']).scalar().user

    all_notes = user.notes.all()

    return render_template('index.html', user=user, all_notes=all_notes)


@app.route('/add_note', methods=['POST'])
@require_auth
def add_note():
    user = Session.query.filter_by(random_id = session['sid']).scalar().user
    note = Note(title=request.form['title'], note=request.form['note'], date=datetime.now(), user=user)
    db.session.add(note) # pylint: disable=no-member
    db.session.commit() # pylint: disable=no-member
    return redirect(url_for('index'))


@app.route('/delete_note', methods=['POST'])
@require_auth
def delete_note():
    # TODO: Make sure the note is owned by session['sid']
    pass


@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('sid'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        u = User.query.filter(User.email == request.form['email']).scalar()

        if (u is None) or (not verify_password(u, request.form['password'])):
            flash('Invalid credentials')
            return redirect(url_for('login'))

        sid = create_new_session_for_user(u)
        session['sid'] = sid

        if session.get('after_login_dest'):
            dest = session['after_login_dest']
            del session['after_login_dest']
            return redirect(dest)
        else:
            return redirect(url_for('index'))

    return render_template('login.html')


@app.route('/logout')
@require_auth
def logout():
    s = Session.query.filter_by(random_id = session['sid']).scalar()
    db.session.delete(s) # pylint: disable=no-member
    db.session.commit()  # pylint: disable=no-member
    del session['sid']
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # TODO: Verify email is actually an email

        exists = db.session.query(User.email).filter_by(email=request.form['email']).scalar() is None # pylint: disable=no-member

        if not exists:
            flash('Email address is already registered!')
            return redirect(url_for('register'))

        salt = os.urandom(16)
        password_hash = hash_password(request.form['password'], salt)

        user = User(email=request.form['email'], password_hash=password_hash, salt=salt)
        db.session.add(user) # pylint: disable=no-member
        db.session.commit() # pylint: disable=no-member

        sid = create_new_session_for_user(user)
        session['sid'] = sid

        # TODO: Respect 'after_login_dest'
        return redirect(url_for('index'))
    else:
        return render_template('register.html')



if __name__ == "__main__":
    app.secret_key = os.urandom(16)
    app.run(debug=True)