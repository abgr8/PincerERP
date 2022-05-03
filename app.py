# Importing Flask Utilities
from flask import Flask, redirect, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin , LoginManager, login_user, login_required, logout_user, current_user, user_loaded_from_cookie

# Form utilites 

from flask_wtf import *
from wtforms import *
from wtforms.validators import DataRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

# creating the APP with the name of the File

app = Flask(__name__)
bcrypt = Bcrypt(app)
# Setting the secret key for the database

db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secret'

# getting the login manager

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ToDo
# 
# TODO: Create a universal CSS file
# 
# TODO: add the main content to the main page
# 
# TODO: create a different folder and file for the main page after the login process
# 


# Creating the database

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    
    # password length 80 because of hashing
    
    password = db.Column(db.String(80), nullable=False)

# Creating the Form

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[DataRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Password"})
    
    submit = SubmitField('Sign Up')
    
    # validating if 2 users have the same username
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')
        
# Login Form

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[DataRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Password"})
    
    submit = SubmitField('Login') 
    
# Routing the app

@app.route('/')
def hello():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            
    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    
    # validating and submitting the form to the database
    
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user.username)
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('hello'))


if __name__ == '__main__':
    print('Abbas spent hours on this')
    # import webbrowser
    # webbrowser.open_new_tab('http://localhost:5000/')
    app.run(debug=True)
    
    # Spent more than 1 hour on this project and it was a good learning experience
    # I still suck at Flask
    # 116 beautifuly formatted clean lines of code
    # https://www.youtube.com/watch?v=dam0GPOAvVI (watch later)