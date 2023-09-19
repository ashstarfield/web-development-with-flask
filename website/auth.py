from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, logout_user, login_required, current_user

auth = Blueprint('auth', __name__)

@auth.route('login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = db.session.query(User).filter_by(email = email).first()
        if user:
            if check_password_hash(user.password,password):
                flash("Successfully logged in", category="Success")
                login_user(user, remember=True)
                print("Successfully logged in")
                return redirect(url_for('views.home'))
            else:
                flash("Incorrect password", category="error")
            
        else:
            flash("User does not exist", category="error")
    return render_template("login.html", user = current_user)


@auth.route('logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('sign-up', methods = ['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        
        user = db.session.query(User).filter_by(email = email).first()

        if user:
            flash("User already exists", category="error")
        elif len(email) < 3:
            flash("The Email must be greater than 3 characters...", category="error")
        elif len(first_name) < 2:
            flash("The first name must contain more than 2 characters...", category="error")
        elif len(last_name) < 2:
            flash("Tha last name must contain more than 2 characters...", category="error")
        elif password1 != password2 :
            flash("Both the password must be same...", category="error")
        else :
            # pass #the data is sent to the Database
            
            new_user= User(email = email, password =generate_password_hash(password1, method="sha256") , firstName = first_name, lastName = last_name)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)    
            flash("The Account has been successfully registered...", category="Success")  
            return redirect(url_for('views.home'))              
    return render_template("sign_up.html", user = current_user)


