from flask import Blueprint, render_template , request , flash , redirect , url_for
from .models import User
from werkzeug.security import generate_password_hash , check_password_hash
from .models import User
from . import db    

auth = Blueprint('auth', __name__)

@auth.route('/login' , methods=['GET', 'POST'])
def login():
    data = request.form
    print(data)
    return render_template("login.html", boolean=True)

@auth.route('/sign-up' , methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if len(email) < 4:
            flash("Email must be greater than 4 characters." , category='error')
        elif len(firstName) < 2:
            flash("First name must be greater than 2 characters." , category='error')
        elif password1 != password2:
            flash("Passwords don't match." , category='error')
        elif len(password1) < 7:
            flash("Password must be at least 7 characters." , category='error')
        else:
            new_user = User(email=email, firstname=firstName, password=generate_password_hash(password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully!" , category='success')
            return redirect(url_for('views.home'))
        
        print(email, firstName, password1, password2)
    return render_template("sign_up.html", text="Testing" , user="Tim")

@auth.route('/logout')
def logout():
    return render_template("logout.html")