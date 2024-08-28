from flask import Flask, flash,render_template,url_for,request
import joblib
import re
import string
import pandas as pd
from flask import Flask, url_for, render_template, request, redirect, session
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
import secrets


app = Flask(__name__)
Model = joblib.load('C:/Users/mubinshaikh/Desktop/fake content identifications/fake_content_dections/model.pkl')

secret_key = secrets.token_hex(24)
app.secret_key = str(secret_key)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route('/')
def index():
    context = {
        'authenticated': {
            'user': False  # Set to a truthy value if the user is authenticated
        }
    }
    return render_template("login.html", **context)

# @app.route('/login')
# def login():
#     return render_template("login.html")

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        # check the form is valid
        if not request.form.get("email") or not request.form.get("password"):
            return "please fill out all required fields"

        # check if email exist in the database
        user = c.execute("SELECT * FROM users WHERE email=:email", {"email": request.form.get("email")}).fetchall()

        if len(user) != 1:
            return "you didn't register"

        # check the password is same to password hash
        pwhash = user[0][2]
        if check_password_hash(pwhash, request.form.get("password")) == False:
            return "wrong password"

        # login the user using session
        session["user_id"] = user[0][0]

        # return success
        return render_template("index.html")

    else:
        context = {
        'authenticated': {
            'user': False  # Set to a truthy value if the user is authenticated
        }
        }
        return render_template("login.html", **context)


conn = sqlite3.connect("db.sqlite3", check_same_thread=False)
c = conn.cursor()

c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
''')

@app.route('/register',  methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        # check if the form is valid

        if not request.form.get("email") or not request.form.get("password") or not request.form.get("confirmation"):
            return "please fill out all fields"

        if request.form.get("password") != request.form.get("confirmation"):
            return "password confirmation doesn't match password"

        # check if email exist in the database
        exist = c.execute("SELECT * FROM users WHERE email=:email", {"email": request.form.get("email")}).fetchall()

        if len(exist) != 0:
            return "user already registered"

        # hash the password
        pwhash = generate_password_hash(request.form.get("password"), method="pbkdf2:sha256", salt_length=8)

        # insert the row
        c.execute("INSERT INTO users (email, password) VALUES (:email, :password)", {"email": request.form.get("email"), "password": pwhash})
        conn.commit()

        # return success
        flash("registered successfully!")
        return redirect('/login')
    else:
        context = {
        'authenticated': {
            'user': True  # Set to a truthy value if the user is authenticated
        }
        }
        return render_template('register.html', **context)

def wordpre(text):
    text = text.lower()
    text = re.sub(r'\[.*?\]', '', text)
    text = re.sub("\\W"," ",text) # remove special chars
    text = re.sub(r'https?://\S+|www\.\S+', '', text)
    text = re.sub('<.*?>+', '', text)
    text = re.sub('[%s]' % re.escape(string.punctuation), '', text)
    text = re.sub('\n', '', text)
    text = re.sub(r'\w*\d\w*', '', text)
    return text

@app.route('/index',methods=['POST'])
def pre():
    if request.method == 'POST':
        txt = request.form['txt']
        txt = wordpre(txt)
        txt = pd.Series(txt)
        result = Model.predict(txt)
        return render_template("index.html", result = result)
    return '' 
    

if __name__ == "__main__":
    app.run(debug=True)



app.config["SECRET_KEY"] = "secretkey"




