
from flask import Flask, render_template, request , render_template, request, redirect, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
import joblib
import re
import string
import pandas as pd
import os
import sqlite3
import secrets

app = Flask(__name__)

conn = sqlite3.connect("db.sqlite3", check_same_thread=False)
c = conn.cursor()

c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
''')

secret_key = secrets.token_hex(24)
app.secret_key = str(secret_key)

# Correct the path to the model file
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
model_path = os.path.join(parent_dir, "model.pkl")
print(f"Corrected model path: {model_path}")

# Load the model
Model = joblib.load(model_path)

@app.route('/')
def index():
    context = {
        'authenticated': {
            'user': False  # Set to a truthy value if the user is authenticated
        }
    }
    return render_template("login.html", **context)


def wordpre(text):
    text = text.lower()
    text = re.sub(r'\[.*?\]', '', text)
    text = re.sub("\\W", " ", text)  # remove special characters
    text = re.sub(r'https?://\S+|www\.\S+', '', text)
    text = re.sub('<.*?>+', '', text)
    text = re.sub('[%s]' % re.escape(string.punctuation), '', text)
    text = re.sub('\n', '', text)
    text = re.sub(r'\w*\d\w*', '', text)
    return text

@app.route('/', methods=['POST'])
def pre():
    if request.method == 'POST':
        txt = request.form['txt']
        txt = wordpre(txt)
        txt = pd.Series([txt])  # Ensure this is passed as a list or a Series
        
        try:
            result = Model.predict(txt)
            result = result[0]  # Assuming it's a list/array, get the first prediction
        except Exception as e:
            result = f"Error: {str(e)}"
        
        return render_template("index.html", result=result)
    




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

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True)




