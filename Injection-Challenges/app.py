import os
import re
import sqlite3
from functools import wraps
from pydoc import html

from flask import Flask, render_template, request, flash, redirect, session, render_template_string

## Flask app
app = Flask(__name__)
app.secret_key = 'sotiCTF{"s3rV3RR_1s_V2n6e2ra3le"}'
## Connect to sqlite3 database
connection = sqlite3.connect('app.db', check_same_thread=False)
## Database cursor
cursor = connection.cursor()
SESSION_COOKIE_SECURE = True
xss_patterns = [
    re.compile(r"<script>alert\(.+\)<\/script>", flags=re.I),
]

# https://flask.palletsprojects.com/en/1.0.x/patterns/viewdecorators/
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "logged" in session:
            return f(*args, **kwargs)
        else:
            flash("Login first", "flash1")
            return redirect("/login")

    return wrap


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect("/")


@app.route("/", methods=['POST', 'GET'])
def homepage():
    return render_template("homepage.html")


# SQL Inject with admin'-- filtered out.
@app.route("/login", methods=['POST', 'GET'])
def login():
    if request.method == "GET":
        return render_template("login.html")
    else:
        if not request.form.get("username") or not request.form.get("password"):
            flash("Please enter username and password.", "danger")
            return render_template("login.html")
        username1 = request.form.get('username')
        password1 = request.form.get('password')
        try:
            result = cursor.execute(
                "SELECT username FROM users WHERE username = '%s' AND password = '%s'" % (username1, password1))

            result = result.fetchall()
            # censored admin'-- to increase difficulty
            if result == "admin'--":
                return render_template("login.html")

            if len(result) == 1:
                session["logged"] = True
                flash("sotiCTF{very_ba5ic_inject!on}", "flash1")

                return render_template("login.html")
            else:
                flash("Please enter username and password.", "danger")

                return render_template("login.html")

        except Exception as e:
            print("problem:" + str(e))
            flash("An unexpected error occured, please try again.\n", "danger")
    return render_template("login.html")


# Reflected XSS with search form
@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        comment = request.form['comment']

        if comment == '':
            return redirect('/search')
        else:
            cursor.execute('INSERT INTO text (text) VALUES (?)', (comment,))

    selectAll = cursor.execute('SELECT text FROM text')
    selectAll = selectAll.fetchall()

    searchQuery = request.args.get('q')

    textArray = []

    for comment in selectAll:
        if searchQuery is None or searchQuery in comment:
            textArray.append(comment)

    newTextArray = [i[0] for i in textArray]

    if searchQuery is not None:
        # encoded_input = html.escape(searchQuery)
        for pattern in xss_patterns:
            if pattern.search(searchQuery):
                flash("sotiCTF{r3fl3cT10ns}", "flash1")

                textArray.clear()
                return render_template('search.html', res=newTextArray, searchQuery=searchQuery)

    return render_template('search.html', res=newTextArray)

#Server Side Template Injection
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    # Get the 'name' parameter from the URL
    name = request.args.get('name', 'Admin')

    # Check if the 'name' parameter contains template syntax
    flag = None
    if "{{" in name and "}}" in name:
        # If it does, flash the flag
        flag = "sotiCTF{t3mpl4te_!njecti0n}"

    # Render the template
    return render_template('admin.html', name=name, flag=flag)

#TBD
@app.route('/adminpage')
@login_required
def admin_page():
    return render_template('adminpage.html')
    
#Running application server 
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='13.209.129.190', port=port, SESSION_COOKIE_SECURE=True)
