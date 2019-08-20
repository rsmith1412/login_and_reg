from flask import Flask, render_template, request, redirect, session, flash
from flask_bcrypt import Bcrypt
from mysql_connection import connectToMySQL
import re 

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
app = Flask(__name__)
app.secret_key = "the biggest secret"
bcrypt = Bcrypt(app)

# First route to login or register
@app.route('/')
def login_and_reg():
    return render_template("index.html")

# POST route for first time users to create an account. If successful, redirects to 'success' page. Otherwise redirects to /
@app.route('/register', methods=['POST'])
def create():
    print("Got post info")
    print(request.form)
    # include some logic to validate user input before adding them to the database!
    # Going to use this data twice, so putting it into a variable
    first_name = request.form["first_name"]
    last_name = request.form["last_name"]
    form_email = request.form["email"]
    pass_word = request.form["password"]
    print(form_email, "LOOK HERE")
    #Setting up a query to retrieve all the email addresses so we can verify the new one doesn't already exist in the DB
    mysql = connectToMySQL("login_and_reg")
    query = "SELECT email FROM users;"
    results = mysql.query_db(query)
    print(results)
    is_valid = True
    if len(first_name) < 2 or not first_name.isalpha():
        is_valid = False
        flash(u"First name must contain at least two letters and only contain letters.", 'register')
    if len(last_name) < 2 or not last_name.isalpha():
        is_valid = False
        flash(u"Last name must contain at least two letters and only contain letters.", 'register')
    if not EMAIL_REGEX.match(form_email):
        is_valid = False
        flash(u"Invalid email address!", 'register')
    if not pass_word == request.form["confirm_password"]:
        is_valid = False
        flash(u"Password was not confirmed!", 'register')
    for result in results:
        if form_email == result["email"]:
            print("------------------------")
            is_valid = False
            flash(u"Email address already exists!", "register")
        
    # create the hash
    pw_hash = bcrypt.generate_password_hash(pass_word)  
    print(pw_hash)  
    # prints something like b'$2b$12$sqjyok5RQccl9S6eFLhEPuaRaJCcH3Esl2RWLm/cimMIEnhnLb7iC'
    # be sure you set up your database so it can store password hashes this long (60 characters)copy
    if is_valid:
        mysql = connectToMySQL("login_and_reg")
        query = "INSERT INTO users (first_name, last_name, email, password_hash) VALUES (%(fname)s, %(lname)s, %(email)s, %(password_hash)s);"
        # put the pw_hash in our data dictionary, NOT the password the user provided
        data = { 
            "fname" : first_name,
            "lname" : last_name,
            "email" : form_email,
            "password_hash" : pw_hash 
        }
        mysql.query_db(query, data)
        session["first_name"] = first_name
        print(session["first_name"], "---------------------")
        # never render on a post, always redirect!
        print(is_valid)
        return redirect("/success")
    return redirect('/')

# POST route to login with an existing account. Success redirects to success page, other wise redirects to login page
@app.route('/login', methods=['POST'])
def login():
    # see if the username provided exists in the database
    mysql = connectToMySQL("login_and_reg")
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = { "email" : request.form["email"] }
    result = mysql.query_db(query, data)
    print(result, "!!!!!!!!!!!!!!!!!!!!!!!!!")
    if len(result) > 0:
        # use bcrypt's check_password_hash method, passing the hash from our database and the password from the form
        if bcrypt.check_password_hash(result[0]['password_hash'], request.form['password_hash']):
            # if we get True after checking the password, we may put the user id in session
            session['first_name'] = result[0]['first_name']
            print(session['first_name'], "?????????????????????????????")
            # never render on a post, always redirect!
            return redirect('/success')
    # if we didn't find anything in the database by searching by username or if the passwords don't match,
    # flash an error message and redirect back to a safe route
    flash(u"You could not be logged in.", 'login')
    return redirect("/")

# Upon successful login/registration, displays welcome message with session["first_name"]
@app.route('/success')
def display_welcome():
    if 'first_name' not in session:
        return redirect('/')
    else:
        user_first_name = session['first_name']
    return render_template("success.html")

# Logout route will clear the session and redirect to root 
@app.route('/logout')
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)