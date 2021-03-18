import sqlite3
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import string
import random

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure python script to use SQLite database
db = sqlite3.connect('votes.db', check_same_thread=False)

def login_required(f):

    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            flash(u'Must provide a username', 'error')
            return redirect('/login')

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash(u'Must provide a password', 'error')
            return redirect('/login')

        # Query database for username
        with db:
            db.row_factory = sqlite3.Row
            cur = db.cursor()
            cur.execute("SELECT * FROM users WHERE username = :username",
                        {'username' : request.form.get("username")})
            rows = cur.fetchall()

            # Ensure username exists and password is correct
            if len(rows) != 1 or not check_password_hash(rows[0]["hash"],
                                        request.form.get("password")):
                flash(u'Invalid password provided', 'error')
                return redirect('/login')

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            flash(u'Must provide a username', 'error')
            return redirect('/register')

        # Ensure password was submitted
        elif not request.form.get("password1") or not request.form.get("password2"):
            flash(u'Must provide a password', 'error')
            return redirect('/register')


        # Ensure that username is unique
        with db:
            cur = db.cursor()
            cur.execute("SELECT * FROM users WHERE username = :username",
                        {'username' : request.form.get("username")})
            rows = cur.fetchall()
            if len(rows) > 0:
                flash(u'Username already in use', 'error')
                return redirect('/register')


        # Ensure that passwords match
        if request.form.get("password1") != request.form.get("password2"):
            flash(u'Passwords must match', 'error')
            return redirect('/register')

        hashed_pwd = generate_password_hash(request.form.get("password1"))

        with db:
            cur = db.cursor()
            cur.execute("INSERT INTO users (username, hash) VALUES (?, ?) ",
            (request.form.get("username"), hashed_pwd))
        return redirect('/')

    else:
        return render_template("register.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect('/')

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/create', methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        credit = request.form.get("credits")
        if credit == '':
            credit = int(100)
        description = request.form.get("description")

        fields = ''
        i = 0
        while True:
            field = request.form.get("field"+str(i))
            if field is None:
                break
            fields += field + '|'
            i += 1

        with db:
            cur = db.cursor()
            code = ''
            while True:
                code = get_random_string()
                cur.execute("SELECT * FROM elections WHERE election_id = :election_id",
                            {'election_id': code})
                if len(cur.fetchall()) == 0:
                    break
            cur.execute("""INSERT INTO elections (creator_id, election_id, credits,
                        description, fields) VALUES (?, ?, ?, ?, ?) """,
                        (session["user_id"], code, credit, description, str(fields)))
        return redirect('/')

    else:
        return render_template("create.html")

@app.route('/elections')
@login_required
def elections():
    with db:
        db.row_factory = sqlite3.Row
        cur = db.cursor()
        cur.execute("SELECT * FROM elections WHERE creator_id = :creator_id",
                    {'creator_id': session["user_id"]})
        rows = cur.fetchall()

    data = format_data(rows)

    return render_template("elections.html", data=data)

@app.route('/<page>')
@login_required
def election(page):
    legit = check_page(page)
    if not legit:
        flash(u'Not Found, 404', 'error')
        return redirect('/')

    with db:
        db.row_factory = sqlite3.Row
        cur = db.cursor()
        cur.execute("""SELECT field, votes FROM votes WHERE election_id = :election_id
                    and user_id = :user_id""",
                    {'election_id': page, 'user_id': session['user_id']})
        rows = cur.fetchall()

    if len(rows) == 0:
        return redirect('/'+page+'/vote')

    with db:
        db.row_factory = sqlite3.Row
        cur = db.cursor()
        cur.execute("SELECT field, votes FROM votes WHERE election_id = :election_id",
                    {'election_id': page})
        rows = cur.fetchall()
        cur.execute("SELECT COUNT(DISTINCT user_id) FROM votes WHERE election_id = :election_id",
                    {'election_id': page})
        num = cur.fetchall()
        cur.execute("SELECT user_id, field, votes FROM votes WHERE election_id = :election_id",
                    {'election_id': page})
        votes = cur.fetchall()

    data = {}
    for i in range(len(rows)):
        if rows[i]['field'] not in data:
            data[rows[i]['field']] = 0
        data[rows[i]['field']] += int(rows[i]['votes'])
    sorted_data = sorted(data.items(), key=lambda x: x[1], reverse=True)

    vote_data = {}
    for i in range(len(votes)):
        if votes[i]['user_id'] not in vote_data:
            vote_data[votes[i]['user_id']] = []
        vote_data[votes[i]['user_id']].append([votes[i]['field'], votes[i]['votes']])

    winners = []
    winner_votes = 0
    for field, votes in data.items():
        if votes > winner_votes:
            winners = [field]
            winner_votes = votes
        elif votes == winner_votes:
            winners.append(field)
    return render_template("results.html", winners=winners,
                            data=sorted_data, number=num, link=page, vote=vote_data)

@app.route('/<page>/vote', methods=["GET", "POST"])
@login_required
def vote(page):
    with db:
        cur = db.cursor()
        cur.execute("SELECT * FROM elections WHERE election_id = :election_id",
                    {'election_id': page})
        rows = cur.fetchall()
    data = format_data(rows)
    if request.method == "POST":
        vote_data = {}
        for i, field in enumerate(data[0]['fields']):
            votes = request.form.get('field'+str(i)+'_votes')
            if votes == '':
                votes = 0
            vote_data[field] = votes

        with db:
            cur = db.cursor()
            for key, value in vote_data.items():
                cur.execute("""INSERT INTO votes (user_id, election_id, field, votes)
                            VALUES (?, ?, ?, ?)""",
                            (session['user_id'], data[0]['election_id'], key, value))

        return redirect('/' + page)
    else:
        legit = check_page(page)
        if not legit:
            flash(u'Not Found, 404', 'error')
            return redirect('/')

        # check to see if user has already voted
        voted = check_voted(data[0]['election_id'])
        if voted:
            flash(u"It seems you've already voted")
            return redirect('/' + page)

        return render_template("vote.html", page=data[0]['election_id'],
                                description=data[0]['description'],
                                fields=data[0]['fields'], credits=data[0]['credits'])

@app.route('/myvotes')
@login_required
def myvotes():
    with db:
        db.row_factory = sqlite3.Row
        cur = db.cursor()
        cur.execute("SELECT election_id, field, votes FROM votes WHERE user_id = :user_id",
                    {'user_id': session['user_id']})
        rows = cur.fetchall()
    data = {}
    for i in range(len(rows)):
        if rows[i]['election_id'] not in data:
            data[rows[i]['election_id']] = []
        data[rows[i]['election_id']].append([rows[i]['field'], rows[i]['votes']])

    return render_template("myvotes.html", data=data)

@app.route('/search', methods=["POST"])
def search():
    return redirect('/' + request.form.get('link'))

def check_voted(election):
    with db:
        cur = db.cursor()
        cur.execute("SELECT * FROM votes WHERE election_id = :election_id AND user_id = :user_id",
                    {'election_id': election, 'user_id': session['user_id']})
        rows = cur.fetchall()

    if len(rows) == 0:
        return False
    return True

def format_data(rows):
    data = []
    for i in range(len(rows)):
        data.append({})
        data[i]['election_id'] = rows[i]['election_id']
        data[i]['description'] = rows[i]['description']
        data[i]['fields'] = rows[i]['fields'].split('|')[0:-1]
        data[i]['credits'] = rows[i]['credits']
    return data

def check_page(page):
    with db:
        cur = db.cursor()
        cur.execute("SELECT election_id FROM elections WHERE election_id = :election_id",
                    {'election_id': page})
        rows = cur.fetchall()

    if len(rows) == 0:
        return False
    return True

def get_random_string():
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(8))
    return result_str

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    flash(u'{0}, {1}'.format(e.name, e.code), 'error')
    return redirect('/')

# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
