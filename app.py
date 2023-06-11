from flask import Flask, redirect, render_template, request, session, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'site'
app.config['SESSION_COOKIE_NAME'] = 'session'
app.config['PERMANENT_SESSION_LIFETIME'] = 600

DATABASE = 'users.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        with g.db as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                type TEXT NOT NULL
            )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS bookings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    date TEXT NOT NULL,
                    time TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """)
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.before_request
def before_request():
    session.permanent = True

@app.teardown_appcontext
def teardown_appcontext(e=None):
    close_db()

@app.route("/")
def home_button():
    return render_template("index.html")

@app.route("/about")
def about_button():
    return render_template("about.html")

@app.route("/login", methods=["GET", "POST"])
def login_button():
    db = get_db()
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        with db:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            user = cursor.fetchone()
            print(user)
        

            if user and check_password_hash(user[3], password):
                session['username'] = username
                if username == 'admin':
                    session['type'] = 'admin'
                else:
                    session['type'] = 'user'
                session['userID'] = user[0]
                return redirect("/")
            else:
                error_message = "Invalid username or password"
                return render_template("login.html", error_message=error_message)
    return render_template("login.html")



@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register_button():
    db = get_db()
    cursor = db.cursor()

    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

        if user:
            error_message = "Username already taken"
            return render_template("register.html", error_message=error_message)
        else:
            hashed_password = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, email, password, type) VALUES (?, ?, ?, ?)", (username, email, hashed_password, "user"))
            db.commit()
            return redirect("/")
        
    return render_template("register.html")


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        user_id = cursor.fetchone()
        if user_id:
            session['reset_password_user_id'] = user_id[0]
            return redirect('/reset_password')
        else:
            error_message = "No account found with that email"
            return render_template('forgot_password.html', error_message=error_message)
    return render_template('forgot_password.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_password_user_id' not in session:
        return redirect('/forgot_password')
    if request.method == 'POST':
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        user_id = session['reset_password_user_id']
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user_id))
        conn.commit()
        session.pop('reset_password_user_id', None)
        return redirect('/', code=302)
    return render_template('reset_password.html')

@app.route("/booking", methods=["GET", "POST"])
def booking():
    if "username" not in session:
        return redirect("/login")
    if request.method == "POST":
        date = request.form["date"]
        time = request.form["time"]
        username = session["username"]
        db = get_db()
        with db:
            cursor = db.cursor()
            cursor.execute("SELECT id FROM users WHERE username=?", (username,))
            user_id = cursor.fetchone()[0]
            cursor.execute("INSERT INTO bookings (user_id, date, time) VALUES (?, ?, ?)", (user_id, date, time))
            db.commit()
            success_message = "Booking successful"
            return render_template("booking.html", success_message=success_message)
    return render_template("booking.html")

@app.route("/manage_bookings", methods=["GET", "POST"])
def manage_bookings():
    if "username" not in session:
        return redirect("/login")
    db = get_db()
    with db:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM  bookings WHERE status = ?",('pending',))
        bookings = cursor.fetchall()
        if request.method == "POST":
            booking_id = request.form["booking_id"]
            status = request.form["status"]
            cursor.execute("UPDATE bookings SET status=? WHERE id=?", (status, booking_id))
            db.commit()
            success_message = "Booking status updated"
            return render_template("manage.html", bookings=bookings, success_message=success_message)
    return render_template("manage.html", bookings=bookings)

@app.route("/accepted_bookings")
def accepted_orders():
    db = get_db()
    with db:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM bookings WHERE user_id = ? AND status = ?", (session['userID'],'accepted'))
        bookings = cursor.fetchall()
    return render_template('accepted_booking.html', bookings = bookings)

@app.route("/pending_bookings")
def pending_orders():
    db = get_db()
    with db:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM bookings WHERE user_id = ? AND status = ?", (session['userID'],'pending'))
        bookings = cursor.fetchall()
    print(session['userID'])
    return render_template('pending_booking.html', bookings = bookings)

@app.route("/accepted_manage")
def accepted_manage():
    db = get_db()
    with db:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM bookings WHERE status = ?", ('accepted',))
        bookings = cursor.fetchall()
    return render_template('accepted_manage.html', bookings = bookings)
@app.route("/declined_manage")
def declined_bookings():
    db = get_db()
    with db:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM bookings WHERE status = ?", ('declined',))
        bookings = cursor.fetchall()
    return render_template('declined_manage.html', bookings = bookings)
if __name__ == '__main__':
    app.run(debug=True,)