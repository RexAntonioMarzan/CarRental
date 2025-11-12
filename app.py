from flask import Flask, render_template, request, redirect, session, flash, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ---------- DATABASE SETUP ----------
def get_db():
    return sqlite3.connect('car_rental.db', timeout=10, check_same_thread=False)

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # USERS
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    ''')

    # CARS
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cars(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            car_type TEXT NOT NULL,
            price_per_day REAL NOT NULL,
            image_url TEXT
        )
    ''')

    # BOOKINGS
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bookings(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            car_id INTEGER,
            days INTEGER,
            total_price REAL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (car_id) REFERENCES cars(id)
        )
    ''')

    # Create default admin if none exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin=1")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
                       ("admin", generate_password_hash("admin123")))

    conn.commit()
    conn.close()

init_db()

# ---------- AUTH ----------
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect('/login')
    if session.get('is_admin'):
        return redirect('/admin')
    return render_template('home.html', username=session['username'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['is_admin'] = bool(user[3])
            flash("Login successful!", "success")
            return redirect('/')
        else:
            flash("Invalid username or password.", "danger")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                           (username, generate_password_hash(password)))
            conn.commit()
            flash("Registration successful!", "success")
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash("Username already exists.", "danger")
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect('/login')

# ---------- USER SIDE ----------
@app.route('/')
def gallery():
    cars = [
        (1, "Toyota Vios", "Sedan", 1800, "vios.jpg"),
        (2, "Honda CR-V", "SUV", 2500, "crv.jpg"),
        (3, "Mitsubishi L300", "Van", 3000, "l300.jpg")
    ]
    return render_template('gallery.html', cars=cars)


@app.route('/book/<int:car_id>', methods=['GET', 'POST'])
def book(car_id):
    if 'user_id' not in session:
        return redirect('/login')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cars WHERE id=?", (car_id,))
    car = cursor.fetchone()

    if request.method == 'POST':
        days = int(request.form['days'])
        total = days * car[3]
        cursor.execute("INSERT INTO bookings (user_id, car_id, days, total_price) VALUES (?, ?, ?, ?)",
                       (session['user_id'], car_id, days, total))
        conn.commit()
        conn.close()
        flash(f"Booking confirmed! Total ₱{total}", "success")
        return redirect('/history')

    conn.close()
    return render_template('book.html', car=car)

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect('/login')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT b.id, c.name, c.car_type, b.days, b.total_price
        FROM bookings b
        JOIN cars c ON b.car_id = c.id
        WHERE b.user_id=?
    ''', (session['user_id'],))
    bookings = cursor.fetchall()
    conn.close()
    return render_template('history.html', bookings=bookings)

@app.route('/cancel/<int:booking_id>')
def cancel_booking(booking_id):
    if 'user_id' not in session:
        return redirect('/login')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM bookings WHERE id=? AND user_id=?", (booking_id, session['user_id']))
    conn.commit()
    conn.close()
    flash("Booking cancelled successfully!", "info")
    return redirect('/history')

# ---------- ADMIN SIDE ----------
@app.route('/admin')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect('/')
    return render_template('admin_dashboard.html')

@app.route('/admin/cars')
def admin_cars():
    if not session.get('is_admin'):
        return redirect('/')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cars")
    cars = cursor.fetchall()
    conn.close()
    return render_template('admin_cars.html', cars=cars)

@app.route('/admin/add_car', methods=['GET', 'POST'])
def add_car():
    if not session.get('is_admin'):
        return redirect('/')
    if request.method == 'POST':
        name = request.form['name']
        ctype = request.form['car_type']
        price = float(request.form['price'])
        image = request.form['image_url']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO cars (name, car_type, price_per_day, image_url) VALUES (?, ?, ?, ?)",
                       (name, ctype, price, image))
        conn.commit()
        conn.close()
        flash("Car added successfully!", "success")
        return redirect('/admin/cars')
    return render_template('add_car.html')

@app.route('/admin/delete_car/<int:car_id>')
def delete_car(car_id):
    if not session.get('is_admin'):
        return redirect('/')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cars WHERE id=?", (car_id,))
    conn.commit()
    conn.close()
    flash("Car deleted.", "info")
    return redirect('/admin/cars')

@app.route('/admin/bookings')
def admin_bookings():
    if not session.get('is_admin'):
        return redirect('/')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT b.id, u.username, c.name, b.days, b.total_price
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        JOIN cars c ON b.car_id = c.id
    ''')
    bookings = cursor.fetchall()
    conn.close()
    return render_template('admin_bookings.html', bookings=bookings)

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)


