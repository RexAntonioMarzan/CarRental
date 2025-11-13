from flask import Flask, render_template, request, redirect, session, flash, url_for
import sqlite3
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import jsonify

app = Flask(__name__)
app.secret_key = "supersecretkey"


# ---------- DATABASE SETUP ----------
def get_db():
    conn = sqlite3.connect("car_rental.db", timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def seed_cars(cursor):
    cars = [
        ("Toyota Vios", "Sedan", 1800, "https://images.unsplash.com/photo-1503736334956-4c8f8e92946d?auto=format&fit=crop&w=900&q=80"),
        ("Honda Civic", "Sedan", 2100, "https://images.unsplash.com/photo-1483721310020-03333e577078?auto=format&fit=crop&w=900&q=80"),
        ("Toyota Camry", "Sedan", 2700, "https://images.unsplash.com/photo-1523983306434-1ffd58dd89ea?auto=format&fit=crop&w=900&q=80"),
        ("Nissan Almera", "Sedan", 1700, "https://images.unsplash.com/photo-1503376780353-7e6692767b70?auto=format&fit=crop&w=900&q=80"),
        ("Honda BR-V", "MPV", 2300, "https://images.unsplash.com/photo-1542281286-9e0a16bb7366?auto=format&fit=crop&w=900&q=80"),
        ("Suzuki Ertiga", "MPV", 2150, "https://images.unsplash.com/photo-1589391886645-d51941baf7fb?auto=format&fit=crop&w=900&q=80"),
        ("Toyota Innova", "MPV", 2600, "https://images.unsplash.com/photo-1525609004556-c46c7d6cf023?auto=format&fit=crop&w=900&q=80"),
        ("Hyundai Staria", "Van", 3400, "https://images.unsplash.com/photo-1493238792000-8113da705763?auto=format&fit=crop&w=900&q=80"),
        ("Mitsubishi L300", "Van", 3000, "https://images.unsplash.com/photo-1511919884226-fd3cad34687c?auto=format&fit=crop&w=900&q=80"),
        ("Toyota Hiace", "Van", 3200, "https://images.unsplash.com/photo-1517142089942-ba376ce32a0b?auto=format&fit=crop&w=900&q=80"),
        ("Ford Ranger", "Pickup", 3500, "https://images.unsplash.com/photo-1523987355523-c7b5b84f07d4?auto=format&fit=crop&w=900&q=80"),
        ("Nissan Navara", "Pickup", 3350, "https://images.unsplash.com/photo-1502872364588-894d7d9b86f2?auto=format&fit=crop&w=900&q=80"),
        ("Isuzu D-Max", "Pickup", 3300, "https://images.unsplash.com/photo-1549923746-c502d488b3ea?auto=format&fit=crop&w=900&q=80"),
        ("Toyota Fortuner", "SUV", 3600, "https://images.unsplash.com/photo-1519641471654-76ce0107ad1b?auto=format&fit=crop&w=900&q=80"),
        ("Ford Everest", "SUV", 3700, "https://images.unsplash.com/photo-1517487881594-2787fef5ebf7?auto=format&fit=crop&w=900&q=80"),
        ("Mazda CX-5", "SUV", 2800, "https://images.unsplash.com/photo-1620891549027-942fdc95d9ea?auto=format&fit=crop&w=900&q=80"),
        ("Honda CR-V", "SUV", 2950, "https://images.unsplash.com/photo-1502877338535-766e1452684a?auto=format&fit=crop&w=900&q=80"),
        ("Subaru Forester", "SUV", 3100, "https://images.unsplash.com/photo-1600240644455-c24dc6cc3f98?auto=format&fit=crop&w=900&q=80"),
        ("BMW 3 Series", "Sedan", 5200, "https://images.unsplash.com/photo-1553440569-bcc63803a83d?auto=format&fit=crop&w=900&q=80"),
        ("Mercedes-Benz GLC", "SUV", 6000, "https://images.unsplash.com/photo-1519642918688-7e43b19245d8?auto=format&fit=crop&w=900&q=80"),
    ]

    for name, car_type, price, image_url in cars:
        cursor.execute("SELECT 1 FROM cars WHERE name = ?", (name,))
        if cursor.fetchone():
            continue
        cursor.execute(
            "INSERT INTO cars (name, car_type, price_per_day, image_url) VALUES (?, ?, ?, ?)",
            (name, car_type, price, image_url),
        )


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS cars(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            car_type TEXT NOT NULL,
            price_per_day REAL NOT NULL,
            image_url TEXT
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS bookings(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            car_id INTEGER,
            days INTEGER,
            total_price REAL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (car_id) REFERENCES cars(id)
        )
    """
    )

    cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
            ("admin", generate_password_hash("admin123")),
        )

    seed_cars(cursor)

    conn.commit()
    conn.close()


init_db()


# ---------- HELPERS ----------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "info")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Administrator access required.", "danger")
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    return wrapped


@app.context_processor
def inject_user_state():
    return {
        "is_authenticated": "user_id" in session,
        "is_admin": session.get("is_admin", False),
        "current_username": session.get("username"),
        "current_year": datetime.utcnow().year,
    }


# ---------- AUTH ----------
@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("is_admin"):
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("gallery"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            flash("Login successful.", "success")
            return redirect(url_for("index"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("register.html")

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            conn.commit()
            flash("Registration successful. You can now log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists.", "danger")
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


# ---------- USER SIDE ----------
@app.route("/home")
@login_required
def user_home():
    return render_template("home.html")


@app.route("/gallery")
@login_required
def gallery():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cars ORDER BY name")
    cars = cursor.fetchall()
    conn.close()
    return render_template("gallery.html", cars=cars)


@app.route("/book/<int:car_id>", methods=["GET", "POST"])
@login_required
def book(car_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cars WHERE id = ?", (car_id,))
    car = cursor.fetchone()

    if not car:
        conn.close()
        flash("Car not found.", "danger")
        return redirect(url_for("gallery"))

    if request.method == "POST":
        try:
            days = int(request.form["days"])
        except (TypeError, ValueError):
            flash("Enter a valid number of days.", "danger")
            return render_template("book.html", car=car)

        if days <= 0:
            flash("Days must be at least 1.", "danger")
            return render_template("book.html", car=car)

        total = days * car["price_per_day"]
        cursor.execute(
            "INSERT INTO bookings (user_id, car_id, days, total_price) VALUES (?, ?, ?, ?)",
            (session["user_id"], car_id, days, total),
        )
        conn.commit()
        conn.close()
        flash(f"Booking confirmed for {car['name']}.", "success")
        return redirect(url_for("history"))

    conn.close()
    return render_template("book.html", car=car)


@app.route("/history")
@login_required
def history():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT b.id, c.name AS car_name, c.car_type, b.days, b.total_price
        FROM bookings b
        JOIN cars c ON b.car_id = c.id
        WHERE b.user_id = ?
        ORDER BY b.id DESC
    """,
        (session["user_id"],),
    )
    bookings = cursor.fetchall()
    conn.close()
    return render_template("history.html", bookings=bookings)


@app.route("/cancel/<int:booking_id>", methods=["POST"])
@login_required
def cancel_booking(booking_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM bookings WHERE id = ? AND user_id = ?",
        (booking_id, session["user_id"]),
    )
    deleted = cursor.rowcount
    conn.commit()
    conn.close()

    if deleted:
        flash("Booking cancelled.", "info")
    else:
        flash("Unable to cancel booking.", "danger")

    return redirect(url_for("history"))


# ---------- ADMIN SIDE ----------
@app.route("/profile")
@login_required
def user_profile():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (session["user_id"],))
    user = cursor.fetchone()

    cursor.execute("SELECT COUNT(*) FROM bookings WHERE user_id = ?", (session["user_id"],))
    booking_count = cursor.fetchone()[0]

    cursor.execute("SELECT IFNULL(SUM(total_price), 0) FROM bookings WHERE user_id = ?", (session["user_id"],))
    total_spent = cursor.fetchone()[0] or 0

    cursor.execute(
        """
        SELECT b.id, c.name AS car_name, b.days, b.total_price
        FROM bookings b JOIN cars c ON b.car_id = c.id
        WHERE b.user_id = ? ORDER BY b.id DESC LIMIT 5
        """,
        (session["user_id"],),
    )
    recent = cursor.fetchall()
    conn.close()

    stats = {"booking_count": booking_count, "total_spent": total_spent}
    return render_template("user_profile.html", user=user, stats=stats, recent=recent)

@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM cars")
    car_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM bookings")
    booking_count = cursor.fetchone()[0]

    cursor.execute("SELECT IFNULL(SUM(total_price), 0) FROM bookings")
    revenue = cursor.fetchone()[0] or 0

    cursor.execute(
        """
        SELECT b.id, u.username, c.name AS car_name, b.days, b.total_price
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        JOIN cars c ON b.car_id = c.id
        ORDER BY b.id DESC
        LIMIT 5
    """
    )
    recent_bookings = cursor.fetchall()
    conn.close()

    stats = {
        "car_count": car_count,
        "booking_count": booking_count,
        "revenue": revenue,
    }

    return render_template(
        "admin_dashboard.html", stats=stats, recent_bookings=recent_bookings
    )


@app.route("/admin/cars")
@admin_required
def admin_cars():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cars ORDER BY name")
    cars = cursor.fetchall()
    conn.close()
    return render_template("admin_cars.html", cars=cars)


@app.route("/admin/cars/new", methods=["GET", "POST"])
@admin_required
def admin_add_car():
    if request.method == "POST":
        name = request.form["name"].strip()
        car_type = request.form["car_type"].strip()
        price_raw = request.form["price_per_day"].strip()
        image_url = request.form.get("image_url", "").strip() or None

        if not name or not car_type or not price_raw:
            flash("All fields except image URL are required.", "danger")
            return render_template(
                "admin_car_form.html",
                action="Add",
                car={"name": name, "car_type": car_type, "price_per_day": price_raw, "image_url": image_url or ""},
            )

        try:
            price = float(price_raw)
        except ValueError:
            flash("Enter a valid price.", "danger")
            return render_template(
                "admin_car_form.html",
                action="Add",
                car={"name": name, "car_type": car_type, "price_per_day": price_raw, "image_url": image_url or ""},
            )

        if price <= 0:
            flash("Price must be greater than zero.", "danger")
            return render_template(
                "admin_car_form.html",
                action="Add",
                car={"name": name, "car_type": car_type, "price_per_day": price_raw, "image_url": image_url or ""},
            )

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO cars (name, car_type, price_per_day, image_url) VALUES (?, ?, ?, ?)",
            (name, car_type, price, image_url),
        )
        conn.commit()
        conn.close()
        flash(f"{name} added to inventory.", "success")
        return redirect(url_for("admin_cars"))

    return render_template("admin_car_form.html", action="Add", car=None)


@app.route("/admin/cars/<int:car_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_car(car_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cars WHERE id = ?", (car_id,))
    car = cursor.fetchone()

    if not car:
        conn.close()
        flash("Car not found.", "danger")
        return redirect(url_for("admin_cars"))

    if request.method == "POST":
        name = request.form["name"].strip()
        car_type = request.form["car_type"].strip()
        price_raw = request.form["price_per_day"].strip()
        image_url = request.form.get("image_url", "").strip() or None

        if not name or not car_type or not price_raw:
            flash("All fields except image URL are required.", "danger")
            return render_template(
                "admin_car_form.html",
                action="Edit",
                car={"id": car_id, "name": name, "car_type": car_type, "price_per_day": price_raw, "image_url": image_url or ""},
            )

        try:
            price = float(price_raw)
        except ValueError:
            flash("Enter a valid price.", "danger")
            return render_template(
                "admin_car_form.html",
                action="Edit",
                car={"id": car_id, "name": name, "car_type": car_type, "price_per_day": price_raw, "image_url": image_url or ""},
            )

        if price <= 0:
            flash("Price must be greater than zero.", "danger")
            return render_template(
                "admin_car_form.html",
                action="Edit",
                car={"id": car_id, "name": name, "car_type": car_type, "price_per_day": price_raw, "image_url": image_url or ""},
            )

        cursor.execute(
            """
            UPDATE cars
            SET name = ?, car_type = ?, price_per_day = ?, image_url = ?
            WHERE id = ?
        """,
            (name, car_type, price, image_url, car_id),
        )
        conn.commit()
        conn.close()
        flash(f"{name} updated.", "success")
        return redirect(url_for("admin_cars"))

    car_dict = dict(car)
    conn.close()
    return render_template("admin_car_form.html", action="Edit", car=car_dict)


@app.route("/admin/cars/<int:car_id>/delete", methods=["POST"])
@admin_required
def admin_delete_car(car_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cars WHERE id = ?", (car_id,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()

    if deleted:
        flash("Car removed from inventory.", "info")
    else:
        flash("Car not found.", "danger")

    return redirect(url_for("admin_cars"))


@app.route("/admin/bookings")
@admin_required
def admin_bookings():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT b.id, u.username, c.name AS car_name, b.days, b.total_price
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        JOIN cars c ON b.car_id = c.id
        ORDER BY b.id DESC
    """
    )
    bookings = cursor.fetchall()
    conn.close()
    return render_template("admin_bookings.html", bookings=bookings)


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)

# -------------------- JSON API (Full-stack endpoints) --------------------
# Cars API
@app.route("/api/cars", methods=["GET"])
@login_required
def api_list_cars():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cars ORDER BY name")
    cars = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(cars), 200


@app.route("/api/cars/<int:car_id>", methods=["GET"])
@login_required
def api_get_car(car_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cars WHERE id = ?", (car_id,))
    car = cursor.fetchone()
    conn.close()
    if not car:
        return jsonify({"error": "Not found"}), 404
    return jsonify(dict(car)), 200


@app.route("/api/cars", methods=["POST"])
@admin_required
def api_create_car():
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    car_type = (payload.get("car_type") or "").strip()
    price_per_day = payload.get("price_per_day")
    image_url = (payload.get("image_url") or "").strip() or None
    if not name or not car_type or price_per_day is None:
        return jsonify({"error": "name, car_type, price_per_day required"}), 400
    try:
        price = float(price_per_day)
        if price <= 0:
            raise ValueError()
    except Exception:
        return jsonify({"error": "price_per_day must be a positive number"}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO cars (name, car_type, price_per_day, image_url) VALUES (?, ?, ?, ?)",
        (name, car_type, price, image_url),
    )
    conn.commit()
    new_id = cursor.lastrowid
    cursor.execute("SELECT * FROM cars WHERE id = ?", (new_id,))
    created = dict(cursor.fetchone())
    conn.close()
    return jsonify(created), 201


@app.route("/api/cars/<int:car_id>", methods=["PUT", "PATCH"])
@admin_required
def api_update_car(car_id):
    payload = request.get_json(silent=True) or {}
    fields = []
    values = []
    for key in ("name", "car_type", "image_url"):
        if key in payload:
            fields.append(f"{key} = ?")
            values.append((payload.get(key) or "").strip() or None)
    if "price_per_day" in payload:
        try:
            price = float(payload.get("price_per_day"))
            if price <= 0:
                raise ValueError()
        except Exception:
            return jsonify({"error": "price_per_day must be a positive number"}), 400
        fields.append("price_per_day = ?")
        values.append(price)

    if not fields:
        return jsonify({"error": "No valid fields to update"}), 400

    conn = get_db()
    cursor = conn.cursor()
    values.append(car_id)
    cursor.execute(f"UPDATE cars SET {', '.join(fields)} WHERE id = ?", values)
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    conn.commit()
    cursor.execute("SELECT * FROM cars WHERE id = ?", (car_id,))
    updated = dict(cursor.fetchone())
    conn.close()
    return jsonify(updated), 200


@app.route("/api/cars/<int:car_id>", methods=["DELETE"])
@admin_required
def api_delete_car(car_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cars WHERE id = ?", (car_id,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    if not deleted:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"status": "deleted"}), 200


# Bookings API
@app.route("/api/my/bookings", methods=["GET"])
@login_required
def api_my_bookings():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT b.id, c.name AS car_name, c.car_type, b.days, b.total_price
        FROM bookings b
        JOIN cars c ON b.car_id = c.id
        WHERE b.user_id = ?
        ORDER BY b.id DESC
    """,
        (session["user_id"],),
    )
    data = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(data), 200


@app.route("/api/bookings", methods=["GET"])
@admin_required
def api_all_bookings():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT b.id, u.username, c.name AS car_name, b.days, b.total_price
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        JOIN cars c ON b.car_id = c.id
        ORDER BY b.id DESC
    """
    )
    data = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(data), 200


@app.route("/api/bookings", methods=["POST"])
@login_required
def api_create_booking():
    payload = request.get_json(silent=True) or {}
    car_id = payload.get("car_id")
    days = payload.get("days")
    try:
        car_id = int(car_id)
        days = int(days)
    except Exception:
        return jsonify({"error": "car_id and days must be integers"}), 400
    if days <= 0:
        return jsonify({"error": "days must be at least 1"}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cars WHERE id = ?", (car_id,))
    car = cursor.fetchone()
    if not car:
        conn.close()
        return jsonify({"error": "Car not found"}), 404

    total = days * float(car["price_per_day"])
    cursor.execute(
        "INSERT INTO bookings (user_id, car_id, days, total_price) VALUES (?, ?, ?, ?)",
        (session["user_id"], car_id, days, total),
    )
    conn.commit()
    booking_id = cursor.lastrowid
    cursor.execute(
        "SELECT id, user_id, car_id, days, total_price FROM bookings WHERE id = ?",
        (booking_id,),
    )
    created = dict(cursor.fetchone())
    conn.close()
    return jsonify(created), 201


@app.route("/api/my/bookings/<int:booking_id>", methods=["DELETE"])
@login_required
def api_cancel_my_booking(booking_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM bookings WHERE id = ? AND user_id = ?",
        (booking_id, session["user_id"]),
    )
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    if not deleted:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"status": "cancelled"}), 200


