# app.py Fakemon -- Nancy Burgos 2025
# Vulnerabilities included:
#  - SQL Injection in /search (unparameterized query)
#  - Stored XSS via comment content (rendered unsafely with |safe in templates)
#  - Reflected XSS via echoed query param on some templates
#  - Broken access control / IDOR via client-controlled cookie and simple admin token
#  - Weak authentication: login sets client-trustable cookie w/o password checks
#

from flask import Flask, g, render_template, request, redirect, url_for, make_response, abort, jsonify, send_from_directory
import sqlite3
import os
import json

APP_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(APP_DIR, "cards.db")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config['DATABASE'] = DB_PATH
app.config['DEBUG'] = False

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
        g._database = db
    return db

@app.teardown_appcontext
def close_connection(exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/cards")
def cards_json():
    """
    Returns JSON list of cards used by the front-end deck.
    """
    db = get_db()
    rows = db.execute("SELECT id, name, type, price, description, image FROM cards WHERE image != '/static/images/card_00.jpg' LIMIT 50").fetchall()
    cards = []
    for r in rows:
        price = r["price"] if r["price"] else 0
        cards.append({
            "id": r["id"],
            "name": r["name"],
            "type": r["type"] or "Unknown",
            "price": f"{price:.2f}",
            "description": r["description"],
            "image": r["image"] or "/static/images/placeholder.png"
        })
    return jsonify({"cards": cards})

@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()

    query = f"SELECT id, name, type, price, description, image FROM cards WHERE name LIKE '%{q}%' AND image != '/static/images/card_00.jpg'"
    try:
        rows = db.execute(query).fetchall()
        formatted_results = []
        for r in rows:
            row_dict = dict(r)
            price = row_dict.get("price", 0)
            row_dict["price"] = f"{price:.2f}"
            formatted_results.append(row_dict)
        rows = formatted_results
    except Exception as e:
        print("DB error in search:", e)
        rows = []
    return render_template("search.html", q=q, results=rows)

@app.route("/cards/<int:card_id>")
def view_card(card_id):
    db = get_db()
    card = db.execute("SELECT * FROM cards WHERE id = ?", (card_id,)).fetchone()
    if not card:
        abort(404)
    comments = db.execute("SELECT * FROM comments WHERE card_id = ?", (card_id,)).fetchall()
    card_dict = dict(card)
    card_dict["image_url"] = card_dict.get("image", "/static/images/placeholder.png")
    card_dict["type"] = card_dict.get("type", "Unknown")
    price = card_dict.get("price", 0)
    card_dict["price"] = f"{price:.2f}"
    return render_template("card.html", card=card_dict, comments=comments)

@app.route("/cards/<int:card_id>/comment", methods=["GET", "POST"])
def comment(card_id):
    """
    POST stores comment content as-is (no sanitization).
    Template renders comment content with |safe — stored XSS.
    """
    db = get_db()
    card = db.execute("SELECT * FROM cards WHERE id = ?", (card_id,)).fetchone()
    if not card:
        abort(404)
    if request.method == "POST":
        author = request.form.get("user", "anon")
        content = request.form.get("text", "")
        db.execute("INSERT INTO comments (card_id, user, text) VALUES (?, ?, ?)",
                   (card_id, author, content))
        db.commit()
        return redirect(url_for("view_card", card_id=card_id))
    comments = db.execute("SELECT * FROM comments WHERE card_id = ?", (card_id,)).fetchall()
    card_dict = dict(card)
    card_dict["image_url"] = card_dict.get("image", "/static/images/placeholder.png")
    card_dict["type"] = card_dict.get("type", "Unknown")
    price = card_dict.get("price", 0)
    card_dict["price"] = f"{price:.2f}"
    return render_template("comment.html", card=card_dict, comments=comments)

@app.route("/register", methods=["GET", "POST"])
def register():

    error = None
    success = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        db = get_db()
        
        if not username:
            error = "Username is required"
        elif len(username) < 3:
            error = "Username must be at least 3 characters long"
        elif not password:
            error = "Password is required"
        elif len(password) < 6:
            error = "Password must be at least 6 characters long"
        elif password != confirm_password:
            error = "Passwords do not match"
        else:
            try:
                existing = db.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchone()
                if existing:
                    error = f"Registration failed: The username '{username}' is already in use. Please choose a different username."
                else:
                    db.execute("INSERT INTO users (username, password, role, credits) VALUES (?, ?, ?, ?)",
                             (username, password, "user", 0))
                    db.commit()
                    success = f"Account created successfully for '{username}'! You can now login."
            except sqlite3.IntegrityError:
                error = f"Registration failed: The username '{username}' is already registered in our system. Please choose a different username or try logging in instead."
            except Exception as e:
                error = f"Registration failed: {str(e)}. Please contact support if this issue persists."
    
    return render_template("register.html", error=error, success=success)

@app.route("/login", methods=["GET", "POST"])
def login():
    """
   LOGIN:
    - Passwords compared in PLAINTEXT (no hashing)
    - Weak password validation (can be bypassed)
    - Username enumeration possible through error messages
    - No rate limiting (brute force possible)
    - Session management via insecure cookies
    """
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        db = get_db()
        
        user = db.execute("SELECT id, username, password, role FROM users WHERE username = ?", 
                         (username,)).fetchone()
        
        if user:
            stored_password = user["password"] if user["password"] else ""
            
            if stored_password and password == stored_password:
                next_url = request.args.get("next", url_for("index"))
                resp = make_response(redirect(next_url))
                if user["role"] == "admin":
                    resp.set_cookie("is_admin", "1")
                else:
                    resp.set_cookie("is_admin", "0")
                resp.set_cookie("user_id", str(user["id"]))
                resp.set_cookie("username", user["username"])
                return resp
            elif not stored_password:
                next_url = request.args.get("next", url_for("index"))
                resp = make_response(redirect(next_url))
                if username == "admin" or user["role"] == "admin":
                    resp.set_cookie("is_admin", "1")
                else:
                    resp.set_cookie("is_admin", "0")
                resp.set_cookie("user_id", str(user["id"]))
                resp.set_cookie("username", user["username"])
                return resp
            else:
                error = f"Incorrect password for user '{username}'. Please try again."
        else:
            error = f"Username '{username}' not found. Please check your username and try again."
    
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("index")))
    resp.set_cookie("is_admin", "0", expires=0)
    resp.set_cookie("user_id", "", expires=0)
    resp.set_cookie("username", "", expires=0)
    return resp

def admin_check():
    is_admin_cookie = request.cookies.get("is_admin", "0")
    token = request.args.get("admin_token", "")
    if is_admin_cookie == "1" or token == "letmein123":
        return True
    return False

@app.route("/admin")
def admin_panel():
    if not admin_check():
        return "Access denied", 403
    db = get_db()
    users = db.execute("SELECT id, username, role FROM users").fetchall()
    cards = db.execute("SELECT id, name, price FROM cards").fetchall()
    error = request.args.get("error")
    return render_template("admin.html", users=users, cards=cards, error=error)

@app.route("/admin/delete_user/<int:user_id>")
def admin_delete_user(user_id):
    if not admin_check():
        return "Access denied", 403
    current_user_id = request.cookies.get("user_id")
    if current_user_id and str(user_id) == current_user_id:
        return redirect(url_for("admin_panel", error="Cannot delete yourself"))
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return redirect(url_for("admin_panel"))

@app.route("/admin/delete_card/<int:card_id>")
def admin_delete_card(card_id):
    if not admin_check():
        return "Access denied", 403
    db = get_db()
    db.execute("DELETE FROM cards WHERE id = ?", (card_id,))
    db.commit()
    return redirect(url_for("admin_panel"))

@app.route("/_dump/users")
def dump_users():

    db = get_db()
    rows = db.execute("SELECT id, username, password, role FROM users").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/lab-guide.pdf")
def lab_guide():
    """Serve the Fakemon Full Lab Guide PDF."""
    return send_from_directory(APP_DIR, "Fakemon-Full_Lab_Guide.pdf", mimetype="application/pdf")

def get_cart():

    cart_cookie = request.cookies.get("cart", "{}")
    try:
        return json.loads(cart_cookie)
    except:
        return {}

def set_cart(resp, cart):

    resp.set_cookie("cart", json.dumps(cart))
    return resp

@app.route("/cart/add/<int:card_id>", methods=["POST"])
def add_to_cart(card_id):

    if not request.cookies.get("user_id"):
        return redirect(url_for("login") + "?next=" + url_for("view_cart"))
    
    db = get_db()
    card = db.execute("SELECT * FROM cards WHERE id = ?", (card_id,)).fetchone()
    if not card:
        abort(404)
    
    quantity = request.form.get("quantity", "1")
    try:
        quantity = int(quantity)
    except (ValueError, TypeError):
        quantity = 1
    
    cart = get_cart()
    
    if str(card_id) in cart:
        new_quantity = cart[str(card_id)] + quantity
        if new_quantity == 0:
            del cart[str(card_id)]
        else:
            cart[str(card_id)] = new_quantity
    else:
        if quantity != 0:
            cart[str(card_id)] = quantity
    
    resp = make_response(redirect(url_for("view_cart")))
    return set_cart(resp, cart)

@app.route("/cart")
def view_cart():

    user_id = request.cookies.get("user_id")
    if not user_id:
        return redirect(url_for("login") + "?next=" + url_for("view_cart"))
    
    cart = get_cart()
    db = get_db()
    
    user = db.execute("SELECT credits FROM users WHERE id = ?", (user_id,)).fetchone()
    user_credits_value = user["credits"] if user and user["credits"] is not None else 0
    user_credits = f"{user_credits_value:.2f}"
    
    cart_items = []
    total = 0.0
    
    for card_id_str, quantity in cart.items():
        try:
            card_id = int(card_id_str)
            card = db.execute("SELECT * FROM cards WHERE id = ?", (card_id,)).fetchone()
            if card:
                price = float(card["price"] or 0)
                line_total = price * quantity
                total += line_total
                cart_items.append({
                    "card": dict(card),
                    "quantity": quantity,
                    "price": f"{price:.2f}",
                    "line_total": f"{line_total:.2f}"
                })
        except (ValueError, TypeError):
            continue
    
    success_message = None
    if request.args.get("success") == "1":
        success_message = "Thank you for your purchase! Your order has been placed successfully!"
    
    return render_template("cart.html", cart_items=cart_items, total=f"{total:.2f}", 
                         user_credits=user_credits, success_message=success_message)

@app.route("/cart/update", methods=["POST"])
def update_cart():

    cart = get_cart()
    
    for card_id_str in request.form:
        try:
            card_id = int(card_id_str)
            quantity = request.form.get(card_id_str, "0")
            quantity = int(quantity)
            
            if quantity == 0:
                if str(card_id) in cart:
                    del cart[str(card_id)]
            else:
                cart[str(card_id)] = quantity
        except (ValueError, TypeError):
            continue
    
    resp = make_response(redirect(url_for("view_cart")))
    return set_cart(resp, cart)

@app.route("/cart/remove/<int:card_id>")
def remove_from_cart(card_id):
    cart = get_cart()
    if str(card_id) in cart:
        del cart[str(card_id)]
    resp = make_response(redirect(url_for("view_cart")))
    return set_cart(resp, cart)

@app.route("/cart/clear")
def clear_cart():
    resp = make_response(redirect(url_for("view_cart")))
    resp.set_cookie("cart", "{}")
    return resp

@app.route("/checkout", methods=["POST"])
def checkout():

    user_id = request.cookies.get("user_id")
    if not user_id:
        return redirect(url_for("login") + "?next=" + url_for("view_cart"))
    
    cart = get_cart()
    db = get_db()
    
    total = 0.0
    for card_id_str, quantity in cart.items():
        try:
            card_id = int(card_id_str)
            card = db.execute("SELECT * FROM cards WHERE id = ?", (card_id,)).fetchone()
            if card:
                price = float(card["price"] or 0)
                line_total = price * quantity
                total += line_total
        except (ValueError, TypeError):
            continue
    
    user = db.execute("SELECT credits FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return redirect(url_for("login") + "?next=" + url_for("view_cart"))
    
    user_credits = user["credits"] or 0
    
    if total > 0 and user_credits < total:
        return redirect(url_for("view_cart", error="insufficient_credits"))
    
    if total != 0:
        new_credits = user_credits - total
        db.execute("UPDATE users SET credits = ? WHERE id = ?", (new_credits, user_id))
        db.commit()
    
    resp = make_response(redirect(url_for("view_cart", success="1")))
    resp.set_cookie("cart", "{}")
    return resp

if __name__ == "__main__":
    if not os.path.exists(app.config['DATABASE']):
        print("Database not found. Please run your init_db.py to create cards.db before starting the app.")
    else:
        app.run(host="0.0.0.0", port=5000, debug=app.config['DEBUG'])
