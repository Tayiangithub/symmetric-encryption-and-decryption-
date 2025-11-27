import os
from flask import Flask, request, render_template, send_from_directory, redirect, url_for, session, flash
from encryption import encrypt_file, decrypt_file
from database import (
    init_db, fix_roles, register_user, validate_user, user_exists,
    add_log, get_logs, get_user_logs,
    get_all_users, update_user_role, delete_user
)

UPLOAD_FOLDER = "uploads"
PROCESSED_FOLDER = "processed"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "supersecretkey_change_me")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROCESSED_FOLDER'] = PROCESSED_FOLDER

# Initialize DB and migrations
init_db()
fix_roles()

# Create default admin only if not exists
if not user_exists("admin"):
    register_user("admin", "admin123", role="admin", first_name="System", second_name="Admin")
    print("Created default admin -> username: admin password: admin123")

# ---------- Routes ----------

@app.route("/")
def home():
    if "username" in session:
        return render_template(
            "index.html",
            user=session.get("username"),
            role=session.get("role", "user"),
            first_name=session.get("first_name"),
            second_name=session.get("second_name")
        )
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        first_name = request.form.get("first_name", "").strip()
        second_name = request.form.get("second_name", "").strip()

        if not username or not password or not confirm_password or not first_name or not second_name:
            flash("All fields are required", "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register"))

        if register_user(username, password, role="user", first_name=first_name, second_name=second_name):
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Username already exists!", "danger")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = validate_user(username, password)
        if user:
            session["username"] = user["username"]
            session["role"] = user.get("role", "user")
            session["first_name"] = user.get("first_name", "")
            session["second_name"] = user.get("second_name", "")
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials!", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# ---------- Logs ----------

@app.route("/mylogs")
def mylogs():
    if "username" not in session:
        return redirect(url_for("login"))
    logs = get_user_logs(session.get("username"))
    return render_template("mylogs.html", logs=logs, user=session.get("username"), role=session.get("role", "user"))

@app.route("/logs")
def logs():
    if "username" not in session or session.get("role", "user") != "admin":
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for("home"))
    logs = get_logs()
    return render_template("logs.html", logs=logs, user=session.get("username"), role=session.get("role", "user"))

# ---------- File Processing ----------

@app.route("/process", methods=["POST"])
def process():
    if "username" not in session:
        return redirect(url_for("login"))

    action = request.form.get("action")
    file = request.files.get("file")
    password = request.form.get("password", "")
    user = session.get("username")

    if not file or not password:
        flash("File and password are required.", "danger")
        return redirect(url_for("home"))

    filename = file.filename
    saved_input = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(saved_input)

    try:
        if action == "encrypt":
            output_name = f"encrypted_{filename}"
            output_path = os.path.join(app.config['PROCESSED_FOLDER'], output_name)
            encrypt_file(saved_input, output_path, password)
            add_log("encrypt", filename, user, output_name)
            return send_from_directory(app.config['PROCESSED_FOLDER'], output_name, as_attachment=True)

        elif action == "decrypt":
            output_name = f"decrypted_{filename}"
            output_path = os.path.join(app.config['PROCESSED_FOLDER'], output_name)
            decrypt_file(saved_input, output_path, password)
            add_log("decrypt", filename, user, output_name)
            return send_from_directory(app.config['PROCESSED_FOLDER'], output_name, as_attachment=True)
    except Exception as e:
        flash(f"Error processing file: {e}", "danger")

    return redirect(url_for("home"))

@app.route("/download/<path:filename>")
def download(filename):
    return send_from_directory(app.config['PROCESSED_FOLDER'], filename, as_attachment=True)

# ---------- Admin User Management ----------

@app.route("/admin/users")
def manage_users():
    if "username" not in session or session.get("role", "user") != "admin":
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for("home"))
    users = get_all_users()
    return render_template("users.html", users=users, user=session.get("username"), role=session.get("role", "user"))

@app.route("/admin/users/promote/<int:user_id>")
def promote_user(user_id):
    if "username" in session and session.get("role", "user") == "admin":
        update_user_role(user_id, "admin")
        flash("User promoted to admin.", "success")
    return redirect(url_for("manage_users"))

@app.route("/admin/users/demote/<int:user_id>")
def demote_user(user_id):
    if "username" in session and session.get("role", "user") == "admin":
        update_user_role(user_id, "user")
        flash("User demoted to normal user.", "warning")
    return redirect(url_for("manage_users"))

@app.route("/admin/users/delete/<int:user_id>")
def remove_user(user_id):
    if "username" in session and session.get("role", "user") == "admin":
        delete_user(user_id)
        flash("User deleted successfully.", "danger")
    return redirect(url_for("manage_users"))

if __name__ == "__main__":
    app.run(debug=True)
