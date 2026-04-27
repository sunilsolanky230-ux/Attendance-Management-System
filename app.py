from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from pathlib import Path
from datetime import date
import csv
from io import StringIO
from functools import wraps

app = Flask(__name__)
app.secret_key = "change-this-secret-key-before-production"

DB_PATH = Path("attendance.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            roll_no TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            class_name TEXT NOT NULL,
            email TEXT UNIQUE,
            phone TEXT,
            password_hash TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            attendance_date TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('Present', 'Absent')),
            marked_by_admin_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,
            FOREIGN KEY(marked_by_admin_id) REFERENCES admins(id) ON DELETE SET NULL,
            UNIQUE(student_id, attendance_date)
        )
    """)

    default_admin = conn.execute(
        "SELECT id FROM admins WHERE username = ?",
        ("admin",)
    ).fetchone()

    if not default_admin:
        conn.execute(
            "INSERT INTO admins (username, email, password_hash) VALUES (?, ?, ?)",
            ("admin", "admin@example.com", generate_password_hash("admin123"))
        )

    conn.commit()
    conn.close()


def login_required(role=None):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                flash("Please login first.", "warning")
                return redirect(url_for("index"))

            if role and session.get("role") != role:
                flash("You do not have permission to access that page.", "danger")
                return redirect(url_for("index"))

            return view_func(*args, **kwargs)
        return wrapper
    return decorator


@app.context_processor
def inject_user():
    return {
        "current_role": session.get("role"),
        "current_user": session.get("username") or session.get("student_name")
    }


@app.route("/")
def index():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    if session.get("role") == "student":
        return redirect(url_for("student_dashboard"))
    return render_template("index.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("index"))


# ---------------- ADMIN AUTH ----------------

@app.route("/admin/signup", methods=["GET", "POST"])
def admin_signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("admin_signup"))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("admin_signup"))

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO admins (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, generate_password_hash(password))
            )
            conn.commit()
            conn.close()
            flash("Admin account created successfully. Please login.", "success")
            return redirect(url_for("admin_login"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")

    return render_template("admin_signup.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        admin = conn.execute(
            "SELECT * FROM admins WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        if admin and check_password_hash(admin["password_hash"], password):
            session.clear()
            session["user_id"] = admin["id"]
            session["username"] = admin["username"]
            session["role"] = "admin"
            flash("Admin login successful.", "success")
            return redirect(url_for("admin_dashboard"))

        flash("Invalid admin username or password.", "danger")

    return render_template("admin_login.html")


# ---------------- STUDENT AUTH ----------------

@app.route("/student/signup", methods=["GET", "POST"])
def student_signup():
    if request.method == "POST":
        roll_no = request.form.get("roll_no", "").strip()
        name = request.form.get("name", "").strip()
        class_name = request.form.get("class_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not roll_no or not name or not class_name or not email or not password:
            flash("Roll number, name, class, email, and password are required.", "danger")
            return redirect(url_for("student_signup"))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("student_signup"))

        conn = get_db()
        existing = conn.execute(
            "SELECT * FROM students WHERE roll_no = ?",
            (roll_no,)
        ).fetchone()

        try:
            if existing:
                if existing["password_hash"]:
                    conn.close()
                    flash("Student account already exists for this roll number.", "danger")
                    return redirect(url_for("student_login"))

                conn.execute("""
                    UPDATE students
                    SET name = ?, class_name = ?, email = ?, phone = ?, password_hash = ?
                    WHERE roll_no = ?
                """, (name, class_name, email, phone, generate_password_hash(password), roll_no))
            else:
                conn.execute("""
                    INSERT INTO students (roll_no, name, class_name, email, phone, password_hash)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (roll_no, name, class_name, email, phone, generate_password_hash(password)))

            conn.commit()
            conn.close()
            flash("Student account created successfully. Please login.", "success")
            return redirect(url_for("student_login"))
        except sqlite3.IntegrityError:
            conn.close()
            flash("Email or roll number already exists.", "danger")

    return render_template("student_signup.html")


@app.route("/student/login", methods=["GET", "POST"])
def student_login():
    if request.method == "POST":
        roll_no = request.form.get("roll_no", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        student = conn.execute(
            "SELECT * FROM students WHERE roll_no = ?",
            (roll_no,)
        ).fetchone()
        conn.close()

        if student and student["password_hash"] and check_password_hash(student["password_hash"], password):
            session.clear()
            session["user_id"] = student["id"]
            session["student_name"] = student["name"]
            session["student_roll"] = student["roll_no"]
            session["role"] = "student"
            flash("Student login successful.", "success")
            return redirect(url_for("student_dashboard"))

        flash("Invalid roll number or password.", "danger")

    return render_template("student_login.html")


# ---------------- ADMIN PAGES ----------------

@app.route("/admin/dashboard")
@login_required("admin")
def admin_dashboard():
    today = date.today().isoformat()
    conn = get_db()

    total_students = conn.execute("SELECT COUNT(*) AS count FROM students").fetchone()["count"]
    registered_students = conn.execute(
        "SELECT COUNT(*) AS count FROM students WHERE password_hash IS NOT NULL"
    ).fetchone()["count"]
    present_today = conn.execute(
        "SELECT COUNT(*) AS count FROM attendance WHERE attendance_date = ? AND status = 'Present'",
        (today,)
    ).fetchone()["count"]
    absent_today = conn.execute(
        "SELECT COUNT(*) AS count FROM attendance WHERE attendance_date = ? AND status = 'Absent'",
        (today,)
    ).fetchone()["count"]

    recent_students = conn.execute(
        "SELECT * FROM students ORDER BY id DESC LIMIT 6"
    ).fetchall()

    conn.close()

    return render_template(
        "admin_dashboard.html",
        today=today,
        total_students=total_students,
        registered_students=registered_students,
        present_today=present_today,
        absent_today=absent_today,
        recent_students=recent_students
    )


@app.route("/admin/students")
@login_required("admin")
def admin_students():
    search = request.args.get("search", "").strip()

    conn = get_db()
    if search:
        students_data = conn.execute("""
            SELECT * FROM students
            WHERE roll_no LIKE ? OR name LIKE ? OR class_name LIKE ? OR email LIKE ?
            ORDER BY roll_no
        """, (f"%{search}%", f"%{search}%", f"%{search}%", f"%{search}%")).fetchall()
    else:
        students_data = conn.execute("SELECT * FROM students ORDER BY roll_no").fetchall()

    conn.close()
    return render_template("admin_students.html", students=students_data, search=search)


@app.route("/admin/students/add", methods=["POST"])
@login_required("admin")
def add_student():
    roll_no = request.form.get("roll_no", "").strip()
    name = request.form.get("name", "").strip()
    class_name = request.form.get("class_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").strip()
    password = request.form.get("password", "")

    if not roll_no or not name or not class_name:
        flash("Roll number, name, and class are required.", "danger")
        return redirect(url_for("admin_students"))

    password_hash = generate_password_hash(password) if password else None

    try:
        conn = get_db()
        conn.execute("""
            INSERT INTO students (roll_no, name, class_name, email, phone, password_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (roll_no, name, class_name, email or None, phone, password_hash))
        conn.commit()
        conn.close()
        flash("Student added successfully.", "success")
    except sqlite3.IntegrityError:
        flash("Roll number or email already exists.", "danger")

    return redirect(url_for("admin_students"))


@app.route("/admin/students/edit/<int:student_id>", methods=["GET", "POST"])
@login_required("admin")
def edit_student(student_id):
    conn = get_db()

    if request.method == "POST":
        roll_no = request.form.get("roll_no", "").strip()
        name = request.form.get("name", "").strip()
        class_name = request.form.get("class_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        new_password = request.form.get("new_password", "")

        try:
            if new_password:
                conn.execute("""
                    UPDATE students
                    SET roll_no = ?, name = ?, class_name = ?, email = ?, phone = ?, password_hash = ?
                    WHERE id = ?
                """, (roll_no, name, class_name, email or None, phone, generate_password_hash(new_password), student_id))
            else:
                conn.execute("""
                    UPDATE students
                    SET roll_no = ?, name = ?, class_name = ?, email = ?, phone = ?
                    WHERE id = ?
                """, (roll_no, name, class_name, email or None, phone, student_id))

            conn.commit()
            conn.close()
            flash("Student updated successfully.", "success")
            return redirect(url_for("admin_students"))
        except sqlite3.IntegrityError:
            flash("Roll number or email already exists.", "danger")

    student = conn.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
    conn.close()

    if not student:
        flash("Student not found.", "danger")
        return redirect(url_for("admin_students"))

    return render_template("edit_student.html", student=student)


@app.route("/admin/students/delete/<int:student_id>", methods=["POST"])
@login_required("admin")
def delete_student(student_id):
    conn = get_db()
    conn.execute("DELETE FROM students WHERE id = ?", (student_id,))
    conn.commit()
    conn.close()

    flash("Student deleted successfully.", "info")
    return redirect(url_for("admin_students"))


@app.route("/admin/attendance", methods=["GET", "POST"])
@login_required("admin")
def mark_attendance():
    selected_date = request.args.get("date") or request.form.get("attendance_date") or date.today().isoformat()
    selected_class = request.args.get("class_name") or request.form.get("class_name") or ""

    conn = get_db()

    if request.method == "POST":
        student_ids = request.form.getlist("student_id")

        for student_id in student_ids:
            status = request.form.get(f"status_{student_id}", "Absent")
            conn.execute("""
                INSERT INTO attendance (student_id, attendance_date, status, marked_by_admin_id, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(student_id, attendance_date)
                DO UPDATE SET 
                    status = excluded.status,
                    marked_by_admin_id = excluded.marked_by_admin_id,
                    updated_at = CURRENT_TIMESTAMP
            """, (student_id, selected_date, status, session.get("user_id")))

        conn.commit()
        conn.close()
        flash("Attendance saved successfully.", "success")
        return redirect(url_for("mark_attendance", date=selected_date, class_name=selected_class))

    classes = conn.execute("""
        SELECT DISTINCT class_name FROM students
        WHERE class_name IS NOT NULL AND class_name != ''
        ORDER BY class_name
    """).fetchall()

    if selected_class:
        students_data = conn.execute("""
            SELECT 
                s.id,
                s.roll_no,
                s.name,
                s.class_name,
                COALESCE(a.status, 'Absent') AS status
            FROM students s
            LEFT JOIN attendance a
                ON s.id = a.student_id AND a.attendance_date = ?
            WHERE s.class_name = ?
            ORDER BY s.roll_no
        """, (selected_date, selected_class)).fetchall()
    else:
        students_data = conn.execute("""
            SELECT 
                s.id,
                s.roll_no,
                s.name,
                s.class_name,
                COALESCE(a.status, 'Absent') AS status
            FROM students s
            LEFT JOIN attendance a
                ON s.id = a.student_id AND a.attendance_date = ?
            ORDER BY s.roll_no
        """, (selected_date,)).fetchall()

    conn.close()

    return render_template(
        "mark_attendance.html",
        students=students_data,
        selected_date=selected_date,
        selected_class=selected_class,
        classes=classes
    )


@app.route("/admin/reports")
@login_required("admin")
def admin_reports():
    selected_date = request.args.get("date", date.today().isoformat())
    selected_class = request.args.get("class_name", "")

    conn = get_db()

    classes = conn.execute("""
        SELECT DISTINCT class_name FROM students
        WHERE class_name IS NOT NULL AND class_name != ''
        ORDER BY class_name
    """).fetchall()

    if selected_class:
        report_data = conn.execute("""
            SELECT 
                s.roll_no,
                s.name,
                s.class_name,
                COALESCE(a.status, 'Not Marked') AS status
            FROM students s
            LEFT JOIN attendance a
                ON s.id = a.student_id AND a.attendance_date = ?
            WHERE s.class_name = ?
            ORDER BY s.roll_no
        """, (selected_date, selected_class)).fetchall()
    else:
        report_data = conn.execute("""
            SELECT 
                s.roll_no,
                s.name,
                s.class_name,
                COALESCE(a.status, 'Not Marked') AS status
            FROM students s
            LEFT JOIN attendance a
                ON s.id = a.student_id AND a.attendance_date = ?
            ORDER BY s.roll_no
        """, (selected_date,)).fetchall()

    present_count = sum(1 for row in report_data if row["status"] == "Present")
    absent_count = sum(1 for row in report_data if row["status"] == "Absent")
    not_marked_count = sum(1 for row in report_data if row["status"] == "Not Marked")

    conn.close()

    return render_template(
        "admin_reports.html",
        report_data=report_data,
        selected_date=selected_date,
        selected_class=selected_class,
        classes=classes,
        present_count=present_count,
        absent_count=absent_count,
        not_marked_count=not_marked_count
    )


@app.route("/admin/reports/export")
@login_required("admin")
def export_report():
    selected_date = request.args.get("date", date.today().isoformat())
    selected_class = request.args.get("class_name", "")

    conn = get_db()

    if selected_class:
        rows = conn.execute("""
            SELECT 
                s.roll_no,
                s.name,
                s.class_name,
                COALESCE(a.status, 'Not Marked') AS status
            FROM students s
            LEFT JOIN attendance a
                ON s.id = a.student_id AND a.attendance_date = ?
            WHERE s.class_name = ?
            ORDER BY s.roll_no
        """, (selected_date, selected_class)).fetchall()
    else:
        rows = conn.execute("""
            SELECT 
                s.roll_no,
                s.name,
                s.class_name,
                COALESCE(a.status, 'Not Marked') AS status
            FROM students s
            LEFT JOIN attendance a
                ON s.id = a.student_id AND a.attendance_date = ?
            ORDER BY s.roll_no
        """, (selected_date,)).fetchall()

    conn.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Roll No", "Name", "Class", "Status", "Date"])

    for row in rows:
        writer.writerow([row["roll_no"], row["name"], row["class_name"], row["status"], selected_date])

    output.seek(0)

    filename = f"attendance_{selected_date}.csv"
    if selected_class:
        filename = f"attendance_{selected_class}_{selected_date}.csv".replace(" ", "_")

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ---------------- STUDENT PAGES ----------------

@app.route("/student/dashboard")
@login_required("student")
def student_dashboard():
    student_id = session.get("user_id")
    conn = get_db()

    student = conn.execute(
        "SELECT * FROM students WHERE id = ?",
        (student_id,)
    ).fetchone()

    total_marked = conn.execute(
        "SELECT COUNT(*) AS count FROM attendance WHERE student_id = ?",
        (student_id,)
    ).fetchone()["count"]

    present_count = conn.execute(
        "SELECT COUNT(*) AS count FROM attendance WHERE student_id = ? AND status = 'Present'",
        (student_id,)
    ).fetchone()["count"]

    absent_count = conn.execute(
        "SELECT COUNT(*) AS count FROM attendance WHERE student_id = ? AND status = 'Absent'",
        (student_id,)
    ).fetchone()["count"]

    attendance_percentage = round((present_count / total_marked) * 100, 2) if total_marked else 0

    records = conn.execute("""
        SELECT attendance_date, status, updated_at
        FROM attendance
        WHERE student_id = ?
        ORDER BY attendance_date DESC
        LIMIT 30
    """, (student_id,)).fetchall()

    conn.close()

    return render_template(
        "student_dashboard.html",
        student=student,
        total_marked=total_marked,
        present_count=present_count,
        absent_count=absent_count,
        attendance_percentage=attendance_percentage,
        records=records
    )


@app.route("/student/profile", methods=["GET", "POST"])
@login_required("student")
def student_profile():
    student_id = session.get("user_id")
    conn = get_db()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")

        try:
            if password:
                conn.execute("""
                    UPDATE students
                    SET name = ?, email = ?, phone = ?, password_hash = ?
                    WHERE id = ?
                """, (name, email or None, phone, generate_password_hash(password), student_id))
            else:
                conn.execute("""
                    UPDATE students
                    SET name = ?, email = ?, phone = ?
                    WHERE id = ?
                """, (name, email or None, phone, student_id))

            conn.commit()
            session["student_name"] = name
            flash("Profile updated successfully.", "success")
        except sqlite3.IntegrityError:
            flash("Email already exists.", "danger")

    student = conn.execute(
        "SELECT * FROM students WHERE id = ?",
        (student_id,)
    ).fetchone()
    conn.close()

    return render_template("student_profile.html", student=student)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
