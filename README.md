# Attendance Management System 

A premium full-stack Attendance Management System built with:

- Frontend: HTML, CSS
- Backend: Python Flask
- Database: SQLite

## Main Features

### Admin Side
- Separate admin signup
- Separate admin login
- Admin dashboard
- Add, edit, delete students
- Search students
- Mark attendance date-wise
- View reports
- Export attendance report as CSV

### Student Side
- Separate student signup
- Separate student login
- Student dashboard
- Student can view only their own attendance
- Student can see present percentage and attendance history
- Student can update basic profile details

## Default Admin Login

A default admin account is created for testing.

Username: `admin`  
Password: `admin123`

You can also create a new admin account from the Admin Signup page.

## How to Run

```bash
pip install -r requirements.txt
python app.py
```

Open in browser:

```text
http://127.0.0.1:5000
```

## Important

This version uses SQLite so it runs directly without MySQL setup.

When you run the project for the first time, a database file named `attendance.db` will be created automatically.
