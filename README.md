# 🔐 SecureSysCall — User-Friendly System Call Interface for Enhanced Security

A full-stack project demonstrating:
- **Authentication** (JWT-based login/register)
- **Role-based access control** (Admin vs User)
- **Secure system call execution** (only permitted calls allowed per role)
- **Detailed audit logging** of all syscall usage

---

## 📁 Project Structure

```
secure-syscall-interface/
├── backend/
│   ├── app.py              ← Flask backend (REST API)
│   └── requirements.txt    ← Python dependencies
└── frontend/
    └── index.html          ← Single-file HTML/CSS/JS frontend
```

---

## 🚀 How to Run in VS Code

### Step 1 — Open in VS Code

```
File → Open Folder → select the "secure-syscall-interface" folder
```

---

### Step 2 — Set Up the Backend (Python/Flask)

Open the **integrated terminal** in VS Code (`Ctrl+` ` ` `) and run:

```bash
cd backend

# Create a virtual environment
python -m venv venv

# Activate it:
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install all dependencies:
pip install -r requirements.txt

# Run the server:
python app.py
```

You should see:
```
✅ Database initialized with default accounts.
   Admin → username: admin | password: admin123
   User  → username: user1 | password: user123

🚀 Server running at http://localhost:5000
```

---

### Step 3 — Open the Frontend

**Option A — VS Code Live Server (recommended):**
1. Install the **Live Server** extension by Ritwick Dey
2. Right-click on `frontend/index.html` → **Open with Live Server**

**Option B — Direct browser:**
- Just open `frontend/index.html` directly in your browser

---

## 🔑 Default Login Credentials

| Role  | Username | Password   | Access Level |
|-------|----------|------------|--------------|
| Admin | `admin`  | `admin123` | All syscalls |
| User  | `user1`  | `user123`  | Basic syscalls only |

---

## 🖥️ Available System Calls

| Syscall       | User | Admin | Description                    |
|---------------|------|-------|--------------------------------|
| cpu_info      | ✅   | ✅    | CPU count, usage, frequency    |
| memory_info   | ✅   | ✅    | RAM total, used, available     |
| disk_info     | ✅   | ✅    | Disk usage and free space      |
| os_info       | ✅   | ✅    | OS name, release, version      |
| process_list  | ✅   | ✅    | Top 20 running processes       |
| network_info  | ❌   | ✅    | Network bytes sent/received    |
| env_vars      | ❌   | ✅    | First 10 environment variables |
| uptime        | ❌   | ✅    | System boot time & uptime      |

---

## 🛡️ Security Features

- **JWT Authentication** — Tokens expire after 8 hours
- **Password Hashing** — bcrypt via Werkzeug
- **Role-Based Access Control** — Admin and User roles
- **Audit Logging** — Every syscall logged to `syscall_audit.log` and SQLite DB
- **Unauthorized Access Prevention** — 403 response for out-of-role calls
- **Failed Login Tracking** — Logged with IP address

---

## 📦 Python Libraries Used

| Library          | Purpose                          |
|------------------|----------------------------------|
| Flask            | Web framework / REST API         |
| Flask-CORS       | Cross-Origin Resource Sharing    |
| Flask-SQLAlchemy | ORM for SQLite database          |
| Werkzeug         | Password hashing utilities       |
| PyJWT            | JWT token generation/verification|
| psutil           | System metrics (CPU, RAM, etc.)  |

---

## 📋 VS Code Recommended Extensions

- **Python** (Microsoft) — Python language support
- **Live Server** (Ritwick Dey) — Serve the frontend HTML
- **SQLite Viewer** (Florian Klampfer) — Browse the syscall.db database
- **REST Client** (Humao) — Test API endpoints directly in VS Code

---

## 🗂️ Mapping to Requirements

| Req ID        | Feature Implemented                                |
|---------------|----------------------------------------------------|
| R3E052B31     | Intuitive Interface — clean dashboard with cards   |
| R3E052B32     | Authentication — JWT login, register, role control |
| R3E052B33     | Detailed Logs — audit table + syscall_audit.log    |
