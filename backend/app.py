from __future__ import annotations

import os
from datetime import datetime
from functools import wraps
from typing import Optional

from flask import Flask, g, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import BadSignature, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

DATABASE_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "task_tracker.db"))
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me")
TOKEN_TTL_SECONDS = int(os.environ.get("TOKEN_TTL_SECONDS", 60 * 60 * 24 * 7))


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DATABASE_PATH}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = SECRET_KEY

    CORS(app)
    db.init_app(app)

    with app.app_context():
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="employee-auth")
        ensure_schema()
        db.create_all()
        seed_data()

    app.config["TOKEN_SERIALIZER"] = serializer

    register_routes(app)
    register_static_routes(app)

    return app


db = SQLAlchemy()


class Employee(db.Model):
    __tablename__ = "employees"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    role = db.Column(db.String(50), nullable=False, default="employee")
    password_hash = db.Column(db.String(255), nullable=False)

    tasks = db.relationship("Task", back_populates="employee", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "title": self.title,
            "email": self.email,
            "role": self.role,
        }


class Task(db.Model):
    __tablename__ = "tasks"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(40), nullable=False, default="pending")
    employee_id = db.Column(db.Integer, db.ForeignKey("employees.id"), nullable=True)
    due_date = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    employee = db.relationship("Employee", back_populates="tasks")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "employee": self.employee.to_dict() if self.employee else None,
            "employee_id": self.employee_id,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "created_at": self.created_at.isoformat(),
        }


def seed_data() -> None:
    if Employee.query.count() > 0:
        return

    employees = [
        Employee(
            name="Avery Diaz",
            title="Engineering Manager",
            email="avery@example.com",
            role="admin",
        ),
        Employee(
            name="Morgan Lee",
            title="Product Designer",
            email="morgan@example.com",
            role="employee",
        ),
        Employee(
            name="Riley Patel",
            title="Backend Engineer",
            email="riley@example.com",
            role="employee",
        ),
    ]
    for employee, password in zip(employees, ["admin123", "design123", "build123"]):
        employee.set_password(password)

    db.session.add_all(employees)
    db.session.flush()

    tasks = [
        Task(
            title="Implement authentication",
            description="Add login flow and secure the API endpoints.",
            status="in_progress",
            employee_id=employees[0].id,
        ),
        Task(
            title="Refresh dashboard visuals",
            description="Update the UI to match the new design system.",
            status="pending",
            employee_id=employees[1].id,
        ),
        Task(
            title="Optimize task queries",
            description="Reduce dashboard latency by improving the task queries.",
            status="completed",
            employee_id=employees[2].id,
        ),
    ]

    db.session.add_all(tasks)
    db.session.commit()


def register_routes(app: Flask) -> None:
    serializer: URLSafeTimedSerializer = app.config["TOKEN_SERIALIZER"]

    def get_current_user():
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None
        token = auth_header.replace("Bearer ", "", 1).strip()
        try:
            payload = serializer.loads(token, max_age=TOKEN_TTL_SECONDS)
        except BadSignature:
            return None

        user_id = payload.get("id")
        if not user_id:
            return None
        return Employee.query.get(user_id)

    def require_auth(role: Optional[str] = None):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                user = get_current_user()
                if not user:
                    return jsonify({"error": "Unauthorized"}), 401
                if role and user.role != role:
                    return jsonify({"error": "Forbidden"}), 403
                g.current_user = user
                return fn(*args, **kwargs)

            return wrapper

        return decorator

    @app.route("/auth/login", methods=["POST"])
    def login():
        payload = request.get_json(force=True, silent=True) or {}
        email = (payload.get("email") or "").lower().strip()
        password = payload.get("password") or ""

        if not email or not password:
            return jsonify({"error": "Email and password are required."}), 400

        employee: Optional[Employee] = Employee.query.filter_by(email=email).first()
        if not employee or not employee.check_password(password):
            return jsonify({"error": "Invalid credentials."}), 401

        token = serializer.dumps({"id": employee.id, "role": employee.role})
        return jsonify({"token": token, "user": employee.to_dict()})

    @app.route("/auth/me", methods=["GET"])
    @require_auth()
    def current_user():
        return jsonify(g.current_user.to_dict())

    @app.route("/employees", methods=["GET"])
    @require_auth(role="admin")
    def get_employees():
        employees = Employee.query.order_by(Employee.name).all()
        return jsonify([employee.to_dict() for employee in employees])

    @app.route("/tasks", methods=["GET"])
    @require_auth()
    def get_tasks():
        status = request.args.get("status")
        employee_id = request.args.get("employee_id", type=int)

        query = Task.query
        if status:
            query = query.filter(Task.status == status)

        if g.current_user.role != "admin":
            query = query.filter(Task.employee_id == g.current_user.id)
        elif employee_id:
            query = query.filter(Task.employee_id == employee_id)

        tasks = query.order_by(Task.created_at.desc()).all()
        return jsonify([task.to_dict() for task in tasks])

    @app.route("/tasks", methods=["POST"])
    @require_auth()
    def create_task():
        payload = request.get_json(force=True, silent=True) or {}
        title = payload.get("title")
        if not title:
            return jsonify({"error": "Title is required."}), 400

        status = payload.get("status", "pending")
        description = payload.get("description")
        employee_id = payload.get("employee_id")
        due_date = parse_date(payload.get("due_date"))

        if g.current_user.role != "admin":
            employee_id = g.current_user.id
        elif employee_id and not Employee.query.get(employee_id):
            return jsonify({"error": "Employee not found."}), 404

        task = Task(
            title=title,
            description=description,
            status=status,
            employee_id=employee_id,
            due_date=due_date,
        )
        db.session.add(task)
        db.session.commit()
        return jsonify(task.to_dict()), 201

    @app.route("/tasks/<int:task_id>", methods=["PUT"])
    @require_auth()
    def update_task(task_id: int):
        task: Optional[Task] = Task.query.get(task_id)
        if not task:
            return jsonify({"error": "Task not found."}), 404

        if g.current_user.role != "admin" and task.employee_id != g.current_user.id:
            return jsonify({"error": "Forbidden"}), 403

        payload = request.get_json(force=True, silent=True) or {}
        status = payload.get("status")
        description = payload.get("description")
        employee_id = payload.get("employee_id")
        due_date = parse_date(payload.get("due_date"))

        if g.current_user.role == "admin" and employee_id is not None:
            if employee_id and not Employee.query.get(employee_id):
                return jsonify({"error": "Employee not found."}), 404
            task.employee_id = employee_id

        if status:
            task.status = status
        if description is not None:
            task.description = description
        if due_date is not None:
            task.due_date = due_date

        db.session.commit()
        return jsonify(task.to_dict())

    @app.route("/api/dashboard", methods=["GET"])
    @require_auth(role="admin")
    def get_dashboard_summary():
        total_tasks = Task.query.count()
        completed_tasks = Task.query.filter(Task.status == "completed").count()
        pending_tasks = Task.query.filter(Task.status != "completed").count()
        employee_count = Employee.query.count()

        completion_rate = (completed_tasks / total_tasks) * 100 if total_tasks else 0

        summary = {
            "total_tasks": total_tasks,
            "completed_tasks": completed_tasks,
            "pending_tasks": pending_tasks,
            "completion_rate": round(completion_rate, 2),
            "employee_count": employee_count,
        }
        return jsonify(summary)


def parse_date(value: Optional[str]):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).date()
    except ValueError:
        return None


def ensure_schema() -> None:
    """Detect old databases missing auth columns and recreate them."""

    if not os.path.exists(DATABASE_PATH):
        return

    inspector = db.inspect(db.engine)
    try:
        employee_columns = {col["name"] for col in inspector.get_columns("employees")}
        required_columns = {"id", "name", "title", "email", "role", "password_hash"}
        if required_columns.issubset(employee_columns):
            return
    except Exception:
        pass

    db.session.remove()
    db.drop_all()
    os.remove(DATABASE_PATH)


def register_static_routes(app: Flask) -> None:
    frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")

    @app.route("/")
    def login_page():
        
        return send_from_directory(frontend_dir, "login.html")

    @app.route("/dashboard")
    def dashboard_page():
        return send_from_directory(frontend_dir, "index.html")

    @app.route("/assets/<path:path>")
    def assets(path: str):
        return send_from_directory(os.path.join(frontend_dir, "assets"), path)


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)), debug=True)