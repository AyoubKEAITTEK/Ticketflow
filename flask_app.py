from flask import Flask, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user
from flask_bcrypt import Bcrypt
from flask_login import current_user
from flask_login import login_required 
from sqlalchemy.sql import func 
from datetime import datetime

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+mysqldb://"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SECRET_KEY"] = "abc"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)

class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    is_admin = db.Column(db.Boolean, default=False) 

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), nullable=False)
    message = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100))  
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('Users', foreign_keys=[user_id], backref=db.backref('tickets', lazy=True))
    status = db.Column(db.String(50), default='Open')
    admin_response = db.Column(db.Text)
    ticket_created_at = db.Column(db.DateTime(timezone=True), server_default=func.now()) 
    ticket_closed_at = db.Column(db.DateTime(timezone=True), nullable=True)  
    closed_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    closed_by = db.relationship('Users', foreign_keys=[closed_by_id])

with app.app_context():
    db.create_all()

@login_manager.user_loader
def loader_user(user_id):
    return Users.query.get(user_id)

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        existing_user = Users.query.filter_by(username=username).first()
        if existing_user:
            return "User already exists", 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        is_admin = username.startswith("bitadmin")
        user = Users(username=username, password=hashed_password, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = Users.query.filter_by(username=username).first()

        if user is None:
            return "User not found", 404

        if bcrypt.check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("home"))
        else:
            return "Incorrect password", 401
    return render_template("login.html")

@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return "Unauthorized", 403

    if request.method == "POST":
        ticket_id = request.form.get("ticket_id")
        new_status = request.form.get("status")
        admin_response = request.form.get("response")

        ticket = Ticket.query.get(ticket_id)
        if ticket:
            ticket.status = new_status
            ticket.admin_response = admin_response
            if new_status == "Closed" and ticket.ticket_closed_at is None:
                ticket.ticket_closed_at = datetime.utcnow()
                ticket.closed_by_id = current_user.id
            db.session.commit()
        return redirect(url_for("admin_dashboard"))

    search_location = request.args.get("location")
    query = Ticket.query.filter(Ticket.status != "Closed")

    if search_location:
        query = query.filter(Ticket.location.ilike(f"%{search_location}%"))

    tickets = query.all()

    return render_template("admin.html", user=current_user, tickets=tickets, search_location=search_location)


@app.route("/ticket", methods=["GET", "POST"])
@login_required
def ticket():
    if request.method == "POST":
        title = request.form.get("title")
        message = request.form.get("message")
        location = request.form.get("location") 

        new_ticket = Ticket(
            title=title,
            message=message,
            location=location, 
            user_id=current_user.id
        )
        db.session.add(new_ticket)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("ticket.html")
    
@app.route("/my_tickets")
@login_required
def my_tickets():
    tickets = Ticket.query.filter(Ticket.user_id == current_user.id, Ticket.status != "Closed").all()
    return render_template("my_tickets.html", tickets=tickets)

@app.route("/closed_tickets")
@login_required
def closed_tickets():
    closed = Ticket.query.filter_by(user_id=current_user.id, status="Closed").all()
    return render_template("closed_tickets.html", tickets=closed)


@app.route("/admin/closed_tickets")
@login_required
def admin_closed_tickets():
    if not current_user.is_admin:
        return "Unauthorized", 403

    search_location = request.args.get("location")
    query = Ticket.query.filter_by(status="Closed") 

    if search_location:
        query = query.filter(Ticket.location.ilike(f"%{search_location}%"))

    closed_tickets = query.all()  
    return render_template("admin_closed_tickets.html", tickets=closed_tickets, search_location=search_location)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route("/")
def home():
    return render_template("home.html", user=current_user)

from pytz import timezone

@app.template_filter('cet')
def convert_to_cet(utc_dt):
    if utc_dt:
        return utc_dt.astimezone(timezone('Europe/Copenhagen')).strftime('%Y-%m-%d %H:%M:%S')
    return 'N/A'
