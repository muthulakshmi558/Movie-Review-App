from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///movies.db"
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ---------- MODELS ----------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    reviews = db.relationship("Review", backref="user", lazy=True)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    movie = db.Column(db.String(200), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

# ---------- LOGIN MANAGER ----------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------- ROUTES ----------
@app.route("/")
def home():
    reviews = Review.query.all()
    return render_template("dashboard.html", reviews=reviews)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed_pw = generate_password_hash(password, method="pbkdf2:sha256")
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Welcome! You are now logged in.", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials!", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

@app.route("/add_review", methods=["GET", "POST"])
@login_required
def add_review():
    if request.method == "POST":
        movie = request.form["movie"]
        rating = int(request.form["rating"])
        comment = request.form["comment"]

        review = Review(movie=movie, rating=rating, comment=comment, user_id=current_user.id)
        db.session.add(review)
        db.session.commit()
        flash("Review submitted successfully!", "success")
        return redirect(url_for("home"))

    return render_template("add_review.html")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
