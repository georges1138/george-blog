from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from blog.extensions import db, login_manager
from blog.models import User
from forms import LoginForm, RegisterForm


auth_bp = Blueprint("auth", __name__)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        print("Got one!!")

        n_email = form.email.data
        hit = User.query.filter_by(email=n_email).first()

        print(type(hit))

        if hit:
            flash("This Email is already used!")
            return redirect(url_for("auth.login"))

        print("New email...creating new account.")

        hash_password = generate_password_hash(
            form.password.data,
            method="pbkdf2:sha256",
            salt_length=8,
        )

        n_name = form.name.data

        add_user = User(
            email=n_email,
            password=hash_password,
            name=n_name,
        )

        db.session.add(add_user)
        db.session.commit()

        flash("Account created.")
        login_user(add_user)

        return redirect(url_for("main.get_all_posts"))

    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        lemail = form.email.data
        lpassword = form.password.data

        log_user = User.query.filter_by(email=lemail).first()

        if log_user:
            if check_password_hash(log_user.password, lpassword):
                login_user(log_user)

                if log_user.id == 1:
                    print("Admin mode On.")

                return redirect(url_for("main.get_all_posts"))

            flash("Wrong Password - Try Again.")
            return redirect(url_for("auth.login"))

        flash("Email Not Found")
        return redirect(url_for("auth.login"))

    return render_template("login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for("auth.login"))
