from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import login_required, login_user, logout_user

from blog.services import UserService
from forms import LoginForm, RegisterForm


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    user_service = UserService()

    if form.validate_on_submit():
        user = user_service.register(
            email=form.email.data,
            password=form.password.data,
            name=form.name.data,
        )

        if user is None:
            flash("This Email is already used!")
            return redirect(url_for("auth.login"))

        flash("Account created.")
        login_user(user)

        return redirect(url_for("main.get_all_posts"))

    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    user_service = UserService()

    if form.validate_on_submit():

        user = user_service.authenticate(
            form.email.data,
            form.password.data,
        )

        if user:
            login_user(user)
            return redirect(url_for("main.get_all_posts"))

        flash("Invalid email or password.")
        return redirect(url_for("auth.login"))

    return render_template("login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for("auth.login"))
