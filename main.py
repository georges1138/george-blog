from decouple import config
from flask import Flask, render_template, redirect, url_for, flash
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from functools import wraps

from blog.extensions import ckeditor, bootstrap, db, login_manager
from blog.models import User, BlogPost, Comment


def create_app(test_config=None):
    app = Flask(__name__)

    if test_config is None:
        S_KEY = config('SEC_KEY')
        POST_DB_URL = config('POSTGRES_DATABASE_URL')

        app.config['SECRET_KEY'] = S_KEY
        app.config['SQLALCHEMY_DATABASE_URI'] = POST_DB_URL
    else:
        app.config.update(test_config)

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    ckeditor.init_app(app)
    bootstrap.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)

    login_manager.login_view = 'login'

    register_routes(app)
    return app


# db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        print("Something is happening before the function is called.")
        print(current_user.id)
        if current_user.id != 1:
            return render_template("403.html"), 403
        return f(*args, **kwargs)
    return wrapper


def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


def register():
    form = RegisterForm()
    if form.validate_on_submit():
        print("Got one!!")
        n_email = form.email.data
        hit = User.query.filter_by(email=n_email).first()
        print(type(hit))
        if hit:
            flash("This Email is already used!")
            return redirect(url_for('login'))
        else:
            print("New email...creating new account.")
            hash_password = generate_password_hash(
                form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
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
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


def login():
    form = LoginForm()
    if form.validate_on_submit():
        lemail = form.email.data
        lpassword = form.password.data
        log_user = User.query.filter_by(email=lemail).first()
        if log_user:
            if check_password_hash(log_user.password, lpassword):
                login_user(log_user)
                # flash('Logged in Successfully.')
                if log_user.id == 1:
                    print("Admin mode On.")
                return redirect(url_for('get_all_posts'))
            else:
                flash('Wrong Password - Try Again.')
                return redirect(url_for('login'))
        else:
            flash("Email Not Found")
            return redirect(url_for('login'))
    return render_template("login.html", form=form)


@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('login'))


def show_post(post_id):
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                comment=form.comment.data,
                commenter_id=current_user.id,
                post_id=post_id
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('get_all_posts'))
        else:
            flash('You must be logged in to save a comment.')
            return redirect(url_for('login'))
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post, form=form)


def about():
    return render_template("about.html")


def contact():
    return render_template("contact.html")


@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        poster = current_user.id
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
            poster_id=poster
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    # poster = current_user.id
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.data
        post.poster_id = current_user.id
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


def register_routes(app):
    app.add_url_rule("/", view_func=get_all_posts)

    app.add_url_rule(
        "/register",
        view_func=register,
        methods=['GET', 'POST'],
    )

    app.add_url_rule(
        "/login",
        view_func=login,
        methods=['GET', 'POST'],
    )

    app.add_url_rule(
        "/logout",
        view_func=logout,
    )

    app.add_url_rule(
        "/post/<int:post_id>",
        view_func=show_post,
        methods=['GET', 'POST'],
    )

    app.add_url_rule(
        "/about",
        view_func=about,
    )

    app.add_url_rule(
        "/contact",
        view_func=contact,
    )

    app.add_url_rule(
        "/new-post",
        view_func=add_new_post,
        methods=['GET', 'POST'],
    )

    app.add_url_rule(
        "/edit-post/<int:post_id>",
        view_func=edit_post,
        methods=['GET', 'POST'],
    )

    app.add_url_rule(
        "/delete/<int:post_id>",
        view_func=delete_post,
    )


if __name__ == "__main__":
    app = create_app()
    app.run(host='0.0.0.0', port=5000)
