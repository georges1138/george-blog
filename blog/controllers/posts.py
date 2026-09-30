from datetime import date
from functools import wraps

from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import current_user, login_required

from blog.extensions import db
from blog.models import BlogPost, Comment
from forms import CommentForm, CreatePostForm


posts_bp = Blueprint("posts", __name__)


def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        print("Something is happening before the function is called.")
        print(current_user.id)

        if current_user.id != 1:
            return render_template("403.html"), 403

        return f(*args, **kwargs)

    return wrapper


@posts_bp.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()

    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                comment=form.comment.data,
                commenter_id=current_user.id,
                post_id=post_id,
            )

            db.session.add(new_comment)
            db.session.commit()

            return redirect(url_for("main.get_all_posts"))

        flash("You must be logged in to save a comment.")
        return redirect(url_for("auth.login"))

    requested_post = BlogPost.query.get(post_id)

    return render_template(
        "post.html",
        post=requested_post,
        form=form,
    )


@posts_bp.route("/new-post", methods=["GET", "POST"])
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
            poster_id=poster,
        )

        db.session.add(new_post)
        db.session.commit()

        return redirect(url_for("main.get_all_posts"))

    return render_template("make-post.html", form=form)


@posts_bp.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)

    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body,
    )

    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.poster_id = current_user.id
        post.body = edit_form.body.data

        db.session.commit()

        return redirect(
            url_for("posts.show_post", post_id=post.id)
        )

    return render_template("make-post.html", form=edit_form)


@posts_bp.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)

    db.session.delete(post_to_delete)
    db.session.commit()

    return redirect(url_for("main.get_all_posts"))
