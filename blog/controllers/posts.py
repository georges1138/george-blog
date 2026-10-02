from functools import wraps

from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import current_user, login_required

from blog.services import PostService, CommentService
from blog.forms import CommentForm, CreatePostForm


posts_bp = Blueprint("posts", __name__)


def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.id != 1:
            return render_template("403.html"), 403

        return f(*args, **kwargs)
    return wrapper


@posts_bp.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()

    if form.validate_on_submit():
        if current_user.is_authenticated:
            CommentService.add(
                user_id=current_user.id,
                post_id=post_id,
                text=form.comment.data,
            )

            return redirect(url_for("main.get_all_posts"))

        flash("You must be logged in to save a comment.")
        return redirect(url_for("auth.login"))

    requested_post = PostService.get(post_id)

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
        PostService.create(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            poster_id=current_user.id,
        )

        return redirect(url_for("main.get_all_posts"))

    return render_template("make-post.html", form=form)


@posts_bp.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = PostService.get(post_id)

    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body,
    )

    if edit_form.validate_on_submit():
        PostService.update(
            post_id=post.id,
            title=edit_form.title.data,
            subtitle=edit_form.subtitle.data,
            body=edit_form.body.data,
            img_url=edit_form.img_url.data,
            poster_id=current_user.id,
        )

        return redirect(
            url_for("posts.show_post", post_id=post.id)
        )

    return render_template("make-post.html", form=edit_form)


@posts_bp.route("/delete/<int:post_id>", methods=["POST"])
@login_required
@admin_only
def delete_post(post_id):
    PostService.delete(post_id)

    return redirect(url_for("main.get_all_posts"))
