from flask import Blueprint, render_template

from blog.services import PostService


main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def get_all_posts():
    posts = PostService.get_all()
    return render_template("index.html", all_posts=posts)


@main_bp.route("/about")
def about():
    return render_template("about.html")


@main_bp.route("/contact")
def contact():
    return render_template("contact.html")
