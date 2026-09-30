from flask import Blueprint, render_template

from blog.models import BlogPost


main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@main_bp.route("/about")
def about():
    return render_template("about.html")


@main_bp.route("/contact")
def contact():
    return render_template("contact.html")
