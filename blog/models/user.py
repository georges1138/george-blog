from flask_login import UserMixin
from blog.extensions import db, login_manager


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    posts = db.relationship('BlogPost', backref='poster')
    comments = db.relationship('Comment', backref='commenter')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)
