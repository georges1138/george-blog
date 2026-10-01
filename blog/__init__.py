from decouple import config
from flask import Flask

from blog.controllers import auth_bp, main_bp, posts_bp
from blog.extensions import bootstrap, ckeditor, db, login_manager


def create_app(test_config=None):
    app = Flask(__name__)

    if test_config is None:
        S_KEY = config("SEC_KEY")
        POST_DB_URL = config("POSTGRES_DATABASE_URL")

        app.config["SECRET_KEY"] = S_KEY
        app.config["SQLALCHEMY_DATABASE_URI"] = POST_DB_URL
    else:
        app.config.update(test_config)

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    ckeditor.init_app(app)
    bootstrap.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)

    login_manager.login_view = "auth.login"

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(posts_bp)

    return app
