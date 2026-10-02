from flask_ckeditor import CKEditor
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect


ckeditor = CKEditor()
bootstrap = Bootstrap()
db = SQLAlchemy()
login_manager = LoginManager()

csrf = CSRFProtect()
