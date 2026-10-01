from werkzeug.security import check_password_hash, generate_password_hash

from blog.extensions import db
from blog.models import User


class UserService:

    @staticmethod
    def register(email, password, name):
        stmt = db.select(
            User
        ).where(
            User.email == email
        )

        existing_user = db.session.execute(
            stmt
        ).scalar_one_or_none()

        if existing_user is not None:
            return None

        hash_password = generate_password_hash(
            password,
            method="pbkdf2:sha256",
            salt_length=8,
        )

        new_user = User(
            email=email,
            password=hash_password,
            name=name,
        )

        db.session.add(new_user)
        db.session.commit()

        return new_user


    @staticmethod
    def authenticate(email, password):
        stmt = db.select(
            User
        ).where(
            User.email == email
        )

        user = db.session.execute(
            stmt
        ).scalar_one_or_none()

        if user and check_password_hash(user.password, password):
            return user

        return None
