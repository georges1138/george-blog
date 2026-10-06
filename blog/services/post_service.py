from datetime import date

from blog.extensions import db
from blog.models import BlogPost


class PostService:

    @staticmethod
    def get_all():
        stmt = db.select(
            BlogPost
        ).order_by(BlogPost.published_on.desc())
        return db.session.execute(stmt).scalars().all()

    @staticmethod
    def get(post_id):
        stmt = db.select(
            BlogPost
        ).where(
            BlogPost.id == post_id
        )
        return db.session.execute(stmt).scalar_one_or_none()

    @staticmethod
    def create(title, subtitle, body, img_url, poster_id):
        new_post = BlogPost(
            title=title,
            subtitle=subtitle,
            body=body,
            img_url=img_url,
            published_on=date.today(),
            poster_id=poster_id,
        )

        db.session.add(new_post)
        db.session.commit()

        return new_post

    @staticmethod
    def update(post_id, title, subtitle, body, img_url, poster_id):
        post = PostService.get(post_id)

        if post is None:
            return False

        post.title = title
        post.subtitle = subtitle
        post.body = body
        post.img_url = img_url
        post.poster_id = poster_id

        db.session.commit()
        return True

    @staticmethod
    def delete(post_id):
        post = PostService.get(post_id)

        if post is None:
            return False

        db.session.delete(post)
        db.session.commit()

        return True
