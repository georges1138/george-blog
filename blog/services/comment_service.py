from blog.extensions import db
from blog.models import Comment


class CommentService:

    @staticmethod
    def add(user_id, post_id, text):
        new_comment = Comment(
            comment=text,
            commenter_id=user_id,
            post_id=post_id,
        )

        db.session.add(new_comment)
        db.session.commit()

        return new_comment
