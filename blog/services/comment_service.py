import nh3

from blog.extensions import db
from blog.models import Comment


ALLOWED_COMMENT_TAGS = {
    "p",
    "strong",
    "em",
    "a",
}

ALLOWED_COMMENT_ATTRIBUTES = {
    "a": {
        "href",
        "title",
    },
}


class CommentService:

    @staticmethod
    def add(user_id, post_id, text):
        clean_text = nh3.clean(
            text,
            tags=ALLOWED_COMMENT_TAGS,
            attributes=ALLOWED_COMMENT_ATTRIBUTES,
            clean_content_tags={"script", "style"},
        )

        new_comment = Comment(
            comment=clean_text,
            commenter_id=user_id,
            post_id=post_id,
        )

        db.session.add(new_comment)
        db.session.commit()

        return new_comment
