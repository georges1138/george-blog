from blog.extensions import db


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    ci_probe = db.Column(db.String(20), nullable=True)
    published_on = db.Column(
        db.Date,
        nullable=False,
    )
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    poster_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comments = db.relationship('Comment', backref='trollers')

    def __repr__(self):
        return '<BlogPost %r>' % self.title
