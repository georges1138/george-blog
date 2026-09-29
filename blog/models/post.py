from blog.extensions import db


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    poster_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comments = db.relationship('Comment', backref='trollers')

    def __repr__(self):
        return '<BlogPost %r>' % self.title
