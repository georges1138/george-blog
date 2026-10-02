from blog.extensions import db
from blog.models import User, BlogPost, Comment
from datetime import date
from werkzeug.security import generate_password_hash


def test_home_page_renders(client):
    response = client.get("/")

    assert response.status_code == 200


def test_register_creates_user_and_logs_them_in(client, app):
    test_email = 'test_user@email.invalid'
    test_password = 'pass123'
    test_name = 'alice'

    response = client.post(
        "/register",
        data={
            'email': test_email,
            'password': test_password,
            'name': test_name,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200

    db.session.remove()

    stmt = db.select(
        User
    ).where(User.email == test_email)

    registered_user = db.session.execute(
        stmt
    ).scalar_one_or_none()

    assert registered_user is not None
    assert registered_user.email == test_email
    assert registered_user.name == test_name

    with client.session_transaction() as session:

        assert session["_user_id"] == str(registered_user.id)


def test_login_accepts_correct_password_and_rejects_wrong_one(client):
    test_email = 'test_bob@email.invalid'
    test_password = 'passbob'
    test_name = 'bob'

    hashed_password = generate_password_hash(
        test_password,
        method='pbkdf2:sha256',
        salt_length=8
    )

    add_user = User(
        email=test_email,
        password=hashed_password,
        name=test_name,
    )
    db.session.add(add_user)
    db.session.commit()

    response = client.post(
        "/login",
        data={
            'email': test_email,
            'password': test_password,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    with client.session_transaction() as session:
        assert session["_user_id"] == str(add_user.id)

        session.clear()

    wrong_password = "definitely-wrong"
    response = client.post(
        "/login",
        data={
            'email': test_email,
            'password': wrong_password,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    with client.session_transaction() as session:
        assert "_user_id" not in session


def test_admin_can_create_post(client):
    test_email = 'test_admin@email.invalid'
    test_password = 'passadmin123'
    test_name = 'test_admin'

    hashed_password = generate_password_hash(
        test_password,
        method='pbkdf2:sha256',
        salt_length=8
    )

    admin_user = User(
        email=test_email,
        password=hashed_password,
        name=test_name,
    )
    db.session.add(admin_user)
    db.session.commit()
    admin_user_id = admin_user.id

    assert admin_user.id == 1

    response = client.post(
        "/login",
        data={
            'email': test_email,
            'password': test_password,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    with client.session_transaction() as session:
        assert session["_user_id"] == str(admin_user.id)

    post_title = 'I am testing a post'
    post_subtitle = 'Need a test post'

    response = client.post(
        "/new-post",
        data={
            'title': post_title,
            'subtitle': post_subtitle,
            'img_url': 'https://www.example.com/img.jpg',
            'body': 'This is the body for my test post.',
        },
        follow_redirects=True,
    )

    assert response.status_code == 200

    db.session.remove()

    stmt = db.select(
        BlogPost
    ).where(BlogPost.title == post_title)

    created_post = db.session.execute(
        stmt
    ).scalar_one_or_none()

    assert created_post is not None
    assert created_post.title == post_title
    assert created_post.subtitle == post_subtitle
    assert created_post.poster_id == admin_user_id


def test_non_admin_gets_403_on_new_post(client):
    test_admin_email = 'test_admin@email.invalid'
    test_admin_password = 'passadmin123'
    test_admin_name = 'test_admin'

    test_user_email = 'test_user@email.invalid'
    test_user_password = 'passtest123'
    test_user_name = 'test_user'

    hashed_admin_password = generate_password_hash(
        test_admin_password,
        method='pbkdf2:sha256',
        salt_length=8
    )

    add_admin = User(
        email=test_admin_email,
        password=hashed_admin_password,
        name=test_admin_name,
    )
    db.session.add(add_admin)
    db.session.commit()

    assert add_admin.id == 1

    hashed_user_password = generate_password_hash(
        test_user_password,
        method='pbkdf2:sha256',
        salt_length=8
    )

    add_user = User(
        email=test_user_email,
        password=hashed_user_password,
        name=test_user_name,
    )
    db.session.add(add_user)
    db.session.commit()

    assert add_user.id == 2

    response = client.post(
        "/login",
        data={
            'email': test_user_email,
            'password': test_user_password,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    with client.session_transaction() as session:
        assert session["_user_id"] == str(add_user.id)

    response = client.get("/new-post")

    assert response.status_code == 403


def test_logged_in_user_can_comment_on_post(client):
    test_user_email = 'test_user@email.invalid'
    test_user_password = 'passtest123'
    test_user_name = 'test_user'

    hashed_user_password = generate_password_hash(
        test_user_password,
        method='pbkdf2:sha256',
        salt_length=8
    )

    add_user = User(
        email=test_user_email,
        password=hashed_user_password,
        name=test_user_name,
    )
    db.session.add(add_user)
    db.session.commit()

    add_post = BlogPost(
        title='This is the post title',
        subtitle='This is the post subtitle',
        body='This is the post body',
        img_url="https://www.example.com/img.jpg",
        date=date.today().strftime("%B %d, %Y"),
        poster_id=add_user.id,
    )
    db.session.add(add_post)
    db.session.commit()

    assert add_user.id is not None
    assert add_post.id is not None
    user_id = add_user.id
    post_id = add_post.id

    response = client.post(
        "/login",
        data={
            'email': test_user_email,
            'password': test_user_password,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    with client.session_transaction() as session:
        assert session["_user_id"] == str(add_user.id)

    comment_text = "This is my test comment"

    response = client.post(
        f"/post/{add_post.id}",
        data={
            "comment": comment_text,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200

    db.session.remove()

    stmt = db.select(
        Comment
    ).where(Comment.comment == comment_text)

    saved_comment = db.session.execute(
        stmt
    ).scalar_one_or_none()

    assert saved_comment is not None
    assert saved_comment.comment == comment_text
    assert saved_comment.commenter_id == user_id
    assert saved_comment.post_id == post_id


def test_comment_html_is_sanitized(client):

    test_admin_email = 'test_admin@email.invalid'
    test_admin_password = 'passadmin123'
    test_admin_name = 'test_admin'

    test_user_email = 'test_user@email.invalid'
    test_user_password = 'passtest123'
    test_user_name = 'test_user'

    hashed_admin_password = generate_password_hash(
        test_admin_password,
        method='pbkdf2:sha256',
        salt_length=8
    )

    admin = User(
        email=test_admin_email,
        password=hashed_admin_password,
        name=test_admin_name,
    )
    db.session.add(admin)
    db.session.commit()
    admin_id = admin.id
    assert admin_id == 1

    hashed_user_password = generate_password_hash(
        test_user_password,
        method='pbkdf2:sha256',
        salt_length=8
    )

    user = User(
        email=test_user_email,
        password=hashed_user_password,
        name=test_user_name,
    )
    db.session.add(user)
    db.session.commit()
    user_id = user.id
    assert user_id == 2

    post = BlogPost(
        title='This is the post title',
        subtitle='This is the post subtitle',
        body='This is the post body',
        img_url="https://www.example.com/img.jpg",
        date=date.today().strftime("%B %d, %Y"),
        poster_id=admin_id,
    )
    db.session.add(post)
    db.session.commit()
    post_id = post.id

    response = client.post(
        "/login",
        data={
            'email': test_user_email,
            'password': test_user_password,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    malicious_comment = (
        "<p>Hello <strong>friend</strong>"
        "<script>alert(1)</script></p>"
    )

    with client.session_transaction() as session:
        assert session["_user_id"] == str(user_id)

    response = client.post(
        f"/post/{post_id}",
        data={
            "comment": malicious_comment,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    response = client.get(f"/post/{post_id}")
    html = response.get_data(as_text=True)

    assert "<script>alert(1)</script>" not in html
    assert "<strong>friend</strong>" in html

    db.session.remove()

    stmt = db.select(
        Comment
    ).where(
        Comment.commenter_id == user_id,
        Comment.post_id == post_id,
    )

    saved_comment = db.session.execute(
        stmt
    ).scalar_one_or_none()

    assert saved_comment is not None
    assert "<script>alert(1)</script>" not in saved_comment.comment
    assert "<strong>friend</strong>" in saved_comment.comment
