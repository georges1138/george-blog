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
        is_admin=True
    )
    db.session.add(admin_user)
    db.session.commit()
    admin_user_id = admin_user.id

    assert admin_user.is_admin == True

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
        published_on=date.today(),
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
        published_on=date.today(),
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


def test_get_cannot_delete_post(client):
    test_admin_email = 'test_admin@email.invalid'
    test_admin_password = 'passadmin123'
    test_admin_name = 'test_admin'

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

    post = BlogPost(
        title='This is the post title',
        subtitle='This is the post subtitle',
        body='This is the post body',
        img_url="https://www.example.com/img.jpg",
        published_on=date.today(),
        poster_id=admin_id,
    )
    db.session.add(post)
    db.session.commit()
    post_id = post.id

    response = client.post(
        "/login",
        data={
            'email': test_admin_email,
            'password': test_admin_password,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    response = client.get(
        f"/delete/{post_id}",
        follow_redirects=False,
    )
    assert response.status_code == 405

    db.session.remove()

    stmt = db.select(
        BlogPost
    ).where(
        BlogPost.id == post_id
    )

    saved_post = db.session.execute(
        stmt
    ).scalar_one_or_none()

    assert saved_post is not None


def test_delete_requires_csrf_token(client, app):
    test_admin_email = 'test_admin@email.invalid'
    test_admin_password = 'passadmin123'
    test_admin_name = 'test_admin'

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

    post = BlogPost(
        title='This is the post title',
        subtitle='This is the post subtitle',
        body='This is the post body',
        img_url="https://www.example.com/img.jpg",
        published_on=date.today(),
        poster_id=admin_id,
    )
    db.session.add(post)
    db.session.commit()
    post_id = post.id

    # log in while normal test CSRF is still disabled
    response = client.post(
        "/login",
        data={
            "email": test_admin_email,
            "password": test_admin_password,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200

    # Turn CSRF protection on for this test
    app.config["WTF_CSRF_ENABLED"] = True

    # ACT - deliberately omit csrf_token
    response = client.post(
        f"/delete/{post_id}",
        follow_redirects=False,
    )

    # ASSERT
    assert response.status_code == 400

    db.session.remove()

    stmt = db.select(
        BlogPost
    ).where(
        BlogPost.id == post_id
    )

    saved_post = db.session.execute(
        stmt
    ).scalar_one_or_none()

    assert saved_post is not None


def test_missing_post_returns_404(client):
    response = client.get("/post/999")

    assert response.status_code == 404


def test_edit_missing_post_returns_404(client):
    test_admin_email = 'test_admin@email.invalid'
    test_admin_password = 'passadmin123'
    test_admin_name = 'test_admin'

    hashed_admin_password = generate_password_hash(
        test_admin_password,
        method='pbkdf2:sha256',
        salt_length=8
    )

    admin = User(
        email=test_admin_email,
        password=hashed_admin_password,
        name=test_admin_name,
        is_admin=True,
    )
    db.session.add(admin)
    db.session.commit()
    assert admin.is_admin == True

    response = client.post(
        "/login",
        data={
            'email': test_admin_email,
            'password': test_admin_password,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    response = client.get(
        "/edit-post/999",
        follow_redirects=False,
    )

    assert response.status_code == 404


def test_delete_missing_post_returns_404(client):
    test_admin_email = 'test_admin@email.invalid'
    test_admin_password = 'passadmin123'
    test_admin_name = 'test_admin'

    hashed_admin_password = generate_password_hash(
        test_admin_password,
        method='pbkdf2:sha256',
        salt_length=8
    )

    admin = User(
        email=test_admin_email,
        password=hashed_admin_password,
        name=test_admin_name,
        is_admin=True,
    )
    db.session.add(admin)
    db.session.commit()
    assert admin.is_admin == True

    response = client.post(
        "/login",
        data={
            'email': test_admin_email,
            'password': test_admin_password,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    response = client.post(
        "/delete/999",
        follow_redirects=False,
    )

    assert response.status_code == 404


def test_comment_on_missing_post_returns_404_and_is_not_saved(client):
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

    # create user
    user = User(
        email=test_user_email,
        password=hashed_user_password,
        name=test_user_name,
    )
    db.session.add(user)
    db.session.commit()
    user_id = user.id
    assert user_id == 2

    # log in user
    response = client.post(
        "/login",
        data={
            'email': test_user_email,
            'password': test_user_password,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    comment_text = "This comment should never be saved"

    response = client.post(
        "/post/999",
        data={
            "comment": comment_text,
        },
        follow_redirects=False,
    )

    assert response.status_code == 404

    db.session.remove()

    stmt = db.select(
        Comment
    ).where(
        Comment.comment == comment_text
    )

    saved_comment = db.session.execute(
        stmt
    ).scalar_one_or_none()

    assert saved_comment is None


def test_admin_role_allows_non_id_one_user(client):
    # create ordinary user first -> should become id 1
    test1_user_email = 'test1_user@email.invalid'
    test1_user_password = 'passtest123'
    test1_user_name = 'test1_user'

    hashed_user1_password = generate_password_hash(
        test1_user_password,
        method='pbkdf2:sha256',
        salt_length=8
    )

    user1 = User(
        email=test1_user_email,
        password=hashed_user1_password,
        name=test1_user_name,
    )
    db.session.add(user1)
    db.session.commit()
    user1_id = user1.id
    user1_is_admin = user1.is_admin
    assert user1_id == 1
    assert user1_is_admin == False

    # create another user with is_admin=True -> should become id 2
    test_user2_email = 'test_user2@email.invalid'
    test_user2_password = 'passtest123'
    test_user2_name = 'test_user2'

    hashed_user2_password = generate_password_hash(
        test_user2_password,
        method='pbkdf2:sha256',
        salt_length=8
    )

    # create user
    user2 = User(
        email=test_user2_email,
        password=hashed_user2_password,
        name=test_user2_name,
        is_admin=True,
    )
    db.session.add(user2)
    db.session.commit()
    user2_id = user2.id
    user2_is_admin = user2.is_admin
    assert user2_id == 2
    assert user2_is_admin == True

    # log in as the second user
    response = client.post(
        "/login",
        data={
            'email': test_user2_email,
            'password': test_user2_password,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    response = client.get("/new-post")

    assert response.status_code == 200


def test_id_one_without_admin_role_gets_403(client):
    # create first user with is_admin=False
    # confirm this user got id 1
    test1_user_email = 'test1_user@email.invalid'
    test1_user_password = 'passtest123'
    test1_user_name = 'test1_user'

    hashed_user1_password = generate_password_hash(
        test1_user_password,
        method='pbkdf2:sha256',
        salt_length=8
    )

    user1 = User(
        email=test1_user_email,
        password=hashed_user1_password,
        name=test1_user_name,
    )
    db.session.add(user1)
    db.session.commit()
    user1_id = user1.id
    user1_is_admin = user1.is_admin
    assert user1_id == 1
    assert user1_is_admin == False

    # log in as that user
    response = client.post(
        "/login",
        data={
            'email': test1_user_email,
            'password': test1_user_password,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    response = client.get("/new-post")

    assert response.status_code == 403


def test_admin_can_delete_post(client):
    test_admin_email = "test_admin@email.invalid"
    test_admin_password = "passadmin123"

    hashed_password = generate_password_hash(
        test_admin_password,
        method="pbkdf2:sha256",
        salt_length=8,
    )

    admin = User(
        email=test_admin_email,
        password=hashed_password,
        name="test_admin",
        is_admin=True,
    )
    db.session.add(admin)
    db.session.commit()

    post = BlogPost(
        title="Post to delete",
        subtitle="Delete test",
        body="This post should disappear",
        img_url="https://www.example.com/img.jpg",
        published_on=date.today(),
        poster_id=admin.id,
    )
    db.session.add(post)
    db.session.commit()
    post_id = post.id

    response = client.post(
        "/login",
        data={
            "email": test_admin_email,
            "password": test_admin_password,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200

    response = client.post(
        f"/delete/{post_id}",
        follow_redirects=False,
    )

    assert response.status_code == 302

    db.session.remove()

    deleted_post = db.session.get(BlogPost, post_id)

    assert deleted_post is None


def test_make_admin_command_promotes_user(app):
    user = User(
        email="future-admin@email.invalid",
        password="not-used-here",
        name="future-admin",
    )
    db.session.add(user)
    db.session.commit()

    assert user.is_admin is False

    runner = app.test_cli_runner()

    result = runner.invoke(
        args=["make-admin", "future-admin@email.invalid"]
    )

    assert result.exit_code == 0

    db.session.remove()

    promoted_user = db.session.execute(
        db.select(User).where(
            User.email == "future-admin@email.invalid"
        )
    ).scalar_one()

    assert promoted_user.is_admin is True


def test_home_page_lists_newest_posts_first(client):
    user = User(
        email="author@email.invalid",
        password="not-used",
        name="author",
    )
    db.session.add(user)
    db.session.commit()

    test_date_1 = date(2025, 1, 10)
    older_post = BlogPost(
        title="Older Post",
        subtitle="Older",
        body="Older body",
        img_url="https://www.example.com/older.jpg",
        published_on=test_date_1,
        poster_id=user.id,
    )

    test_date_2 = date(2026, 1, 10)
    newer_post = BlogPost(
        title="Newer Post",
        subtitle="Newer",
        body="Newer body",
        img_url="https://www.example.com/newer.jpg",
        published_on=test_date_2,
        poster_id=user.id,
    )

    db.session.add(older_post)
    db.session.add(newer_post)
    db.session.commit()

    response = client.get("/")

    assert response.status_code == 200

    html = response.get_data(as_text=True)

    older_position = html.index("Older Post")
    newer_position = html.index("Newer Post")

    assert newer_position < older_position


def test_same_day_posts_list_newest_first(client):
    # create user
    user = User(
        email="author@email.invalid",
        password="not-used",
        name="author",
    )
    db.session.add(user)
    db.session.commit()

    same_day = date(2026, 10, 6)
    first_post = BlogPost(
        title="First Post",
        subtitle="First",
        body="First body",
        img_url="https://www.example.com/first.jpg",
        published_on=same_day,
        poster_id=user.id,
    )

    second_post = BlogPost(
        title="Second Post",
        subtitle="Second",
        body="Second body",
        img_url="https://www.example.com/second.jpg",
        published_on=same_day,
        poster_id=user.id,
    )

    third_post = BlogPost(
        title="Third Post",
        subtitle="Third",
        body="Third body",
        img_url="https://www.example.com/third.jpg",
        published_on=same_day,
        poster_id=user.id,
    )

    db.session.add(first_post)
    db.session.add(second_post)
    db.session.add(third_post)
    db.session.commit()

    response = client.get("/")
    html = response.get_data(as_text=True)

    first_position = html.index("First Post")
    second_position = html.index("Second Post")
    third_position = html.index("Third Post")

    assert third_position < second_position < first_position
