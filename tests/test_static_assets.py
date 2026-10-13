import re
from datetime import date

from werkzeug.security import generate_password_hash

from blog.extensions import db
from blog.models import BlogPost, User


STATIC_URL_PATTERN = re.compile(r"""['"](/static/[^'"]+)""")


def _static_urls(response):
    html = response.get_data(as_text=True)
    return set(STATIC_URL_PATTERN.findall(html))


def _render_covered_pages(client):
    responses = [
        client.get("/"),
        client.get("/about"),
        client.get("/contact"),
        client.get("/login"),
        client.get("/register"),
    ]

    admin_password = "static-test-password"

    admin = User(
        email="static-admin@email.invalid",
        password=generate_password_hash(
            admin_password,
            method="pbkdf2:sha256",
            salt_length=8,
        ),
        name="static-admin",
        is_admin=True,
    )
    db.session.add(admin)
    db.session.commit()

    post = BlogPost(
        title="Static Asset Test",
        subtitle="Static asset coverage",
        body="Test body",
        img_url="https://www.example.com/test.jpg",
        published_on=date.today(),
        poster_id=admin.id,
    )
    db.session.add(post)
    db.session.commit()

    login_response = client.post(
        "/login",
        data={
            "email": admin.email,
            "password": admin_password,
        },
        follow_redirects=True,
    )
    assert login_response.status_code == 200

    responses.extend(
        [
            client.get("/new-post"),
            client.get(f"/edit-post/{post.id}"),
            client.get(f"/post/{post.id}"),
        ]
    )

    return responses


def test_rendered_pages_reference_existing_static_assets(client):
    responses = _render_covered_pages(client)

    static_urls = set()

    for response in responses:
        assert response.status_code == 200
        static_urls.update(_static_urls(response))

    assert static_urls

    for static_url in sorted(static_urls):
        response = client.get(static_url)
        assert response.status_code == 200, (
            f"Missing static asset: {static_url}"
        )


def test_rendered_pages_use_single_frontend_stack(client):
    responses = _render_covered_pages(client)

    for response in responses:
        assert response.status_code == 200

        html = response.get_data(as_text=True)

        bootstrap_stylesheets = re.findall(
            r"""href=['"][^'"]*bootstrap[^'"]*\.css[^'"]*['"]""",
            html,
            flags=re.IGNORECASE,
        )
        jquery_scripts = re.findall(
            r"""src=['"][^'"]*jquery[^'"]*\.js[^'"]*['"]""",
            html,
            flags=re.IGNORECASE,
        )

        assert html.lower().count("<!doctype html>") == 1
        assert len(bootstrap_stylesheets) == 1
        assert len(jquery_scripts) == 1
        assert "3.3.7" not in html
