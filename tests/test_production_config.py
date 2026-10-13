from blog import create_app


def test_legacy_postgres_url_is_normalized(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgres://user:password@localhost/example",
    )

    app = create_app()

    assert (
        app.config["SQLALCHEMY_DATABASE_URI"]
        == "postgresql://user:password@localhost/example"
    )


def test_production_uses_secure_cookie_settings(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://user:password@localhost/example",
    )

    app = create_app()

    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["REMEMBER_COOKIE_SECURE"] is True


def test_test_config_keeps_secure_cookies_off():
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        }
    )

    assert app.config["SESSION_COOKIE_SECURE"] is False
    assert app.config.get("REMEMBER_COOKIE_SECURE", False) is False
