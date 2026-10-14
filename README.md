# George's Blog

[![CI](https://github.com/georges1138/george-blog/actions/workflows/ci.yml/badge.svg)](https://github.com/georges1138/george-blog/actions/workflows/ci.yml)

A Flask blog application I audited and modernized with security fixes, automated tests, database migrations, Docker, continuous integration, and a live Railway deployment.

**Live site:** https://george-blog-production.up.railway.app

## Project Overview

George's Blog began as a small Flask application and was modernized into a more maintainable, testable, and production-ready project.

The work focused on four areas:

- improving application security
- separating application responsibilities into clearer layers
- replacing ad-hoc database setup with versioned migrations
- adding repeatable testing, containerization, CI, and production deployment

## Modernization at a Glance

| Before | After |
| --- | --- |
| Most application logic lived in one `main.py` file | App factory with blueprints, controllers, services, and models |
| Database tables were created directly by the application | Versioned schema changes with Flask-Migrate and Alembic |
| No automated test suite | 24 pytest tests covering application behavior and production configuration |
| No continuous integration | GitHub Actions runs tests and migration checks on every push |
| Large vendored frontend dependencies lived in the repository | Static files reduced from 12 MB to 0.9 MB; about 67,000 vendored lines removed; container image reduced from 95.2 MB to 84.4 MB |
| Development-oriented startup only | Docker, Gunicorn, PostgreSQL, and a live Railway deployment |

## Security Audit & Fixes

The modernization work included a review of several security and reliability problems in the original application.

| Finding | Why It Matters | Fix | Commit |
| --- | --- | --- | --- |
| User-supplied comment HTML could be stored and rendered as trusted markup | A malicious comment could introduce stored cross-site scripting (XSS) | Sanitize comments when they are saved using an `nh3` allowlist | [`fbd6ef9`](https://github.com/georges1138/george-blog/commit/fbd6ef94df288acff8b6874ec3718a9416b98d04) |
| Posts could be deleted with a GET request and no CSRF validation | A destructive action could be triggered without an intentional form submission | Require POST for deletes and enable application-wide CSRF protection | [`676426c`](https://github.com/georges1138/george-blog/commit/676426ce4006e1caa9550f434af14defcadd2f16) |
| Admin access depended on the hard-coded user ID `1` | Authorization depended on database insertion order instead of an explicit role | Add an `is_admin` role, migrate the existing admin, and provide a `make-admin` CLI command | [`09a88f9`](https://github.com/georges1138/george-blog/commit/09a88f9cc4bfdba08b73d517e5870a36a9698f6f), [`acd9594`](https://github.com/georges1138/george-blog/commit/acd9594544b178afdfb13ca9c8c9aa1f9e524c36) |
| Login errors revealed whether an email address was registered | Different responses could be used to enumerate accounts | Return the same generic error for an unknown email or incorrect password | [`f10b925`](https://github.com/georges1138/george-blog/commit/f10b925dc7a3bd70d2f72fa28ff4af42ffbdecb2) |
| Requests for missing posts could produce application errors | Invalid URLs should fail predictably instead of reaching code that expects a record | Return HTTP 404 when a requested post does not exist | [`23b490f`](https://github.com/georges1138/george-blog/commit/23b490f7108b172561ab4e09a7c42a5efe7c97b2) |
| Pages could load conflicting Bootstrap and jQuery stacks through an outdated integration | Duplicate frontend frameworks increase maintenance risk and can cause inconsistent behavior | Replace Flask-Bootstrap with Bootstrap-Flask and add regression coverage for the frontend stack | [`647903c`](https://github.com/georges1138/george-blog/commit/647903cfeb5981d14c1aa1f710daa2c6445fff04) |
| Third-party frontend assets were vendored directly in the repository | Large copied dependencies are harder to audit and keep current | Replace vendored dependencies with pinned CDN resources protected by Subresource Integrity (SRI) | [`3b06b27`](https://github.com/georges1138/george-blog/commit/3b06b27b6231b9dfe6a1cb073ab6f1c4a1277735) |
| The application lacked production-specific hardening | Development assumptions do not hold when the app runs behind a public HTTPS proxy | Add secure cookie settings, `ProxyFix`, a non-root container user, production Gunicorn settings, and graceful shutdown | [`4d3c006`](https://github.com/georges1138/george-blog/commit/4d3c00607a40740f848db2d38c823ea7c3524809), [`dfbf874`](https://github.com/georges1138/george-blog/commit/dfbf87481317ccf27af7bcfbed135935d34857a0), [`44a4755`](https://github.com/georges1138/george-blog/commit/44a4755932555c8d28d4dcb3182870eb95e6fd31) |

The generic login-error fix was made as part of the service-layer refactor in `f10b925`, rather than as a standalone security commit.

## Known Limitations

This project intentionally remains small, and a few areas were left for future improvement:

- Post bodies are rendered as trusted HTML with Jinja's `|safe` filter. Only administrators can create or edit posts, so this is treated as trusted author content rather than user-submitted content.
- Logout is currently performed with a GET request. A future revision could change this to POST with CSRF protection, matching the approach used for destructive actions such as post deletion.
- Flask-CKEditor uses CKEditor 4, which has reached end of life. Replacing the editor is a future maintenance task.
- The login endpoint does not currently implement rate limiting or account lockout protection.
- The PostgreSQL credentials in `compose.yaml` are development-only values and are not used in production.
- Local Docker Compose runs over `http://localhost`. Browser handling of secure cookies on localhost is a development-specific exception and should not be treated as equivalent to production HTTPS.
- The CI migration round trip starts from a fresh PostgreSQL database. It verifies upgrade, downgrade, drift detection, and re-upgrade behavior, but does not currently test migrations against a copy of production data.

## Tech Stack & Architecture

- **Backend:** Python 3.12, Flask, SQLAlchemy, Flask-Migrate/Alembic, PostgreSQL, psycopg 3
- **Frontend:** Bootstrap 4.6 and jQuery 3.7 from pinned CDN links with SRI, forms rendered with Bootstrap-Flask, Jinja templates, CKEditor 4
- **Testing & tooling:** pytest, uv, GitHub Actions
- **Deployment:** Docker, Docker Compose, Gunicorn, Railway

The application uses Flask's app-factory pattern. Extensions are created independently in `extensions.py` and initialized inside `create_app()`, which keeps application setup centralized while remaining testable.

Request handling is separated into controllers, services, and models so that route code stays focused on HTTP concerns while reusable application logic lives outside the Flask views.

```text
blog/
├── __init__.py          # create_app() and application configuration
├── extensions.py        # Flask extension instances
├── forms.py             # WTForms definitions
├── controllers/
│   ├── auth.py          # registration, login, and logout routes
│   ├── main.py          # public page routes
│   └── posts.py         # post-management routes
├── services/
│   ├── user_service.py
│   ├── post_service.py
│   └── comment_service.py
├── models/
│   ├── user.py
│   ├── post.py
│   └── comment.py
├── templates/
└── static/

migrations/              # Alembic migration history
tests/                   # pytest suite
compose.yaml              # local PostgreSQL + migration + app services
Dockerfile                # production container
.github/workflows/ci.yml  # tests and migration validation
```
## Getting Started

### Docker Compose

Docker Compose is the simplest way to run the complete application locally with PostgreSQL and database migrations.

1. Clone the repository and enter the project directory:

   ```bash
   git clone https://github.com/georges1138/george-blog.git
   cd george-blog
   ```

2. Create a local environment file from the example:

   **PowerShell:**

   ```powershell
   Copy-Item .env.example .env
   ```

   **macOS/Linux:**

   ```bash
   cp .env.example .env
   ```

3. Replace the placeholder `SECRET_KEY` in `.env` with a random value. For example:

   ```bash
   uv run python -c "import secrets; print(secrets.token_hex(32))"
   ```

4. Build and start the application:

   ```bash
   docker compose up --build
   ```

   Compose starts PostgreSQL, waits for it to become healthy, applies Alembic migrations, and then starts the Flask application.

5. Open:

   ```text
   http://localhost:5001
   ```
### Creating an Admin

Register a user through the application first. Then promote that account from another terminal:

```bash
docker compose exec app flask --app blog make-admin you@example.com
```

To stop the local environment:

```bash
docker compose down
```

Note: The PostgreSQL data is stored in a Docker volume and remains available between normal `docker compose down` / `docker compose up` cycles.

## Tests & Continuous Integration

The project currently has **24 pytest tests** covering core application behavior, security regressions, static assets, and production configuration.

Run the complete test suite locally with:

```bash
uv run pytest
```

GitHub Actions runs two CI jobs on every push and pull request:

### Application Tests

The test job:

1. Checks out the repository.
2. Installs the locked dependencies with `uv`.
3. Runs the complete pytest suite.

```bash
uv run pytest -v
```

### Migration Validation

A separate CI job starts a clean PostgreSQL 16 database and verifies the Alembic migration chain by running:

```bash
uv run flask --app blog db upgrade
uv run flask --app blog db check
uv run flask --app blog db downgrade base
uv run flask --app blog db upgrade
```

This confirms that the schema can be built from scratch, contains no model/migration drift, can be downgraded to the base revision, and can then be upgraded successfully again.

### Verifying CI Failure Detection

The migration drift check was also tested deliberately on a temporary branch. Commit [`883d8ac`](https://github.com/georges1138/george-blog/commit/883d8acec90bcc41bda68389b69e22d978c0b0a7), preserved as the [`ci-drift-probe`](https://github.com/georges1138/george-blog/tree/ci-drift-probe) tag, added a model column without creating a corresponding migration.

The application tests still ran, but the migration job failed as expected because Alembic detected that the models and migration history no longer matched. The probe was not merged into `master`.

That experiment verified that CI catches a class of database change that ordinary application tests may miss.

## Database Migrations

Database schema changes are managed with **Flask-Migrate and Alembic** rather than creating tables automatically at application startup.

The migration history begins with the original application schema and then tracks later structural changes, including the admin-role migration and the conversion of blog post dates from strings to a real SQL `DATE` column.

### Date Conversion

The original application stored publication dates as formatted strings such as:

```text
October 13, 2026
```

A later migration converts those values into real database dates before replacing the old string column. The downgrade path converts the dates back into the original display format.

This matters because dates can now be sorted and queried as dates instead of as presentation text.

The migration was also adjusted to behave consistently across SQLite and PostgreSQL. See [`65bd9a2`](https://github.com/georges1138/george-blog/commit/65bd9a2fe4dc8a21bec972943b5a680826edb175).

### Common Commands

Apply all pending migrations:

```bash
uv run flask --app blog db upgrade
```

Check whether the SQLAlchemy models and migration history have drifted apart:

```bash
uv run flask --app blog db check
```

View the migration history:

```bash
uv run flask --app blog db history
```

The initial migration setup was introduced in [`4613d54`](https://github.com/georges1138/george-blog/commit/4613d54cfdfbabb746c4b0e4a35a788689117047).

## Deployment

The production application runs on **Railway** with a managed PostgreSQL database.

Railway builds the application from the repository's `Dockerfile`. The app runs under Gunicorn, binds to Railway's assigned `PORT`, and runs as a non-root container user.

Production configuration includes:

- `DATABASE_URL` references Railway's PostgreSQL service rather than storing credentials in the repository.
- `SECRET_KEY` is provided as a Railway environment variable.
- `flask --app blog db upgrade` runs as a pre-deploy command so database migrations complete before a new version begins serving traffic.
- Pushes to `master` automatically trigger a new Railway deployment.
- Railway terminates HTTPS at the proxy, while Flask uses `ProxyFix` and secure session-cookie settings behind it.

**Live application:** https://george-blog-production.up.railway.app

## Design Decisions

- **Keep services independent of Flask.** Business logic lives in service classes without depending on request or application context, which makes it easier to test and reuse.

- **Sanitize comments when they are saved.** User-submitted HTML is cleaned once before it reaches the database instead of relying on every template to sanitize it correctly later.

- **Use psycopg 3 for PostgreSQL.** SQLAlchemy 2.1 made psycopg 3 the default PostgreSQL driver for plain `postgresql://` URLs, which works cleanly with provider-supplied connection URLs without requiring a driver suffix.

- **Use pinned CDN assets with SRI.** Large third-party frontend libraries are not vendored into the repository; pinned CDN resources with Subresource Integrity keep the repository smaller while still verifying downloaded assets.
