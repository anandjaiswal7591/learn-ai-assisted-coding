# User authentication REST API

Express REST API for user registration, login, and role-based authorization backed by SQLite. It runs on Bun and stores only an id, unique username, email, display name, role, password hash, and creation timestamp for each user.

## Setup

```bash
bun install
copy .env.example .env
```

Set `JWT_SECRET` in `.env` to a long random value before starting the server.

```bash
bun run start
```

The API listens on `http://localhost:3000` by default. The SQLite database is created at `data/auth.sqlite`; set `DATABASE_PATH` to change it.

## Endpoints

### Register

`POST /api/auth/register`

```json
{
  "username": "alex_123",
  "email": "alex@example.com",
  "name": "Alex",
  "password": "a-password-at-least-8-characters"
}
```

Returns `201` with a sanitized user and a one-hour JWT. Usernames are case-insensitive, must be 3-30 characters using lowercase letters, numbers, or underscores, and passwords are hashed before storage.

### Login

`POST /api/auth/login` with `username` and `password`:

```json
{
  "username": "alex_123",
  "password": "a-password-at-least-8-characters"
}
```

Returns `401` for invalid credentials and otherwise returns the sanitized user and JWT.

### Current user

`GET /api/users/me` with `Authorization: Bearer <token>`.

### Admin user lookup

`GET /api/admin/users/:id` with an admin JWT. New accounts have the `user` role. Promote an account directly in SQLite when bootstrapping an administrator:

```sql
UPDATE users SET role = 'admin' WHERE email = 'admin@example.com';
```

## Development

```bash
bun run dev
bun run typecheck
```
