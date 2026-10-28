import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { Database } from "bun:sqlite";

export type UserRole = "user" | "admin";

export interface User {
  id: number;
  username: string;
  email: string;
  name: string;
  role: UserRole;
  created_at: string;
}

export interface UserWithPassword extends User {
  password_hash: string;
}

const databasePath = process.env.DATABASE_PATH ?? "./data/auth.sqlite";
mkdirSync(dirname(databasePath), { recursive: true });

export const db = new Database(databasePath, { strict: true });

db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

const userColumns = db
  .query<{ name: string }, []>("PRAGMA table_info(users)")
  .all();
if (!userColumns.some((column) => column.name === "username")) {
  db.run("ALTER TABLE users ADD COLUMN username TEXT");
  db.run(
    "UPDATE users SET username = lower(substr(email, 1, instr(email, '@') - 1)) || '_' || id WHERE username IS NULL",
  );
}
db.run(
  "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username COLLATE NOCASE)",
);

export function findUserByEmail(email: string): UserWithPassword | null {
  return db
    .query<UserWithPassword, [string]>(
      "SELECT id, username, email, name, password_hash, role, created_at FROM users WHERE email = ?",
    )
    .get(email);
}

export function findUserByUsername(username: string): UserWithPassword | null {
  return db
    .query<UserWithPassword, [string]>(
      "SELECT id, username, email, name, password_hash, role, created_at FROM users WHERE username = ?",
    )
    .get(username);
}

export function findUserById(id: number): UserWithPassword | null {
  return db
    .query<UserWithPassword, [number]>(
      "SELECT id, username, email, name, password_hash, role, created_at FROM users WHERE id = ?",
    )
    .get(id);
}

export function createUser(
  username: string,
  email: string,
  name: string,
  passwordHash: string,
): User {
  const result = db
    .query(
      "INSERT INTO users (username, email, name, password_hash) VALUES (?, ?, ?, ?) RETURNING id, username, email, name, role, created_at",
    )
    .get(username, email, name, passwordHash);

  if (!result) {
    throw new Error("User was not created");
  }

  return result as User;
}
