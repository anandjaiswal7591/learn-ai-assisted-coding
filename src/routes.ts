import { Router } from "express";
import {
  authenticate,
  createToken,
  hashPassword,
  requireRole,
  verifyPassword,
  type AuthenticatedRequest,
} from "./auth.ts";
import {
  createUser,
  findUserByEmail,
  findUserById,
  findUserByUsername,
  type User,
} from "./db.ts";

const router = Router();

const publicUser = (user: User) => ({
  id: user.id,
  username: user.username,
  email: user.email,
  name: user.name,
  role: user.role,
  createdAt: user.created_at,
});

router.post("/auth/register", async (request, response, next) => {
  const { username, email, name, password } = request.body as {
    username?: unknown;
    email?: unknown;
    name?: unknown;
    password?: unknown;
  };

  if (
    typeof username !== "string" ||
    typeof email !== "string" ||
    typeof name !== "string" ||
    typeof password !== "string"
  ) {
    response.status(400).json({
      error: "username, email, name, and password are required",
    });
    return;
  }

  const normalizedEmail = email.trim().toLowerCase();
  const normalizedUsername = username.trim().toLowerCase();
  const trimmedName = name.trim();
  if (
    !/^[a-z0-9_]{3,30}$/.test(normalizedUsername) ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail) ||
    trimmedName.length < 1 ||
    trimmedName.length > 100 ||
    password.length < 8 ||
    password.length > 72
  ) {
    response.status(400).json({
      error:
        "Provide a username with 3-30 lowercase letters, numbers, or underscores, a valid email, a name between 1 and 100 characters, and a password between 8 and 72 characters",
    });
    return;
  }

  if (findUserByEmail(normalizedEmail)) {
    response.status(409).json({ error: "An account with that email already exists" });
    return;
  }
  if (findUserByUsername(normalizedUsername)) {
    response.status(409).json({ error: "That username is already taken" });
    return;
  }

  try {
    const user = createUser(
      normalizedUsername,
      normalizedEmail,
      trimmedName,
      await hashPassword(password),
    );
    response.status(201).json({ user: publicUser(user), token: createToken(user) });
  } catch (error) {
    if (error instanceof Error && error.message.includes("UNIQUE constraint failed")) {
      response.status(409).json({ error: "That username or email is already in use" });
      return;
    }
    next(error);
  }
});

router.post("/auth/login", async (request, response) => {
  const { username, password } = request.body as {
    username?: unknown;
    password?: unknown;
  };
  if (typeof username !== "string" || typeof password !== "string") {
    response.status(400).json({ error: "username and password are required" });
    return;
  }

  const user = findUserByUsername(username.trim().toLowerCase());
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    response.status(401).json({ error: "Invalid email or password" });
    return;
  }

  response.json({ user: publicUser(user), token: createToken(user) });
});

router.get("/users/me", authenticate, (request: AuthenticatedRequest, response) => {
  response.json({ user: publicUser(request.user!) });
});

router.get(
  "/admin/users/:id",
  authenticate,
  requireRole("admin"),
  (request, response, next) => {
    const id = Number(request.params.id);
    if (!Number.isInteger(id) || id < 1) {
      response.status(400).json({ error: "User id must be a positive integer" });
      return;
    }

    const user = findUserById(id);
    if (!user) {
      response.status(404).json({ error: "User not found" });
      return;
    }

    response.json({ user: publicUser(user) });
  },
);

export default router;
