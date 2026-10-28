import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import type { NextFunction, Request, Response } from "express";
import type { User, UserRole } from "./db.ts";
import { findUserById } from "./db.ts";

const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  throw new Error("JWT_SECRET must be set before starting the server");
}
const secret: string = jwtSecret;

export interface AuthenticatedRequest extends Request {
  user?: User;
}

interface TokenPayload extends jwt.JwtPayload {
  userId: number;
  role: UserRole;
}

function isTokenPayload(payload: string | jwt.JwtPayload): payload is TokenPayload {
  return (
    typeof payload !== "string" &&
    typeof payload.userId === "number" &&
    (payload.role === "user" || payload.role === "admin")
  );
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(
  password: string,
  passwordHash: string,
): Promise<boolean> {
  return bcrypt.compare(password, passwordHash);
}

export function createToken(user: User): string {
  return jwt.sign({ userId: user.id, role: user.role }, secret, {
    expiresIn: "1h",
  });
}

export function authenticate(
  request: AuthenticatedRequest,
  response: Response,
  next: NextFunction,
): void {
  const header = request.header("authorization");
  const token = header?.startsWith("Bearer ") ? header.slice(7) : undefined;

  if (!token) {
    response.status(401).json({ error: "Authentication token is required" });
    return;
  }

  try {
    const payload = jwt.verify(token, secret);
    if (!isTokenPayload(payload)) {
      response.status(401).json({ error: "Invalid authentication token" });
      return;
    }

    const user = findUserById(payload.userId);
    if (!user) {
      response.status(401).json({ error: "User no longer exists" });
      return;
    }

    request.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      name: user.name,
      role: user.role,
      created_at: user.created_at,
    };
    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError || error instanceof jwt.TokenExpiredError) {
      response.status(401).json({ error: "Invalid or expired authentication token" });
      return;
    }
    next(error);
  }
}

export function requireRole(role: UserRole) {
  return (
    request: AuthenticatedRequest,
    response: Response,
    next: NextFunction,
  ): void => {
    if (request.user?.role !== role) {
      response.status(403).json({ error: "Insufficient permissions" });
      return;
    }
    next();
  };
}
