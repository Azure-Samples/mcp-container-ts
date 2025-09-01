console.warn("WARNING: This file is for demonstration purposes only.");
console.warn("WARNING: It generates a JWT token and writes it to a .env file.");
console.warn(
  "WARNING: In a real application, you should securely manage your secrets and tokens."
);
console.warn(
  "WARNING: Do not use this in production without proper security measures."
);

import { writeFileSync, readFileSync, existsSync } from "fs";
import { randomBytes } from "crypto";
import jwt from "jsonwebtoken";
import { getUserPermissions, UserRole } from "./authorization";

// define dummy values for JWT_SECRET, JWT_EXPIRY, and PAYLOAD
const JWT_SECRET = randomBytes(32).toString('base64');
const JWT_EXPIRY = "1h";
const JWT_AUDIENCE = "urn:foo";
const JWT_ISSUER = "urn:bar";
const PAYLOAD = {
  issuer: JWT_ISSUER,
  audience: JWT_AUDIENCE,
  id: "user-id-123",
  email: "user@example.com",
  role: UserRole.ADMIN,
  permissions: getUserPermissions(UserRole.ADMIN)
};

const token = jwt.sign(PAYLOAD, JWT_SECRET, {
  algorithm: "HS256",
  expiresIn: JWT_EXPIRY,
});

// Define JWT variables to update
const jwtVariables = {
  JWT_AUDIENCE: JWT_AUDIENCE,
  JWT_ISSUER: JWT_ISSUER,
  JWT_EXPIRY: JWT_EXPIRY,
  JWT_SECRET: JWT_SECRET,
  JWT_TOKEN: token
};

// Read existing .env file if it exists
let envContent = "";
if (existsSync(".env")) {
  envContent = readFileSync(".env", "utf8");
}

// Replace or append each JWT variable
for (const [key, value] of Object.entries(jwtVariables)) {
  const regex = new RegExp(`^${key}=.*$`, 'm');
  const replacement = `${key}="${value}"`;
  
  if (regex.test(envContent)) {
    // Replace existing variable
    envContent = envContent.replace(regex, replacement);
  } else {
    // Append new variable
    if (envContent && !envContent.endsWith("\n")) {
      envContent += "\n";
    }
    envContent += replacement + "\n";
  }
}

writeFileSync(".env", envContent);