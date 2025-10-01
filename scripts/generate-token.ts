console.warn(
  "------------------------------------------------------------------------------------------------------------"
);
console.warn("WARNING: This script is for demonstration purposes only.");
console.warn("WARNING: It generates a JWT token and writes it to a .env file.");
console.warn(
  "WARNING: In a real application, you should securely manage your secrets and tokens."
);
console.warn(
  "WARNING: Do not use this in production without proper security measures."
);
console.warn(
  "------------------------------------------------------------------------------------------------------------"
);
console.warn(
  "Learn more: https://learn.microsoft.com/azure/security/fundamentals/secrets-best-practices"
);
console.warn(
  "------------------------------------------------------------------------------------------------------------"
);
console.warn("");

import { writeFileSync, readFileSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import jwt from "jsonwebtoken";
import {
  USER_DETAILS_ADMIN_DEMO,
  USER_DETAILS_READONLY_DEMO,
  USER_DETAILS_USER_DEMO,
} from "../src/auth/user-details-demo";

// define dummy values for JWT_SECRET, JWT_EXPIRY, and PAYLOAD
const JWT_SECRET = randomBytes(32).toString("base64");
const JWT_EXPIRY = "48h";
const JWT_AUDIENCE = "urn:foo";
const JWT_ISSUER = "urn:bar";
const USER_ROLE =
  process.argv[2] === "--admin"
    ? USER_DETAILS_ADMIN_DEMO
    : process.argv[2] === "--user"
    ? USER_DETAILS_USER_DEMO
    : USER_DETAILS_READONLY_DEMO;
const PAYLOAD = {
  issuer: JWT_ISSUER,
  audience: JWT_AUDIENCE,
  ...USER_ROLE,
};

const JWT_TOKEN = jwt.sign(PAYLOAD, JWT_SECRET, {
  algorithm: "HS256",
  expiresIn: JWT_EXPIRY,
});

// Define JWT variables to update
const jwtVariables = {
  JWT_AUDIENCE,
  JWT_ISSUER,
  JWT_EXPIRY,
  JWT_SECRET,
  JWT_TOKEN,
};

console.log(`Generated JWT token for role=${USER_ROLE.role}: `, jwtVariables);

// Read existing .env file if it exists
let envContent = "";
if (existsSync(".env")) {
  envContent = readFileSync(".env", "utf8");
}

// Replace or append each JWT variable
for (const [key, value] of Object.entries(jwtVariables)) {
  const regex = new RegExp(`^${key}=.*$`, "m");
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
