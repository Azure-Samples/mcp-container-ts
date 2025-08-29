const jwt = require('jsonwebtoken');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ISSUER = process.env.JWT_ISSUER || 'mcp-server';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'mcp-client';
const JWT_EXPIRY = process.env.JWT_EXPIRY || '1h';

if (!JWT_SECRET) {
  console.error('JWT_SECRET not found in .env file');
  process.exit(1);
}

// Create a demo user with all required fields
const demoUser = {
  id: 'demo-user',
  email: 'demo@example.com',
  role: 'admin',
  permissions: [
    'read:todos',
    'create:todos', 
    'update:todos',
    'delete:todos',
    'list:tools',
    'call:tools'
  ]
};

const token = jwt.sign(demoUser, JWT_SECRET, {
  expiresIn: JWT_EXPIRY,
  issuer: JWT_ISSUER,
  audience: JWT_AUDIENCE,
});

console.log('Demo token with user info:');
console.log(token);
console.log('\nToken payload:');
console.log(JSON.stringify(jwt.decode(token), null, 2));
