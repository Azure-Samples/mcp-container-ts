# Authorization Implementation Guide

## Overview

This guide explains how to implement and use the authorization system for your MCP server. The system provides **Role-Based Access Control (RBAC)** with fine-grained permissions.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   JWT Token     │────│  Authentication │────│  Authorization  │
│   (User Info)   │    │   (Who are you) │    │ (What can you do)│
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                                                        ▼
                                              ┌─────────────────┐
                                              │ Tool Execution  │
                                              │   (Secured)     │
                                              └─────────────────┘
```

## User Roles

### 1. **READONLY**
- Can only read todos
- Can list available tools
- **Permissions**: `read:todos`, `list:tools`

### 2. **USER** (Default)
- Can read, create, and update todos
- Cannot delete todos
- **Permissions**: `read:todos`, `create:todos`, `update:todos`, `list:tools`, `call:tools`

### 3. **ADMIN**
- Full access to all operations
- **Permissions**: All permissions including `delete:todos`

## Tool-Permission Mapping

| Tool Name | Required Permissions |
|-----------|---------------------|
| `add_todo` | `create:todos` |
| `list_todos` | `read:todos` |
| `complete_todo` | `update:todos` |
| `delete_todo` | `delete:todos` |
| `updateTodoText` | `update:todos` |

## Environment Variables

Create a `.env` file with the following variables:

```bash
# Required for JWT authentication
JWT_SECRET=your-super-secret-jwt-key-here
JWT_REFRESH_SECRET=your-refresh-secret-here
JWT_EXPIRY=1h
JWT_REFRESH_EXPIRY=7d

# Optional for API key authentication
API_KEYS=api-key-1,api-key-2,api-key-3

# CORS configuration
ALLOWED_ORIGINS=http://localhost:3000,https://your-frontend-domain.com

# Node environment
NODE_ENV=production
```

## Usage Examples

### 1. Creating JWT Tokens

```typescript
import { JWTService } from './src/auth/jwt.js';
import { UserRole } from './src/auth/authorization.js';

// Create token for a regular user
const userToken = JWTService.generateToken({
  id: 'user123',
  email: 'user@example.com',
  role: UserRole.USER
});

// Create token for an admin
const adminToken = JWTService.generateToken({
  id: 'admin456',
  email: 'admin@example.com',
  role: UserRole.ADMIN
});

// Create refresh token
const refreshToken = JWTService.generateRefreshToken('user123');
```

### 2. Making Authenticated Requests

```bash
# Using JWT token
curl -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "tools/list",
    "params": {}
  }'

# Using API key (for service-to-service)
curl -X POST http://localhost:3000/mcp \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "tools/call",
    "params": {
      "name": "add_todo",
      "arguments": {"title": "Buy groceries"}
    }
  }'
```

### 3. Client Integration

```typescript
import { MCPClient } from './src/client.js';

// Create client with JWT token
const client = new MCPClient(
  'my-app', 
  'http://localhost:3000/mcp',
  'YOUR_JWT_TOKEN'
);

await client.connect();

// List available tools (filtered by user permissions)
const tools = await client.getAvailableTools();
console.log('Available tools:', tools);

// Call a tool (subject to authorization)
try {
  const result = await client.callTool('add_todo', '{"title": "Buy milk"}');
  console.log('Tool result:', result);
} catch (error) {
  console.error('Authorization failed:', error);
}
```

## Authorization Responses

### Success Response
```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Tool add_todo executed with arguments {\"title\":\"Buy milk\"}. Result: {\"content\":[\"Added TODO: Buy milk (id: 1)\"]}"
      }
    ]
  }
}
```

### Authorization Failure
```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "error": {
    "code": -32603,
    "message": "Insufficient permissions to call tool: delete_todo"
  }
}
```

### Authentication Failure
```json
{
  "error": "Invalid token",
  "message": "Token expired"
}
```

## Advanced Features

### 1. Custom Permission Checks

```typescript
import { hasPermission, Permission } from './src/auth/authorization.js';

// Check if user has specific permission
const canDelete = hasPermission(user, Permission.DELETE_TODOS);

// Middleware for custom permission checking
app.use('/admin', requirePermission(Permission.DELETE_TODOS));
```

### 2. Role-Based Routes

```typescript
import { requireRole, UserRole } from './src/auth/authorization.js';

// Admin-only endpoint
app.get('/admin/stats', requireRole(UserRole.ADMIN), (req, res) => {
  // Admin logic here
});
```

### 3. Token Refresh

```typescript
import { JWTService } from './src/auth/jwt.js';

app.post('/auth/refresh', (req, res) => {
  try {
    const { refreshToken } = req.body;
    const payload = JWTService.verifyRefreshToken(refreshToken);
    
    // Generate new access token
    const newToken = JWTService.generateToken({
      id: payload.id,
      email: user.email, // Get from database
      role: user.role    // Get from database
    });
    
    res.json({ token: newToken });
  } catch (error) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});
```

## Security Best Practices

### 1. Token Management
- Use short-lived access tokens (1 hour)
- Implement token refresh mechanism
- Store refresh tokens securely (database, not localStorage)

### 2. Permission Validation
- Always validate permissions on the server side
- Use principle of least privilege
- Regularly audit user permissions

### 3. Environment Security
- Never commit secrets to version control
- Use environment variables for all sensitive data
- Rotate JWT secrets regularly

### 4. Logging and Monitoring
- Log all authentication attempts
- Monitor for suspicious permission requests
- Set up alerts for failed authorization attempts

## Testing Authorization

### 1. Unit Tests

```typescript
import { hasPermission, Permission, UserRole } from './src/auth/authorization.js';

describe('Authorization', () => {
  test('USER role can create todos', () => {
    const user = { id: '1', email: 'test@example.com', role: UserRole.USER };
    expect(hasPermission(user, Permission.CREATE_TODOS)).toBe(true);
  });

  test('READONLY role cannot delete todos', () => {
    const user = { id: '1', email: 'test@example.com', role: UserRole.READONLY };
    expect(hasPermission(user, Permission.DELETE_TODOS)).toBe(false);
  });
});
```

### 2. Integration Tests

```typescript
import request from 'supertest';
import { app } from './src/index.js';

describe('MCP Authorization', () => {
  test('should reject unauthenticated requests', async () => {
    const response = await request(app)
      .post('/mcp')
      .send({
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/list',
        params: {}
      });
    
    expect(response.status).toBe(401);
  });

  test('should allow authorized tool calls', async () => {
    const token = generateTestToken(UserRole.USER);
    const response = await request(app)
      .post('/mcp')
      .set('Authorization', `Bearer ${token}`)
      .send({
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: {
          name: 'add_todo',
          arguments: { title: 'Test todo' }
        }
      });
    
    expect(response.status).toBe(200);
  });
});
```

## Troubleshooting

### Common Issues

1. **"JWT_SECRET environment variable is required"**
   - Ensure `.env` file is loaded
   - Check that `JWT_SECRET` is set

2. **"Invalid token"**
   - Verify token is not expired
   - Check that JWT_SECRET matches the one used to sign the token

3. **"Insufficient permissions"**
   - Verify user role has required permissions
   - Check tool-permission mapping

### Debug Mode

Enable debug logging to troubleshoot authorization issues:

```bash
DEBUG=mcp:* npm run dev
```

This will show detailed logs of authentication and authorization decisions.

## Migration Guide

If you're upgrading from the basic authentication system:

1. **Update Environment Variables**: Add new JWT and permission-related variables
2. **Update Client Code**: Ensure clients send proper JWT tokens
3. **Test Role Assignments**: Verify users have appropriate roles
4. **Update Error Handling**: Handle new authorization error responses

## Conclusion

This authorization system provides:
- ✅ **Role-based access control**
- ✅ **Fine-grained permissions**
- ✅ **JWT token security**
- ✅ **API key support**
- ✅ **Comprehensive logging**
- ✅ **Production-ready security**

For questions or issues, refer to the security documentation in `SEC.md` or check the troubleshooting section above.
