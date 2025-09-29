import { Request, Response, NextFunction } from 'express';
import { logger } from '../helpers/logs.js';
import { trace, SpanStatusCode } from '@opentelemetry/api';

const log = logger('authorization');

// Define roles and permissions
export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
  READONLY = 'readonly'
}

export enum Permission {
  READ_TODOS = 'read:todos',
  CREATE_TODOS = 'create:todos',
  UPDATE_TODOS = 'update:todos',
  DELETE_TODOS = 'delete:todos',
  LIST_TOOLS = 'list:tools',
  CALL_TOOLS = 'call:tools'
}

// Role-permission mapping
const rolePermissions: Record<UserRole, Permission[]> = {
  [UserRole.ADMIN]: [
    Permission.READ_TODOS,
    Permission.CREATE_TODOS,
    Permission.UPDATE_TODOS,
    Permission.DELETE_TODOS,
    Permission.LIST_TOOLS,
    Permission.CALL_TOOLS
  ],
  [UserRole.USER]: [
    Permission.READ_TODOS,
    Permission.CREATE_TODOS,
    Permission.UPDATE_TODOS,
    Permission.LIST_TOOLS,
    Permission.CALL_TOOLS
  ],
  [UserRole.READONLY]: [
    Permission.READ_TODOS,
    Permission.LIST_TOOLS
  ]
};

// Tool-permission mapping
const toolPermissions: Record<string, Permission[]> = {
  'add_todo': [Permission.CREATE_TODOS],
  'list_todos': [Permission.READ_TODOS],
  'complete_todo': [Permission.UPDATE_TODOS],
  'delete_todo': [Permission.DELETE_TODOS],
  'updateTodoText': [Permission.UPDATE_TODOS]
};

export interface AuthenticatedUser {
  id: string;
  email: string;
  role: UserRole;
  permissions?: Permission[];
  iat?: number;
  exp?: number;
}

export function getUserPermissions(role: UserRole): Permission[] {
  return rolePermissions[role] || [];
}

export function hasPermission(user: AuthenticatedUser, permission: Permission): boolean {
  const tracer = trace.getTracer('authorization');
  const span = tracer.startSpan('authorization.hasPermission', {
    attributes: {
      'user.id': user.id,
      'user.role': user.role,
      'user.email': user.email || 'unknown',
      'permission.requested': permission,
      'user.has_custom_permissions': !!(user.permissions && user.permissions.length > 0),
    }
  });
  
  try {
    const userPermissions = user.permissions || getUserPermissions(user.role);
    const result = userPermissions.includes(permission);
    
    span.setAttributes({
      'auth.result': result,
      'user.total_permissions': userPermissions.length,
      'user.permissions': userPermissions.join(','),
    });
    
    if (result) {
      span.addEvent('authorization.permission_granted', {
        'user.id': user.id,
        'permission': permission,
      });
      span.setStatus({
        code: SpanStatusCode.OK,
        message: 'Permission granted',
      });
    } else {
      span.addEvent('authorization.permission_denied', {
        'user.id': user.id,
        'permission': permission,
        'user.permissions': userPermissions.join(','),
      });
      span.setStatus({
        code: SpanStatusCode.OK,
        message: 'Permission denied',
      });
    }
    
    return result;
  } catch (error) {
    span.addEvent('authorization.permission_check_error', {
      'error.message': error instanceof Error ? error.message : String(error),
    });
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  } finally {
    span.end();
  }
}

export function requirePermission(permission: Permission) {
  return (req: Request, res: Response, next: NextFunction) => {
    const tracer = trace.getTracer('authorization');
    const span = tracer.startSpan('authorization.requirePermission', {
      attributes: {
        'permission.required': permission,
        'request.method': (req as any).method || 'unknown',
        'request.path': (req as any).path || (req as any).url || 'unknown',
        'request.ip': (req as any).ip || 'unknown',
      }
    });
    
    try {
      const user = (req as any).user as AuthenticatedUser;
      
      if (user) {
        span.setAttributes({
          'user.id': user.id,
          'user.role': user.role,
          'user.email': user.email || 'unknown',
        });
      }
      
      if (!user) {
        span.addEvent('authorization.authentication_required', {
          'request.path': (req as any).path || (req as any).url || 'unknown',
          'request.method': (req as any).method || 'unknown',
        });
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: 'No user authentication found',
        });
        log.warn('Authorization check failed: No user in request');
        (res as any).status(401).json({ error: 'Authentication required' });
        return;
      }

      if (!hasPermission(user, permission)) {
        span.addEvent('authorization.permission_denied', {
          'user.id': user.id,
          'permission.required': permission,
          'user.role': user.role,
        });
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: 'Insufficient permissions',
        });
        log.warn(`Authorization failed: User ${user.id} lacks permission ${permission}`);
        (res as any).status(403).json({ 
          error: 'Insufficient permissions',
          required: permission,
          userRole: user.role
        });
        return;
      }

      span.addEvent('authorization.permission_granted', {
        'user.id': user.id,
        'permission.granted': permission,
      });
      span.setStatus({
        code: SpanStatusCode.OK,
        message: 'Permission check passed',
      });
      log.info(`Authorization granted: User ${user.id} has permission ${permission}`);
      next();
    } catch (error) {
      span.addEvent('authorization.middleware_error', {
        'error.message': error instanceof Error ? error.message : String(error),
      });
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error instanceof Error ? error.message : String(error),
      });
      log.error('Authorization middleware error:', error);
      (res as any).status(500).json({ error: 'Internal authorization error' });
    } finally {
      span.end();
    }
  };
}

export function requireRole(role: UserRole) {
  return (req: Request, res: Response, next: NextFunction) => {
    const tracer = trace.getTracer('authorization');
    const span = tracer.startSpan('authorization.requireRole', {
      attributes: {
        'role.required': role,
        'request.method': (req as any).method || 'unknown',
        'request.path': (req as any).path || (req as any).url || 'unknown',
        'request.ip': (req as any).ip || 'unknown',
      }
    });
    
    try {
      const user = (req as any).user as AuthenticatedUser;
      
      if (user) {
        span.setAttributes({
          'user.id': user.id,
          'user.role': user.role,
          'user.email': user.email || 'unknown',
        });
      }
      
      if (!user) {
        span.addEvent('authorization.authentication_required', {
          'request.path': (req as any).path || (req as any).url || 'unknown',
          'request.method': (req as any).method || 'unknown',
        });
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: 'No user authentication found',
        });
        (res as any).status(401).json({ error: 'Authentication required' });
        return;
      }

      if (user.role !== role) {
        span.addEvent('authorization.role_mismatch', {
          'user.id': user.id,
          'user.role': user.role,
          'role.required': role,
        });
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: 'Insufficient role privileges',
        });
        log.warn(`Role check failed: User ${user.id} has role ${user.role}, required ${role}`);
        (res as any).status(403).json({ 
          error: 'Insufficient role',
          required: role,
          userRole: user.role
        });
        return;
      }

      span.addEvent('authorization.role_granted', {
        'user.id': user.id,
        'role.matched': role,
      });
      span.setStatus({
        code: SpanStatusCode.OK,
        message: 'Role check passed',
      });
      next();
    } catch (error) {
      span.addEvent('authorization.middleware_error', {
        'error.message': error instanceof Error ? error.message : String(error),
      });
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error instanceof Error ? error.message : String(error),
      });
      log.error('Role authorization middleware error:', error);
      (res as any).status(500).json({ error: 'Internal authorization error' });
    } finally {
      span.end();
    }
  };
}

// Middleware to check tool-specific permissions
export function requireToolPermission(toolName: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const tracer = trace.getTracer('authorization');
    const span = tracer.startSpan('authorization.requireToolPermission', {
      attributes: {
        'tool.name': toolName,
        'request.method': (req as any).method || 'unknown',
        'request.path': (req as any).path || (req as any).url || 'unknown',
        'request.ip': (req as any).ip || 'unknown',
      }
    });
    
    try {
      const user = (req as any).user as AuthenticatedUser;
      const requiredPermissions = toolPermissions[toolName];
      
      if (user) {
        span.setAttributes({
          'user.id': user.id,
          'user.role': user.role,
          'user.email': user.email || 'unknown',
        });
      }
      
      if (!requiredPermissions) {
        span.addEvent('authorization.unknown_tool', {
          'tool.name': toolName,
          'available_tools': Object.keys(toolPermissions).join(','),
        });
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: 'Unknown tool requested',
        });
        log.warn(`Unknown tool: ${toolName}`);
        (res as any).status(400).json({ error: 'Unknown tool' });
        return;
      }
      
      span.setAttributes({
        'tool.required_permissions': requiredPermissions.join(','),
        'tool.permissions_count': requiredPermissions.length,
      });

      if (!user) {
        span.addEvent('authorization.authentication_required', {
          'tool.name': toolName,
          'required_permissions': requiredPermissions.join(','),
        });
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: 'Authentication required for tool access',
        });
        (res as any).status(401).json({ error: 'Authentication required' });
        return;
      }

      const hasRequiredPermission = requiredPermissions.some(permission => 
        hasPermission(user, permission)
      );
      
      const userPermissions = user.permissions || getUserPermissions(user.role);
      span.setAttributes({
        'user.permissions': userPermissions.join(','),
        'auth.has_required_permission': hasRequiredPermission,
      });

      if (!hasRequiredPermission) {
        span.addEvent('authorization.tool_access_denied', {
          'user.id': user.id,
          'tool.name': toolName,
          'required_permissions': requiredPermissions.join(','),
          'user.permissions': userPermissions.join(','),
        });
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: 'Insufficient permissions for tool access',
        });
        log.warn(`Tool access denied: User ${user.id} lacks permissions for tool ${toolName}`);
        (res as any).status(403).json({ 
          error: 'Insufficient permissions for this tool',
          tool: toolName,
          required: requiredPermissions,
          userRole: user.role
        });
        return;
      }

      span.addEvent('authorization.tool_access_granted', {
        'user.id': user.id,
        'tool.name': toolName,
        'matched_permissions': requiredPermissions.filter(p => 
          userPermissions.includes(p)
        ).join(','),
      });
      span.setStatus({
        code: SpanStatusCode.OK,
        message: 'Tool access granted',
      });
      next();
    } catch (error) {
      span.addEvent('authorization.middleware_error', {
        'error.message': error instanceof Error ? error.message : String(error),
        'tool.name': toolName,
      });
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error instanceof Error ? error.message : String(error),
      });
      log.error('Tool authorization middleware error:', error);
      (res as any).status(500).json({ error: 'Internal authorization error' });
    } finally {
      span.end();
    }
  };
}
