import { getUserPermissions, UserRole } from "./authorization.js";

export const USER_DETAILS_ADMIN_DEMO = {
  id: "user-id-123",
  email: "user@example.com",
  role: UserRole.ADMIN,
  permissions: getUserPermissions(UserRole.ADMIN),
};

export const USER_DETAILS_USER_DEMO = {
  id: "user-id-456",
  email: "user2@example.com",
  role: UserRole.USER,
  permissions: getUserPermissions(UserRole.USER),
};

export const USER_DETAILS_READONLY_DEMO = {
  id: "user-id-789",
  email: "user3@example.com",
  role: UserRole.READONLY,
  permissions: getUserPermissions(UserRole.READONLY),
};
