import { getUserPermissions, UserRole } from "./authorization.js";

export const USER_DETAILS_DEMO = {
  id: "user-id-123",
  email: "user@example.com",
  role: UserRole.ADMIN,
  permissions: getUserPermissions(UserRole.ADMIN),
};
