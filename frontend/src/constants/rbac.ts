export const ROLES = {
  USER: 'USER',
  SECURITY_ANALYST: 'SECURITY_ANALYST',
  INSTITUTION_ADMIN: 'INSTITUTION_ADMIN',
  CYBER_CELL_INVESTIGATOR: 'CYBER_CELL_INVESTIGATOR',
  SYSTEM_ADMIN: 'SYSTEM_ADMIN',
} as const;

export type RoleCode = typeof ROLES[keyof typeof ROLES];
export const CROSS_ORG_ROLES: RoleCode[] = [ROLES.CYBER_CELL_INVESTIGATOR, ROLES.SYSTEM_ADMIN];
export const ADMIN_ROLES: RoleCode[] = [ROLES.INSTITUTION_ADMIN, ROLES.SYSTEM_ADMIN];
export const ORG_ASSIGNABLE_ROLES: RoleCode[] = [ROLES.SECURITY_ANALYST, ROLES.USER];
export const ALL_ASSIGNABLE_ROLES: RoleCode[] = Object.values(ROLES);

export const isCrossOrgRole = (role?: string | null): boolean => !!role && CROSS_ORG_ROLES.includes(role as RoleCode);
export const isAdminRole = (role?: string | null): boolean => !!role && ADMIN_ROLES.includes(role as RoleCode);
