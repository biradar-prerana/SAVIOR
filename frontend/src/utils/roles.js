
export const ROLES = {
  SOC_MANAGER: 'soc_manager',
  SECURITY_ANALYST: 'security_analyst',
  COMPLIANCE_OFFICER: 'compliance_officer',
};

export const hasRole = (user, role) => {
  if (!user) return false;
  return user.role === role;
};

export const isSocManager = (user) => hasRole(user, ROLES.SOC_MANAGER);
export const isSecurityAnalyst = (user) => hasRole(user, ROLES.SECURITY_ANALYST);
export const isComplianceOfficer = (user) => hasRole(user, ROLES.COMPLIANCE_OFFICER);

export const canAccessScanning = (user) => {
  if (!user) return false;
  return isSocManager(user) || isSecurityAnalyst(user);
};

export const canFetchScanData = (user) => {
  if (!user) return false;
  return true;
};

export const canAccessRiskScoring = (user) => {
  if (!user) return false;
  return isSocManager(user) || isComplianceOfficer(user);
};

export const canAccessReports = (user) => {
  if (!user) return false;
  return true;
};

export const canAccessIntegrations = (user) => {
  if (!user) return false;
  return isSocManager(user);
};

export const canAccessAlerts = (user) => {
  if (!user) return false;
  return isSocManager(user) || isComplianceOfficer(user);
};

