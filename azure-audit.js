/**
 * Azure Entra ID Audit Module
 * Version: 2.7.0
 *
 * Provides Azure AD/Entra ID security audit functionality using Microsoft Graph API
 *
 * Features:
 * - User security analysis
 * - Privileged access review
 * - Application security checks
 * - Conditional Access policy analysis
 * - Identity Protection (requires Azure AD P2)
 * - Group analysis
 * - SSE streaming with 20 progress steps
 *
 * Request Body Options:
 * - skipPremiumCheck: (boolean) Skip Premium P2 features to allow auditing free tenants
 * - includeRiskyUsers: (boolean, default: true) Include risky users detection (requires P2)
 *
 * Example for free tenants:
 * {
 *   "skipPremiumCheck": true,
 *   "includeRiskyUsers": false
 * }
 *
 * @requires @microsoft/microsoft-graph-client
 */

const { Client } = require('@microsoft/microsoft-graph-client');
require('isomorphic-fetch'); // Required for Graph client in Node.js

// ====================================================================================================
// AZURE GRAPH API CLIENT
// ====================================================================================================

/**
 * Create authenticated Microsoft Graph client
 * @param {string} tenantId - Azure Tenant ID
 * @param {string} clientId - Azure App Client ID
 * @param {string} clientSecret - Azure App Client Secret
 * @returns {Promise<Client>} Authenticated Graph client
 */
async function createGraphClient(tenantId, clientId, clientSecret) {
  const tokenEndpoint = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;

  // Get access token using client credentials flow
  const tokenResponse = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      scope: 'https://graph.microsoft.com/.default',
      grant_type: 'client_credentials'
    })
  });

  if (!tokenResponse.ok) {
    const error = await tokenResponse.text();
    throw new Error(`Azure authentication failed: ${error}`);
  }

  const tokenData = await tokenResponse.json();
  const accessToken = tokenData.access_token;

  // Create Graph client with access token
  return Client.init({
    authProvider: (done) => {
      done(null, accessToken);
    }
  });
}

// ====================================================================================================
// DATA FETCHERS
// ====================================================================================================

/**
 * Fetch all users with pagination support
 * @param {Client} client - Graph API client
 * @param {boolean} skipPremium - Skip Premium-only fields (signInActivity, lastPasswordChangeDateTime)
 */
async function fetchAllUsers(client, skipPremium = false) {
  const users = [];

  // Premium fields: signInActivity, lastPasswordChangeDateTime
  // Free tier fields: id, userPrincipalName, displayName, mail, accountEnabled, etc.
  let nextLink;
  if (skipPremium) {
    // Free tenant - exclude Premium-only fields
    nextLink = '/users?$select=id,userPrincipalName,displayName,mail,accountEnabled,createdDateTime,assignedLicenses,assignedPlans,onPremisesSyncEnabled,userType,passwordPolicies&$top=999';
  } else {
    // Premium tenant - include all fields
    nextLink = '/users?$select=id,userPrincipalName,displayName,mail,accountEnabled,signInActivity,lastPasswordChangeDateTime,createdDateTime,assignedLicenses,assignedPlans,onPremisesSyncEnabled,userType,passwordPolicies&$top=999';
  }

  while (nextLink) {
    const response = await client.api(nextLink).get();
    users.push(...response.value);
    nextLink = response['@odata.nextLink'] || null;
  }

  return users;
}

/**
 * Fetch all groups with pagination support
 */
async function fetchAllGroups(client) {
  const groups = [];
  let nextLink = '/groups?$select=id,displayName,description,securityEnabled,mailEnabled,groupTypes,createdDateTime,onPremisesSyncEnabled,membershipRule&$top=999';

  while (nextLink) {
    const response = await client.api(nextLink).get();
    groups.push(...response.value);
    nextLink = response['@odata.nextLink'] || null;
  }

  return groups;
}

/**
 * Fetch directory roles (privileged roles)
 */
async function fetchDirectoryRoles(client) {
  const response = await client.api('/directoryRoles').get();
  return response.value;
}

/**
 * Fetch members of a directory role
 */
async function fetchRoleMembers(client, roleId) {
  const response = await client.api(`/directoryRoles/${roleId}/members`).get();
  return response.value;
}

/**
 * Fetch all applications
 */
async function fetchAllApplications(client) {
  const apps = [];
  let nextLink = '/applications?$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials,requiredResourceAccess&$top=999';

  while (nextLink) {
    const response = await client.api(nextLink).get();
    apps.push(...response.value);
    nextLink = response['@odata.nextLink'] || null;
  }

  return apps;
}

/**
 * Fetch all service principals
 */
async function fetchAllServicePrincipals(client) {
  const sps = [];
  let nextLink = '/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,passwordCredentials,keyCredentials&$top=999';

  while (nextLink) {
    const response = await client.api(nextLink).get();
    sps.push(...response.value);
    nextLink = response['@odata.nextLink'] || null;
  }

  return sps;
}

/**
 * Fetch Conditional Access policies
 */
async function fetchConditionalAccessPolicies(client) {
  try {
    const response = await client.api('/identity/conditionalAccess/policies').get();
    return response.value;
  } catch (error) {
    // Insufficient privileges - requires Policy.Read.All
    if (error.statusCode === 403) {
      console.warn('Conditional Access policies: Insufficient permissions (Policy.Read.All required)');
      return [];
    }
    throw error;
  }
}

/**
 * Fetch risky users (Identity Protection - requires Azure AD P2)
 */
async function fetchRiskyUsers(client) {
  try {
    const response = await client.api('/identityProtection/riskyUsers').get();
    return response.value;
  } catch (error) {
    if (error.statusCode === 403) {
      console.warn('Risky users: Insufficient permissions or Azure AD P2 license required');
      return [];
    }
    throw error;
  }
}

/**
 * Fetch risky sign-ins (Identity Protection - requires Azure AD P2)
 */
async function fetchRiskySignIns(client) {
  try {
    const response = await client.api('/identityProtection/riskyServicePrincipals?$top=100').get();
    return response.value;
  } catch (error) {
    if (error.statusCode === 403) {
      console.warn('Risky sign-ins: Insufficient permissions or Azure AD P2 license required');
      return [];
    }
    throw error;
  }
}

/**
 * Fetch organization details
 */
async function fetchOrganization(client) {
  const response = await client.api('/organization').get();
  return response.value[0];
}

// ====================================================================================================
// VULNERABILITY DETECTION FUNCTIONS
// ====================================================================================================

/**
 * Detect users without MFA
 */
function detectUsersWithoutMFA(users) {
  // Note: This requires using the authentication methods API for each user
  // For now, we'll mark this as requiring additional API calls
  return [];
}

/**
 * Detect global admins without MFA
 */
function detectGlobalAdminsNoMFA(users, globalAdminMembers) {
  const findings = [];
  const globalAdminIds = new Set(globalAdminMembers.map(m => m.id));

  for (const user of users) {
    if (globalAdminIds.has(user.id)) {
      // Would need authentication methods API to verify MFA
      findings.push({
        type: 'AZURE_GLOBAL_ADMIN_NO_MFA',
        severity: 'CRITICAL',
        user: user.userPrincipalName,
        displayName: user.displayName,
        userId: user.id,
        description: 'Global Administrator without Multi-Factor Authentication',
        remediation: 'Enable MFA for this privileged account immediately'
      });
    }
  }

  return findings;
}

/**
 * Detect inactive users (no sign-in for 90+ days)
 */
function detectInactiveUsers(users) {
  const findings = [];
  const ninetyDaysAgo = new Date();
  ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);

  for (const user of users) {
    if (!user.accountEnabled) continue;

    const lastSignIn = user.signInActivity?.lastSignInDateTime;
    if (!lastSignIn) {
      findings.push({
        type: 'AZURE_USER_NEVER_SIGNED_IN',
        severity: 'MEDIUM',
        user: user.userPrincipalName,
        displayName: user.displayName,
        userId: user.id,
        createdDateTime: user.createdDateTime,
        description: 'Enabled user account has never signed in',
        remediation: 'Review if account is still needed or disable it'
      });
    } else {
      const lastSignInDate = new Date(lastSignIn);
      if (lastSignInDate < ninetyDaysAgo) {
        const daysInactive = Math.floor((new Date() - lastSignInDate) / (1000 * 60 * 60 * 24));
        findings.push({
          type: 'AZURE_USER_INACTIVE',
          severity: 'HIGH',
          user: user.userPrincipalName,
          displayName: user.displayName,
          userId: user.id,
          lastSignIn: lastSignIn,
          daysInactive: daysInactive,
          description: `User inactive for ${daysInactive} days`,
          remediation: 'Review account activity and disable if no longer needed'
        });
      }
    }
  }

  return findings;
}

/**
 * Detect guest users with privileged roles
 */
function detectGuestPrivilegedAccess(users, roleAssignments) {
  const findings = [];
  const privilegedUserIds = new Set();

  // Collect all users with privileged roles
  for (const [roleName, members] of Object.entries(roleAssignments)) {
    for (const member of members) {
      privilegedUserIds.add(member.id);
    }
  }

  for (const user of users) {
    if (user.userType === 'Guest' && privilegedUserIds.has(user.id)) {
      findings.push({
        type: 'AZURE_GUEST_PRIVILEGED_ACCESS',
        severity: 'CRITICAL',
        user: user.userPrincipalName,
        displayName: user.displayName,
        userId: user.id,
        userType: user.userType,
        description: 'Guest user has privileged role assignment',
        remediation: 'Review guest access and remove privileged roles if not required'
      });
    }
  }

  return findings;
}

/**
 * Detect old passwords (180+ days)
 */
function detectOldPasswords(users) {
  const findings = [];
  const sixMonthsAgo = new Date();
  sixMonthsAgo.setDate(sixMonthsAgo.getDate() - 180);

  for (const user of users) {
    const lastPasswordChange = user.lastPasswordChangeDateTime;
    if (lastPasswordChange) {
      const lastChangeDate = new Date(lastPasswordChange);
      if (lastChangeDate < sixMonthsAgo) {
        const daysOld = Math.floor((new Date() - lastChangeDate) / (1000 * 60 * 60 * 24));
        findings.push({
          type: 'AZURE_PASSWORD_OLD',
          severity: 'MEDIUM',
          user: user.userPrincipalName,
          displayName: user.displayName,
          userId: user.id,
          lastPasswordChange: lastPasswordChange,
          daysOld: daysOld,
          description: `Password not changed for ${daysOld} days`,
          remediation: 'Enforce password rotation policy'
        });
      }
    }
  }

  return findings;
}

/**
 * Detect applications with expiring credentials
 */
function detectExpiringAppCredentials(applications) {
  const findings = [];
  const thirtyDaysFromNow = new Date();
  thirtyDaysFromNow.setDate(thirtyDaysFromNow.getDate() + 30);

  for (const app of applications) {
    // Check password credentials
    for (const cred of (app.passwordCredentials || [])) {
      const endDate = new Date(cred.endDateTime);
      if (endDate < new Date()) {
        findings.push({
          type: 'AZURE_APP_CREDENTIAL_EXPIRED',
          severity: 'HIGH',
          application: app.displayName,
          appId: app.appId,
          credentialType: 'password',
          endDate: cred.endDateTime,
          description: 'Application credential has expired',
          remediation: 'Renew or remove expired credential'
        });
      } else if (endDate < thirtyDaysFromNow) {
        findings.push({
          type: 'AZURE_APP_CREDENTIAL_EXPIRING',
          severity: 'MEDIUM',
          application: app.displayName,
          appId: app.appId,
          credentialType: 'password',
          endDate: cred.endDateTime,
          description: 'Application credential expiring within 30 days',
          remediation: 'Plan credential renewal'
        });
      }
    }

    // Check key credentials
    for (const cred of (app.keyCredentials || [])) {
      const endDate = new Date(cred.endDateTime);
      if (endDate < new Date()) {
        findings.push({
          type: 'AZURE_APP_CREDENTIAL_EXPIRED',
          severity: 'HIGH',
          application: app.displayName,
          appId: app.appId,
          credentialType: 'certificate',
          endDate: cred.endDateTime,
          description: 'Application certificate has expired',
          remediation: 'Renew or remove expired certificate'
        });
      } else if (endDate < thirtyDaysFromNow) {
        findings.push({
          type: 'AZURE_APP_CREDENTIAL_EXPIRING',
          severity: 'MEDIUM',
          application: app.displayName,
          appId: app.appId,
          credentialType: 'certificate',
          endDate: cred.endDateTime,
          description: 'Application certificate expiring within 30 days',
          remediation: 'Plan certificate renewal'
        });
      }
    }
  }

  return findings;
}

/**
 * Detect risky users from Identity Protection
 */
function detectRiskyUsers(riskyUsers) {
  const findings = [];

  for (const user of riskyUsers) {
    const severity = user.riskLevel === 'high' ? 'CRITICAL' :
                     user.riskLevel === 'medium' ? 'HIGH' : 'MEDIUM';

    findings.push({
      type: 'AZURE_RISKY_USER',
      severity: severity,
      user: user.userPrincipalName,
      displayName: user.userDisplayName,
      userId: user.id,
      riskLevel: user.riskLevel,
      riskState: user.riskState,
      riskDetail: user.riskDetail,
      description: `User flagged as ${user.riskLevel} risk by Identity Protection`,
      remediation: 'Investigate risk detections and require password reset or MFA'
    });
  }

  return findings;
}

/**
 * Detect disabled Conditional Access policies
 */
function detectDisabledCAPolicies(policies) {
  const findings = [];

  for (const policy of policies) {
    if (policy.state === 'disabled') {
      findings.push({
        type: 'AZURE_CA_POLICY_DISABLED',
        severity: 'MEDIUM',
        policyName: policy.displayName,
        policyId: policy.id,
        createdDateTime: policy.createdDateTime,
        description: 'Conditional Access policy is disabled',
        remediation: 'Review if policy should be enabled or deleted'
      });
    }
  }

  return findings;
}

/**
 * Detect missing MFA requirement in Conditional Access
 */
function detectMissingMFAPolicy(policies) {
  const hasMFAPolicy = policies.some(p =>
    p.state === 'enabled' &&
    p.grantControls?.builtInControls?.includes('mfa')
  );

  if (!hasMFAPolicy) {
    return [{
      type: 'AZURE_NO_MFA_CA_POLICY',
      severity: 'CRITICAL',
      description: 'No enabled Conditional Access policy requires MFA',
      remediation: 'Create and enable a Conditional Access policy requiring MFA for all users',
      totalPolicies: policies.length,
      enabledPolicies: policies.filter(p => p.state === 'enabled').length
    }];
  }

  return [];
}

// ====================================================================================================
// SSE PROGRESS TRACKING
// ====================================================================================================

const AZURE_AUDIT_STEPS = [
  { step: 'AZURE_STEP_01_INIT', description: 'Initializing Azure audit' },
  { step: 'AZURE_STEP_02_AUTH', description: 'Authenticating to Microsoft Graph API' },
  { step: 'AZURE_STEP_03_ORG_INFO', description: 'Fetching organization information' },
  { step: 'AZURE_STEP_04_USERS', description: 'Fetching all users' },
  { step: 'AZURE_STEP_05_GROUPS', description: 'Fetching all groups' },
  { step: 'AZURE_STEP_06_ROLES', description: 'Fetching directory roles' },
  { step: 'AZURE_STEP_07_APPS', description: 'Fetching applications' },
  { step: 'AZURE_STEP_08_SPS', description: 'Fetching service principals' },
  { step: 'AZURE_STEP_09_CA_POLICIES', description: 'Fetching Conditional Access policies' },
  { step: 'AZURE_STEP_10_RISKY_USERS', description: 'Fetching risky users (Identity Protection)' },
  { step: 'AZURE_STEP_11_USER_MFA', description: 'Checking user MFA status' },
  { step: 'AZURE_STEP_12_INACTIVE_USERS', description: 'Detecting inactive users' },
  { step: 'AZURE_STEP_13_GUEST_ACCESS', description: 'Analyzing guest user access' },
  { step: 'AZURE_STEP_14_PASSWORD_AGE', description: 'Checking password age' },
  { step: 'AZURE_STEP_15_PRIVILEGED', description: 'Analyzing privileged roles' },
  { step: 'AZURE_STEP_16_APP_CREDS', description: 'Checking application credentials' },
  { step: 'AZURE_STEP_17_CA_ANALYSIS', description: 'Analyzing Conditional Access policies' },
  { step: 'AZURE_STEP_18_RISK_ANALYSIS', description: 'Processing Identity Protection risks' },
  { step: 'AZURE_STEP_19_SCORING', description: 'Calculating security score' },
  { step: 'AZURE_STEP_20_COMPLETE', description: 'Azure audit complete' }
];

/**
 * Send SSE progress update (ISO format with AD audit)
 */
function sendProgress(res, step, status = 'completed', count = 0, findings = {}, duration = null) {
  const stepData = AZURE_AUDIT_STEPS.find(s => s.step === step);
  const eventData = {
    step: step,
    description: stepData?.description || step,
    status: status,
    count: count
  };

  // Add duration if provided (like AD audit format)
  if (duration !== null) {
    eventData.duration = `${duration.toFixed(2)}s`;
  }

  // Add findings if any (for detailed progress)
  if (findings && Object.keys(findings).length > 0) {
    eventData.findings = findings;
  }

  // ISO SSE format with AD audit: event line + data line
  res.write(`event: progress\n`);
  res.write(`data: ${JSON.stringify(eventData)}\n\n`);
}

/**
 * Helper to track step with automatic duration (like AD audit)
 */
function trackStep(res, step, count = 0, findings = {}, stepStartTime) {
  const duration = stepStartTime ? (Date.now() - stepStartTime) / 1000 : null;
  sendProgress(res, step, 'completed', count, findings, duration);
  console.log(`[AZURE AUDIT] ${step}: ${count} items - ${duration ? duration.toFixed(2) + 's' : 'N/A'}`);
}

// ====================================================================================================
// MAIN AUDIT HANDLER
// ====================================================================================================

/**
 * Main Azure audit handler with SSE streaming
 */
async function azureAuditStreamHandler(req, res) {
  const startTime = Date.now();
  let stepStart = Date.now(); // Track individual step duration

  // Set SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  // Send initial connection event (like AD audit)
  res.write(`event: connected\n`);
  res.write(`data: ${JSON.stringify({ message: 'Azure audit stream connected', timestamp: new Date().toISOString() })}\n\n`);

  try {
    // Parse request body options
    const options = req.body || {};
    const skipPremiumCheck = options.skipPremiumCheck === true;
    const includeRiskyUsers = options.includeRiskyUsers !== false; // Default true

    // Get Azure credentials from environment
    const tenantId = process.env.AZURE_TENANT_ID;
    const clientId = process.env.AZURE_CLIENT_ID;
    const clientSecret = process.env.AZURE_CLIENT_SECRET;

    if (!tenantId || !clientId || !clientSecret) {
      throw new Error('Azure credentials not configured. Run install.sh to configure Azure audit.');
    }

    // STEP 1: Initialize
    stepStart = Date.now();
    sendProgress(res, 'AZURE_STEP_01_INIT', 'completed', 0, {}, (Date.now() - stepStart) / 1000);

    // STEP 2: Authenticate
    stepStart = Date.now();
    sendProgress(res, 'AZURE_STEP_02_AUTH', 'in_progress');
    const client = await createGraphClient(tenantId, clientId, clientSecret);
    trackStep(res, 'AZURE_STEP_02_AUTH', 0, {}, stepStart);

    // STEP 3: Organization info
    stepStart = Date.now();
    sendProgress(res, 'AZURE_STEP_03_ORG_INFO', 'in_progress');
    const organization = await fetchOrganization(client);
    trackStep(res, 'AZURE_STEP_03_ORG_INFO', 0, {}, stepStart);

    // STEP 4: Fetch users (with or without Premium fields)
    stepStart = Date.now();
    sendProgress(res, 'AZURE_STEP_04_USERS', 'in_progress');
    const users = await fetchAllUsers(client, skipPremiumCheck);
    trackStep(res, 'AZURE_STEP_04_USERS', users.length, {}, stepStart);

    // STEP 5: Fetch groups
    stepStart = Date.now();
    sendProgress(res, 'AZURE_STEP_05_GROUPS', 'in_progress');
    const groups = await fetchAllGroups(client);
    trackStep(res, 'AZURE_STEP_05_GROUPS', groups.length, {}, stepStart);

    // STEP 6: Fetch directory roles
    sendProgress(res, 'AZURE_STEP_06_ROLES', 'in_progress');
    const roles = await fetchDirectoryRoles(client);
    const roleAssignments = {};
    for (const role of roles) {
      const members = await fetchRoleMembers(client, role.id);
      roleAssignments[role.displayName] = members;
    }
    sendProgress(res, 'AZURE_STEP_06_ROLES', 'completed', roles.length);

    // STEP 7: Fetch applications
    sendProgress(res, 'AZURE_STEP_07_APPS', 'in_progress');
    const applications = await fetchAllApplications(client);
    sendProgress(res, 'AZURE_STEP_07_APPS', 'completed', applications.length);

    // STEP 8: Fetch service principals
    sendProgress(res, 'AZURE_STEP_08_SPS', 'in_progress');
    const servicePrincipals = await fetchAllServicePrincipals(client);
    sendProgress(res, 'AZURE_STEP_08_SPS', 'completed', servicePrincipals.length);

    // STEP 9: Fetch Conditional Access policies
    sendProgress(res, 'AZURE_STEP_09_CA_POLICIES', 'in_progress');
    const caPolicies = await fetchConditionalAccessPolicies(client);
    sendProgress(res, 'AZURE_STEP_09_CA_POLICIES', 'completed', caPolicies.length);

    // STEP 10: Fetch risky users (skip if Premium not available or skipPremiumCheck enabled)
    sendProgress(res, 'AZURE_STEP_10_RISKY_USERS', 'in_progress');
    let riskyUsers = [];
    if (!skipPremiumCheck && includeRiskyUsers) {
      try {
        riskyUsers = await fetchRiskyUsers(client);
        sendProgress(res, 'AZURE_STEP_10_RISKY_USERS', 'completed', riskyUsers.length);
      } catch (error) {
        console.warn('Risky users fetch failed (Premium P2 likely required), continuing without:', error.message);
        sendProgress(res, 'AZURE_STEP_10_RISKY_USERS', 'completed', 0, { skipped: true, reason: 'Premium P2 required' });
      }
    } else {
      sendProgress(res, 'AZURE_STEP_10_RISKY_USERS', 'completed', 0, { skipped: true, reason: 'Disabled via skipPremiumCheck' });
    }

    // Start vulnerability detection
    const allFindings = {
      critical: [],
      high: [],
      medium: [],
      low: []
    };

    // STEP 11: Check MFA status
    sendProgress(res, 'AZURE_STEP_11_USER_MFA', 'in_progress');
    const globalAdminRole = roleAssignments['Global Administrator'] || [];
    const globalAdminNoMFA = detectGlobalAdminsNoMFA(users, globalAdminRole);
    globalAdminNoMFA.forEach(f => allFindings[f.severity.toLowerCase()].push(f));
    sendProgress(res, 'AZURE_STEP_11_USER_MFA', 'completed', globalAdminNoMFA.length, {
      critical: globalAdminNoMFA.filter(f => f.severity === 'CRITICAL').length
    });

    // STEP 12: Detect inactive users
    sendProgress(res, 'AZURE_STEP_12_INACTIVE_USERS', 'in_progress');
    const inactiveUsers = detectInactiveUsers(users);
    inactiveUsers.forEach(f => allFindings[f.severity.toLowerCase()].push(f));
    sendProgress(res, 'AZURE_STEP_12_INACTIVE_USERS', 'completed', inactiveUsers.length, {
      high: inactiveUsers.filter(f => f.severity === 'HIGH').length,
      medium: inactiveUsers.filter(f => f.severity === 'MEDIUM').length
    });

    // STEP 13: Guest access analysis
    sendProgress(res, 'AZURE_STEP_13_GUEST_ACCESS', 'in_progress');
    const guestPrivileged = detectGuestPrivilegedAccess(users, roleAssignments);
    guestPrivileged.forEach(f => allFindings[f.severity.toLowerCase()].push(f));
    sendProgress(res, 'AZURE_STEP_13_GUEST_ACCESS', 'completed', guestPrivileged.length, {
      critical: guestPrivileged.length
    });

    // STEP 14: Password age check
    sendProgress(res, 'AZURE_STEP_14_PASSWORD_AGE', 'in_progress');
    const oldPasswords = detectOldPasswords(users);
    oldPasswords.forEach(f => allFindings[f.severity.toLowerCase()].push(f));
    sendProgress(res, 'AZURE_STEP_14_PASSWORD_AGE', 'completed', oldPasswords.length, {
      medium: oldPasswords.length
    });

    // STEP 15: Privileged roles analysis
    sendProgress(res, 'AZURE_STEP_15_PRIVILEGED', 'in_progress');
    const privilegedCount = Object.values(roleAssignments).reduce((sum, members) => sum + members.length, 0);
    sendProgress(res, 'AZURE_STEP_15_PRIVILEGED', 'completed', privilegedCount);

    // STEP 16: Application credentials
    sendProgress(res, 'AZURE_STEP_16_APP_CREDS', 'in_progress');
    const appCredIssues = detectExpiringAppCredentials(applications);
    appCredIssues.forEach(f => allFindings[f.severity.toLowerCase()].push(f));
    sendProgress(res, 'AZURE_STEP_16_APP_CREDS', 'completed', appCredIssues.length, {
      high: appCredIssues.filter(f => f.severity === 'HIGH').length,
      medium: appCredIssues.filter(f => f.severity === 'MEDIUM').length
    });

    // STEP 17: Conditional Access analysis
    sendProgress(res, 'AZURE_STEP_17_CA_ANALYSIS', 'in_progress');
    const caIssues = [
      ...detectDisabledCAPolicies(caPolicies),
      ...detectMissingMFAPolicy(caPolicies)
    ];
    caIssues.forEach(f => allFindings[f.severity.toLowerCase()].push(f));
    sendProgress(res, 'AZURE_STEP_17_CA_ANALYSIS', 'completed', caIssues.length, {
      critical: caIssues.filter(f => f.severity === 'CRITICAL').length,
      medium: caIssues.filter(f => f.severity === 'MEDIUM').length
    });

    // STEP 18: Risk analysis
    sendProgress(res, 'AZURE_STEP_18_RISK_ANALYSIS', 'in_progress');
    const riskFindings = detectRiskyUsers(riskyUsers);
    riskFindings.forEach(f => allFindings[f.severity.toLowerCase()].push(f));
    sendProgress(res, 'AZURE_STEP_18_RISK_ANALYSIS', 'completed', riskFindings.length, {
      critical: riskFindings.filter(f => f.severity === 'CRITICAL').length,
      high: riskFindings.filter(f => f.severity === 'HIGH').length
    });

    // STEP 19: Calculate security score
    sendProgress(res, 'AZURE_STEP_19_SCORING', 'in_progress');
    const totalVulns = allFindings.critical.length + allFindings.high.length +
                       allFindings.medium.length + allFindings.low.length;
    const maxScore = 100;
    const score = Math.max(0, maxScore - (
      allFindings.critical.length * 10 +
      allFindings.high.length * 5 +
      allFindings.medium.length * 2 +
      allFindings.low.length * 1
    ));
    sendProgress(res, 'AZURE_STEP_19_SCORING', 'completed');

    // Build final response
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);

    const auditResult = {
      success: true,
      audit: {
        metadata: {
          provider: 'azure',
          tenantId: tenantId,
          organizationName: organization.displayName,
          timestamp: new Date().toISOString(),
          duration: `${duration}s`,
          version: '2.7.0'
        },
        summary: {
          users: users.length,
          groups: groups.length,
          applications: applications.length,
          servicePrincipals: servicePrincipals.length,
          conditionalAccessPolicies: caPolicies.length,
          vulnerabilities: {
            critical: allFindings.critical.length,
            high: allFindings.high.length,
            medium: allFindings.medium.length,
            low: allFindings.low.length,
            total: totalVulns,
            score: score
          }
        },
        findings: allFindings,
        azure: {
          userSecurity: {
            totalUsers: users.length,
            enabledUsers: users.filter(u => u.accountEnabled).length,
            guestUsers: users.filter(u => u.userType === 'Guest').length,
            inactiveUsers: inactiveUsers.length,
            riskyUsers: riskyUsers.length
          },
          privilegedAccess: {
            totalRoles: roles.length,
            totalAssignments: privilegedCount,
            globalAdmins: globalAdminRole.length,
            roleAssignments: roleAssignments
          },
          applicationSecurity: {
            totalApplications: applications.length,
            totalServicePrincipals: servicePrincipals.length,
            credentialIssues: appCredIssues.length
          },
          conditionalAccess: {
            totalPolicies: caPolicies.length,
            enabledPolicies: caPolicies.filter(p => p.state === 'enabled').length,
            disabledPolicies: caPolicies.filter(p => p.state === 'disabled').length,
            policies: caPolicies
          },
          identityProtection: {
            riskyUsers: riskyUsers.length,
            available: riskyUsers.length > 0 || riskyUsers === null
          },
          groupAnalysis: {
            totalGroups: groups.length,
            securityGroups: groups.filter(g => g.securityEnabled).length,
            dynamicGroups: groups.filter(g => g.groupTypes?.includes('DynamicMembership')).length
          }
        }
      }
    };

    // STEP 20: Complete
    sendProgress(res, 'AZURE_STEP_20_COMPLETE', 'completed', totalVulns, {
      critical: allFindings.critical.length,
      high: allFindings.high.length,
      medium: allFindings.medium.length,
      low: allFindings.low.length,
      score: score
    });

    // Send final result with event: complete (ISO with AD audit)
    res.write(`event: complete\n`);
    res.write(`data: ${JSON.stringify(auditResult)}\n\n`);
    res.end();

  } catch (error) {
    console.error('Azure audit error:', error);
    // ISO SSE error format (like AD audit)
    res.write(`event: error\n`);
    res.write(`data: ${JSON.stringify({
      success: false,
      error: error.message
    })}\n\n`);
    res.end();
  }
}

/**
 * Azure status handler - check if Azure is configured
 */
async function azureStatusHandler(req, res) {
  const tenantId = process.env.AZURE_TENANT_ID;
  const clientId = process.env.AZURE_CLIENT_ID;
  const clientSecret = process.env.AZURE_CLIENT_SECRET;

  const isConfigured = !!(tenantId && clientId && clientSecret);

  res.json({
    success: true,
    azure: {
      configured: isConfigured,
      tenantId: isConfigured ? tenantId : null,
      clientId: isConfigured ? clientId : null,
      message: isConfigured
        ? 'Azure audit is configured and ready'
        : 'Azure audit not configured. Run install.sh to configure Azure credentials.'
    }
  });
}

/**
 * Get detailed Azure tenant information
 * @param {boolean} maskSensitive - Mask sensitive data (tenant ID, domains, etc.)
 * @returns {Promise<Object>} Detailed Azure tenant information
 */
async function getDetailedAzureInfo(maskSensitive = false) {
  const tenantId = process.env.AZURE_TENANT_ID;
  const clientId = process.env.AZURE_CLIENT_ID;
  const clientSecret = process.env.AZURE_CLIENT_SECRET;

  if (!tenantId || !clientId || !clientSecret) {
    throw new Error('Azure credentials not configured');
  }

  // Create Graph client
  const client = await createGraphClient(tenantId, clientId, clientSecret);

  // Fetch organization information
  const organization = await client.api('/organization').get();
  const orgData = organization.value[0];

  // Extract verified domains
  const verifiedDomains = orgData.verifiedDomains
    .filter(d => d.isVerified)
    .map(d => d.name);

  const defaultDomain = orgData.verifiedDomains.find(d => d.isDefault)?.name || verifiedDomains[0];

  return {
    success: true,
    connected: true,
    provider: 'azure-entra-id',
    tenant: {
      id: maskSensitive ? '***MASKED***' : tenantId,
      name: maskSensitive ? '***MASKED***' : orgData.displayName,
      country: orgData.countryLetterCode || 'Unknown',
      defaultDomain: maskSensitive ? '***MASKED***' : defaultDomain,
      verifiedDomains: maskSensitive ? ['***MASKED***'] : verifiedDomains
    },
    authentication: {
      method: 'client-credentials',
      tokenValid: true,
      clientId: maskSensitive ? '***MASKED***' : clientId
    }
  };
}

/**
 * Azure test connection handler - detailed tenant information
 */
async function azureTestConnectionHandler(req, res) {
  try {
    const { maskSensitiveData } = req.body;
    const info = await getDetailedAzureInfo(maskSensitiveData === true);
    res.json(info);
  } catch (error) {
    res.status(500).json({
      success: false,
      connected: false,
      provider: 'azure-entra-id',
      error: error.message
    });
  }
}

// ====================================================================================================
// EXPORTS
// ====================================================================================================

module.exports = {
  azureAuditStreamHandler,
  azureStatusHandler,
  azureTestConnectionHandler
};
