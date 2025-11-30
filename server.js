const express = require('express');
const ldap = require('ldapjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Load CA certificate if it exists
let caCert = null;
const certPath = process.env.NODE_EXTRA_CA_CERTS || '/app/certs/ad-root-ca.crt';
if (fs.existsSync(certPath)) {
  try {
    caCert = fs.readFileSync(certPath, 'utf8');
    console.log(`✅ Loaded CA certificate from ${certPath}`);
  } catch (err) {
    console.warn(`⚠️  Failed to load CA certificate: ${err.message}`);
  }
}

// Configuration from environment variables
const config = {
  port: process.env.PORT || 8443,
  ldap: {
    url: process.env.LDAP_URL || 'ldaps://localhost:636',
    baseDN: process.env.LDAP_BASE_DN || 'DC=example,DC=com',
    bindDN: process.env.LDAP_BIND_DN || 'CN=admin,CN=Users,DC=example,DC=com',
    bindPassword: process.env.LDAP_BIND_PASSWORD || 'password',
    tlsOptions: {
      rejectUnauthorized: process.env.LDAP_TLS_VERIFY === 'true',
      ...(caCert && { ca: [caCert] }),  // Add CA certificate if loaded
      // Allow connecting by IP when certificate is issued for hostname
      checkServerIdentity: function() { return undefined; }
    }
  }
};

// Generate JWT secret from environment or create new one
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// Generate or use provided API token
let API_TOKEN;
if (process.env.API_TOKEN) {
  API_TOKEN = process.env.API_TOKEN;
} else {
  API_TOKEN = jwt.sign(
    { service: 'ad-collector', created: Date.now() },
    JWT_SECRET,
    { expiresIn: process.env.TOKEN_EXPIRY || '365d' }
  );
}

console.log('\n========================================');
console.log('AD Collector for n8n - v1.7.3');
console.log('========================================');
console.log('Configuration:');
console.log(`  LDAP URL: ${config.ldap.url}`);
console.log(`  Base DN: ${config.ldap.baseDN}`);
console.log(`  Bind DN: ${config.ldap.bindDN}`);
console.log(`  TLS Verify: ${config.ldap.tlsOptions.rejectUnauthorized}`);
console.log('========================================');
console.log('API Token:');
console.log(API_TOKEN);
console.log('========================================\n');

const app = express();
app.use(express.json());

// In-memory cache for last audit result (avoid re-running audit on fallback)
let lastAuditCache = {
  result: null,
  timestamp: null,
  ttl: 5 * 60 * 1000 // 5 minutes TTL
};

// Authentication middleware
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];
  if (token !== API_TOKEN) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  next();
}

// LDAP client factory
function createLdapClient() {
  const client = ldap.createClient({
    url: config.ldap.url,
    tlsOptions: config.ldap.tlsOptions
  });

  return new Promise((resolve, reject) => {
    client.bind(config.ldap.bindDN, config.ldap.bindPassword, (err) => {
      if (err) reject(err);
      else resolve(client);
    });
  });
}

// Helper to search for a single entry
async function searchOne(filter, attributes = ['*']) {
  const client = await createLdapClient();

  return new Promise((resolve, reject) => {
    const opts = {
      filter: filter,
      scope: 'sub',
      attributes: attributes
    };

    let found = false;

    client.search(config.ldap.baseDN, opts, (err, search) => {
      if (err) {
        client.unbind();
        return reject(err);
      }

      search.on('searchEntry', (entry) => {
        found = true;
        client.unbind();
        resolve(entry.pojo);
      });

      search.on('error', (err) => {
        client.unbind();
        reject(err);
      });

      search.on('end', () => {
        if (!found) {
          client.unbind();
          reject(new Error('Entry not found'));
        }
      });
    });
  });
}

// Helper to search for multiple entries with pagination
async function searchMany(filter, attributes = ['*'], maxResults = 1000) {
  const client = await createLdapClient();
  const pageSize = 100; // Fetch results in pages of 100
  const results = [];

  return new Promise(async (resolve, reject) => {
    try {
      let cookie = null;
      let hasMorePages = true;

      while (hasMorePages && results.length < maxResults) {
        const opts = {
          filter: filter,
          scope: 'sub',
          attributes: attributes,
          paged: {
            pageSize: Math.min(pageSize, maxResults - results.length),
            pagePause: false
          }
        };

        // Add cookie for subsequent pages
        if (cookie) {
          opts.paged.cookie = cookie;
        }

        await new Promise((pageResolve, pageReject) => {
          client.search(config.ldap.baseDN, opts, (err, search) => {
            if (err) {
              return pageReject(err);
            }

            search.on('searchEntry', (entry) => {
              if (results.length < maxResults) {
                results.push(entry.pojo);
              }
            });

            search.on('page', (result, cb) => {
              cookie = result.cookie;
              if (!cookie || results.length >= maxResults) {
                hasMorePages = false;
              }
              if (cb) cb();
            });

            search.on('error', (err) => {
              // If we got "Size Limit Exceeded" but we have partial results, return them
              if (err.name === 'SizeLimitExceededError' && results.length > 0) {
                console.log(`Size limit exceeded during pagination, returning ${results.length} partial results`);
                hasMorePages = false;
                return pageResolve();
              }
              pageReject(err);
            });

            search.on('end', (result) => {
              if (!result || !result.cookie) {
                hasMorePages = false;
              }
              pageResolve();
            });
          });
        });
      }

      client.unbind();
      console.log(`Pagination complete: retrieved ${results.length} results`);
      resolve(results);
    } catch (error) {
      client.unbind();
      reject(error);
    }
  });
}

// LDAP escape function to prevent injection
function escapeLdap(str) {
  if (!str) return str;
  return str.replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
}

// Helper to get DN from samAccountName
async function getDnFromSam(samAccountName) {
  const user = await searchOne(`(sAMAccountName=${escapeLdap(samAccountName)})`);
  return user.objectName;
}

// Helper to convert Windows FileTime to JavaScript Date
function fileTimeToDate(fileTime) {
  if (!fileTime || fileTime === '0' || fileTime === '9223372036854775807') {
    return null;
  }
  // Windows FileTime is 100-nanosecond intervals since 1601-01-01 UTC
  const EPOCH_DIFF = 11644473600000; // milliseconds between 1601 and 1970
  const timestamp = (parseInt(fileTime) / 10000) - EPOCH_DIFF;
  return new Date(timestamp);
}

// Helper to format date as human-readable string
function formatDate(date) {
  if (!date) return null;
  return date.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
}

// Helper to extract detailed user attributes for audit results
function getUserDetails(user) {
  const attrs = user.attributes || [];
  const getValue = (type) => attrs.find(a => a.type === type)?.values[0] || null;

  const sam = getValue('sAMAccountName') || 'Unknown';
  const dn = user.objectName;

  // Extract all security-relevant attributes
  const details = {
    sam,
    dn,
    // HIGH PRIORITY - Security critical
    displayName: getValue('displayName'),
    title: getValue('title'),
    department: getValue('department'),
    manager: getValue('manager'),
    whenCreated: getValue('whenCreated'),
    lastLogonTimestamp: getValue('lastLogonTimestamp'),
    lastLogon: getValue('lastLogon'),
    pwdLastSet: getValue('pwdLastSet'),
    adminCount: getValue('adminCount'),
    // MEDIUM PRIORITY - Identification/Contact
    mail: getValue('mail'),
    userPrincipalName: getValue('userPrincipalName'),
    description: getValue('description'),
    // OPTIONAL - Additional context
    telephoneNumber: getValue('telephoneNumber'),
    company: getValue('company'),
    employeeID: getValue('employeeID')
  };

  // Remove null values to reduce payload size
  return Object.fromEntries(Object.entries(details).filter(([_, v]) => v !== null));
}

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'ad-collector', version: '1.7.3' });
});

// Test LDAP connection
app.post('/api/test-connection', authenticate, async (req, res) => {
  try {
    const client = await createLdapClient();
    client.unbind();
    res.json({
      success: true,
      status: 'ok',
      message: 'LDAP connection successful',
      connected: true
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      status: 'error',
      message: error.message,
      connected: false
    });
  }
});

// ========== USER OPERATIONS ==========

// Get user by samAccountName
app.post('/api/users/get', authenticate, async (req, res) => {
  try {
    const { samAccountName, includeAll } = req.body;

    if (!samAccountName) {
      return res.status(400).json({ error: 'samAccountName is required' });
    }

    const user = await searchOne(`(sAMAccountName=${escapeLdap(samAccountName)})`);
    res.json({ success: true, user });
  } catch (error) {
    if (error.message === 'Entry not found') {
      res.status(404).json({ success: false, error: 'User not found' });
    } else {
      res.status(500).json({ success: false, error: error.message });
    }
  }
});

// Find user by samAccountName
app.post('/api/users/find-by-sam', authenticate, async (req, res) => {
  try {
    const { samAccountName } = req.body;

    if (!samAccountName) {
      return res.status(400).json({ error: 'samAccountName is required' });
    }

    const user = await searchOne(`(sAMAccountName=${escapeLdap(samAccountName)})`);
    res.json({ success: true, user, found: true });
  } catch (error) {
    if (error.message === 'Entry not found') {
      res.json({ success: true, found: false });
    } else {
      res.status(500).json({ success: false, error: error.message });
    }
  }
});

// List users
app.post('/api/users/list', authenticate, async (req, res) => {
  try {
    const { filter, maxResults, attributes } = req.body;

    const ldapFilter = filter || '(&(objectClass=user)(objectCategory=person))';
    const attrs = attributes || ['*'];
    const limit = maxResults || 1000;

    const users = await searchMany(ldapFilter, attrs, limit);
    res.json({ success: true, users, count: users.length });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create user
app.post('/api/users/create', authenticate, async (req, res) => {
  try {
    const client = await createLdapClient();
    const {
      samAccountName,
      password,
      firstName,
      lastName,
      ou,
      email,
      displayName,
      description,
      userPrincipalName
    } = req.body;

    if (!samAccountName || !firstName || !lastName) {
      return res.status(400).json({
        success: false,
        error: 'samAccountName, firstName, and lastName are required'
      });
    }

    const cn = displayName || `${firstName} ${lastName}`;
    const dn = `CN=${cn},${ou || config.ldap.baseDN}`;
    const domain = config.ldap.baseDN.replace(/DC=/g, '').replace(/,/g, '.');
    const upn = userPrincipalName || `${samAccountName}@${domain}`;

    const entry = {
      objectClass: ['top', 'person', 'organizationalPerson', 'user'],
      cn: cn,
      sAMAccountName: samAccountName,
      givenName: firstName,
      sn: lastName,
      displayName: cn,
      userPrincipalName: upn,
      userAccountControl: '544'
    };

    if (email) entry.mail = email;
    if (description) entry.description = description;

    return new Promise((resolve, reject) => {
      client.add(dn, entry, (err) => {
        if (err) {
          client.unbind();
          return res.status(500).json({ success: false, error: err.message });
        }

        if (password) {
          const passwordBuffer = Buffer.from(`"${password}"`, 'utf16le');
          const change = new ldap.Change({
            operation: 'replace',
            modification: {
              type: 'unicodePwd',
              values: [passwordBuffer]
            }
          });

          client.modify(dn, change, (err) => {
            if (err) {
              const enableChange = new ldap.Change({
                operation: 'replace',
                modification: {
                  type: 'userAccountControl',
                  values: ['512']
                }
              });

              client.modify(dn, enableChange, (err2) => {
                client.unbind();
                if (err2) {
                  return res.status(500).json({
                    success: false,
                    error: 'User created but password and enable failed: ' + err.message
                  });
                }
                res.json({ success: true, dn, created: true });
              });
            } else {
              const enableChange = new ldap.Change({
                operation: 'replace',
                modification: {
                  type: 'userAccountControl',
                  values: ['512']
                }
              });

              client.modify(dn, enableChange, (err2) => {
                client.unbind();
                if (err2) {
                  return res.status(500).json({
                    success: false,
                    error: 'User created with password but enable failed: ' + err2.message
                  });
                }
                res.json({ success: true, dn, created: true });
              });
            }
          });
        } else {
          client.unbind();
          res.json({ success: true, dn, created: true });
        }
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Enable user
app.post('/api/users/enable', authenticate, async (req, res) => {
  try {
    const { dn, samAccountName } = req.body;

    let userDn = dn;
    if (!userDn && samAccountName) {
      userDn = await getDnFromSam(samAccountName);
    }

    if (!userDn) {
      return res.status(400).json({
        success: false,
        error: 'Either dn or samAccountName is required'
      });
    }

    const user = await searchOne(`(distinguishedName=${userDn})`);
    const uacAttr = user.attributes.find(a => a.type === 'userAccountControl');
    let uac = parseInt(uacAttr.values[0]);

    uac &= ~0x2;

    const client = await createLdapClient();
    const change = new ldap.Change({
      operation: 'replace',
      modification: {
        type: 'userAccountControl',
        values: [uac.toString()]
      }
    });

    return new Promise((resolve, reject) => {
      client.modify(userDn, change, (err) => {
        client.unbind();
        if (err) {
          return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, dn: userDn, enabled: true });
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Disable user
app.post('/api/users/disable', authenticate, async (req, res) => {
  try {
    const { dn, samAccountName } = req.body;

    let userDn = dn;
    if (!userDn && samAccountName) {
      userDn = await getDnFromSam(samAccountName);
    }

    if (!userDn) {
      return res.status(400).json({
        success: false,
        error: 'Either dn or samAccountName is required'
      });
    }

    const user = await searchOne(`(distinguishedName=${userDn})`);
    const uacAttr = user.attributes.find(a => a.type === 'userAccountControl');
    let uac = parseInt(uacAttr.values[0]);

    uac |= 0x2;

    const client = await createLdapClient();
    const change = new ldap.Change({
      operation: 'replace',
      modification: {
        type: 'userAccountControl',
        values: [uac.toString()]
      }
    });

    return new Promise((resolve, reject) => {
      client.modify(userDn, change, (err) => {
        client.unbind();
        if (err) {
          return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, dn: userDn, disabled: true });
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Reset password
app.post('/api/users/reset-password', authenticate, async (req, res) => {
  try {
    const { dn, samAccountName, newPassword, forceChange } = req.body;

    let userDn = dn;
    if (!userDn && samAccountName) {
      userDn = await getDnFromSam(samAccountName);
    }

    if (!userDn) {
      return res.status(400).json({
        success: false,
        error: 'Either dn or samAccountName is required'
      });
    }

    if (!newPassword) {
      return res.status(400).json({ success: false, error: 'newPassword is required' });
    }

    const client = await createLdapClient();
    const passwordBuffer = Buffer.from(`"${newPassword}"`, 'utf16le');

    const changes = [
      new ldap.Change({
        operation: 'replace',
        modification: {
          type: 'unicodePwd',
          values: [passwordBuffer]
        }
      })
    ];

    if (forceChange) {
      changes.push(new ldap.Change({
        operation: 'replace',
        modification: {
          type: 'pwdLastSet',
          values: ['0']
        }
      }));
    }

    return new Promise((resolve, reject) => {
      client.modify(userDn, changes, (err) => {
        client.unbind();
        if (err) {
          return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, dn: userDn, passwordReset: true });
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete user
app.post('/api/users/delete', authenticate, async (req, res) => {
  try {
    const { dn, samAccountName } = req.body;

    let userDn = dn;
    if (!userDn && samAccountName) {
      userDn = await getDnFromSam(samAccountName);
    }

    if (!userDn) {
      return res.status(400).json({
        success: false,
        error: 'Either dn or samAccountName is required'
      });
    }

    const client = await createLdapClient();

    return new Promise((resolve, reject) => {
      client.del(userDn, (err) => {
        client.unbind();
        if (err) {
          return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, dn: userDn, deleted: true });
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Unlock user account
app.post('/api/users/unlock', authenticate, async (req, res) => {
  try {
    const { samAccountName, dn } = req.body;

    let userDn = dn;
    if (!userDn && samAccountName) {
      userDn = await getDnFromSam(samAccountName);
    }

    if (!userDn) {
      return res.status(400).json({
        success: false,
        error: 'Either dn or samAccountName is required'
      });
    }

    const client = await createLdapClient();
    const change = new ldap.Change({
      operation: 'replace',
      modification: {
        type: 'lockoutTime',
        values: ['0']
      }
    });

    return new Promise((resolve, reject) => {
      client.modify(userDn, change, (err) => {
        client.unbind();
        if (err) {
          return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, dn: userDn, unlocked: true });
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Check password expiry
app.post('/api/users/check-password-expiry', authenticate, async (req, res) => {
  try {
    const { samAccountName } = req.body;

    if (!samAccountName) {
      return res.status(400).json({ success: false, error: 'samAccountName is required' });
    }

    const user = await searchOne(`(sAMAccountName=${escapeLdap(samAccountName)})`);

    const pwdLastSetAttr = user.attributes.find(a => a.type === 'pwdLastSet');
    const pwdLastSet = pwdLastSetAttr ? pwdLastSetAttr.values[0] : null;

    const accountExpiresAttr = user.attributes.find(a => a.type === 'accountExpires');
    const accountExpires = accountExpiresAttr ? accountExpiresAttr.values[0] : null;

    const maxPwdAge = parseInt(process.env.MAX_PWD_AGE_DAYS) || 90;

    const willExpire = pwdLastSet && pwdLastSet !== '0';

    // Convert Windows FileTime to JavaScript Date
    const pwdLastSetDate = fileTimeToDate(pwdLastSet);
    const accountExpiresDate = fileTimeToDate(accountExpires);

    // Calculate password expiry date
    let passwordExpiresDate = null;
    let daysUntilExpiry = null;

    if (willExpire && pwdLastSetDate) {
      passwordExpiresDate = new Date(pwdLastSetDate);
      passwordExpiresDate.setDate(passwordExpiresDate.getDate() + maxPwdAge);

      // Calculate days until expiry
      const now = new Date();
      const timeDiff = passwordExpiresDate.getTime() - now.getTime();
      daysUntilExpiry = Math.ceil(timeDiff / (1000 * 3600 * 24));
    }

    // Handle special value for "never expires"
    const accountExpiresReadable = accountExpires === '9223372036854775807'
      ? 'Never'
      : formatDate(accountExpiresDate);

    res.json({
      success: true,
      samAccountName,
      pwdLastSet,
      pwdLastSetDate: formatDate(pwdLastSetDate),
      accountExpires,
      accountExpiresDate: accountExpiresReadable,
      passwordExpiresDate: formatDate(passwordExpiresDate),
      maxPwdAge,
      willExpire,
      expiryDays: willExpire ? maxPwdAge : null,
      daysUntilExpiry
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Set user attributes
app.post('/api/users/set-attributes', authenticate, async (req, res) => {
  try {
    const { dn, samAccountName, attributes } = req.body;

    let userDn = dn;
    if (!userDn && samAccountName) {
      userDn = await getDnFromSam(samAccountName);
    }

    if (!userDn) {
      return res.status(400).json({
        success: false,
        error: 'Either dn or samAccountName is required'
      });
    }

    if (!attributes || Object.keys(attributes).length === 0) {
      return res.status(400).json({ success: false, error: 'attributes object is required' });
    }

    const client = await createLdapClient();
    const changes = [];

    for (const [key, value] of Object.entries(attributes)) {
      changes.push(new ldap.Change({
        operation: 'replace',
        modification: {
          type: key,
          values: Array.isArray(value) ? value : [value]
        }
      }));
    }

    return new Promise((resolve, reject) => {
      client.modify(userDn, changes, (err) => {
        client.unbind();
        if (err) {
          return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, dn: userDn, modified: true });
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get user groups
app.post('/api/users/get-groups', authenticate, async (req, res) => {
  try {
    const { samAccountName, includeNested, fullDetails } = req.body;

    if (!samAccountName) {
      return res.status(400).json({ success: false, error: 'samAccountName is required' });
    }

    const user = await searchOne(`(sAMAccountName=${escapeLdap(samAccountName)})`);
    const memberOfAttr = user.attributes.find(a => a.type === 'memberOf');
    const groups = memberOfAttr ? memberOfAttr.values : [];

    res.json({
      success: true,
      samAccountName,
      groups,
      count: groups.length
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get user activity
app.post('/api/users/get-activity', authenticate, async (req, res) => {
  try {
    const { samAccountName, activityType } = req.body;

    if (!samAccountName) {
      return res.status(400).json({ success: false, error: 'samAccountName is required' });
    }

    const user = await searchOne(`(sAMAccountName=${escapeLdap(samAccountName)})`);

    const lastLogonAttr = user.attributes.find(a => a.type === 'lastLogon');
    const lastLogonTimestampAttr = user.attributes.find(a => a.type === 'lastLogonTimestamp');
    const whenCreatedAttr = user.attributes.find(a => a.type === 'whenCreated');
    const whenChangedAttr = user.attributes.find(a => a.type === 'whenChanged');

    res.json({
      success: true,
      samAccountName,
      activity: {
        lastLogon: lastLogonAttr ? lastLogonAttr.values[0] : null,
        lastLogonTimestamp: lastLogonTimestampAttr ? lastLogonTimestampAttr.values[0] : null,
        whenCreated: whenCreatedAttr ? whenCreatedAttr.values[0] : null,
        whenChanged: whenChangedAttr ? whenChangedAttr.values[0] : null
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// AD Comprehensive Audit
app.post('/api/audit', authenticate, async (req, res) => {
  try {
    const { includeDetails, includeComputers } = req.body;
    const auditStart = Date.now();
    const progress = [];
    const findings = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: []
    };

    // Helper to track progress
    function trackStep(code, description, data) {
      const stepData = {
        step: code,
        description,
        status: 'completed',
        count: data.count || 0,
        duration: `${((Date.now() - stepStart) / 1000).toFixed(2)}s`
      };
      if (data.findings) stepData.findings = data.findings;
      progress.push(stepData);
      console.log(`[AUDIT] ${code}: ${description} - ${stepData.count} items - ${stepData.duration}`);
    }

    let stepStart = Date.now();

    // STEP 01: User Enumeration
    trackStep('STEP_01_INIT', 'Audit initialization', { count: 1 });
    stepStart = Date.now();

    const allUsers = await searchMany('(&(objectClass=user)(objectCategory=person))', ['*'], 10000);
    trackStep('STEP_02_USER_ENUM', 'User enumeration', { count: allUsers.length });
    stepStart = Date.now();

    // STEP 03: Password Security Analysis
    const passwordIssues = {
      neverExpires: [],
      notRequired: [],
      reversibleEncryption: [],
      expired: [],
      veryOld: [],
      cannotChange: []
    };

    const now = Date.now();
    const maxPwdAge = parseInt(process.env.MAX_PWD_AGE_DAYS) || 90;
    const veryOldThreshold = 365; // 1 year

    for (const user of allUsers) {
      const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || 'Unknown';
      const uac = parseInt(user.attributes.find(a => a.type === 'userAccountControl')?.values[0] || '0');
      const dn = user.objectName;

      // Password never expires
      if (uac & 0x10000) {
        passwordIssues.neverExpires.push(getUserDetails(user));
      }

      // Password not required
      if (uac & 0x20) {
        passwordIssues.notRequired.push(getUserDetails(user));
        findings.critical.push({ type: 'PASSWORD_NOT_REQUIRED', ...getUserDetails(user) });
      }

      // Reversible encryption
      if (uac & 0x80) {
        passwordIssues.reversibleEncryption.push(getUserDetails(user));
        findings.critical.push({ type: 'REVERSIBLE_ENCRYPTION', ...getUserDetails(user) });
      }

      // Cannot change password
      if (uac & 0x40) {
        passwordIssues.cannotChange.push(getUserDetails(user));
      }

      // Check password age
      const pwdLastSet = fileTimeToDate(user.attributes.find(a => a.type === 'pwdLastSet')?.values[0]);
      if (pwdLastSet) {
        const pwdAge = Math.floor((now - pwdLastSet.getTime()) / (24 * 60 * 60 * 1000));

        // Expired password
        if (pwdAge > maxPwdAge && !(uac & 0x10000) && !(uac & 0x2)) {
          passwordIssues.expired.push({ ...getUserDetails(user), daysExpired: pwdAge - maxPwdAge });
        }

        // Very old password (>1 year)
        if (pwdAge > veryOldThreshold) {
          passwordIssues.veryOld.push({ ...getUserDetails(user), daysOld: pwdAge });
          findings.medium.push({ type: 'PASSWORD_VERY_OLD', ...getUserDetails(user), daysOld: pwdAge });
        }
      }
    }

    trackStep('STEP_03_PASSWORD_SEC', 'Password security analysis', {
      count: passwordIssues.neverExpires.length + passwordIssues.notRequired.length +
             passwordIssues.reversibleEncryption.length + passwordIssues.expired.length,
      findings: {
        neverExpires: passwordIssues.neverExpires.length,
        notRequired: passwordIssues.notRequired.length,
        reversibleEncryption: passwordIssues.reversibleEncryption.length,
        expired: passwordIssues.expired.length
      }
    });
    stepStart = Date.now();

    // STEP 04: Kerberos Security Analysis
    const kerberosIssues = {
      spnAccounts: [],
      noPreauth: [],
      unconstrainedDelegation: [],
      constrainedDelegation: []
    };

    for (const user of allUsers) {
      const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || 'Unknown';
      const uac = parseInt(user.attributes.find(a => a.type === 'userAccountControl')?.values[0] || '0');
      const dn = user.objectName;
      const spn = user.attributes.find(a => a.type === 'servicePrincipalName')?.values || [];

      // SPN accounts (Kerberoasting risk)
      if (spn.length > 0) {
        kerberosIssues.spnAccounts.push({ ...getUserDetails(user), spnCount: spn.length, spns: spn });
        findings.high.push({ type: 'KERBEROASTING_RISK', ...getUserDetails(user), spnCount: spn.length });
      }

      // No Kerberos preauth (AS-REP roasting risk)
      if (uac & 0x400000) {
        kerberosIssues.noPreauth.push(getUserDetails(user));
        findings.critical.push({ type: 'ASREP_ROASTING_RISK', ...getUserDetails(user) });
      }

      // Unconstrained delegation (very dangerous!)
      if (uac & 0x80000) {
        kerberosIssues.unconstrainedDelegation.push(getUserDetails(user));
        findings.critical.push({ type: 'UNCONSTRAINED_DELEGATION', ...getUserDetails(user) });
      }

      // Constrained delegation
      const allowedToDelegateTo = user.attributes.find(a => a.type === 'msDS-AllowedToDelegateTo')?.values || [];
      if (allowedToDelegateTo.length > 0) {
        kerberosIssues.constrainedDelegation.push({ ...getUserDetails(user), delegateTo: allowedToDelegateTo });
        findings.high.push({ type: 'CONSTRAINED_DELEGATION', ...getUserDetails(user), targetCount: allowedToDelegateTo.length });
      }
    }

    trackStep('STEP_04_KERBEROS_SEC', 'Kerberos security analysis', {
      count: kerberosIssues.spnAccounts.length + kerberosIssues.noPreauth.length +
             kerberosIssues.unconstrainedDelegation.length,
      findings: {
        spnAccounts: kerberosIssues.spnAccounts.length,
        noPreauth: kerberosIssues.noPreauth.length,
        unconstrainedDelegation: kerberosIssues.unconstrainedDelegation.length
      }
    });
    stepStart = Date.now();

    // STEP 05: Account Status Analysis
    const accountStatus = {
      disabled: [],
      locked: [],
      expired: [],
      neverLoggedOn: [],
      inactive90: [],
      inactive180: [],
      inactive365: []
    };

    const inactivityThresholds = {
      days90: 90 * 24 * 60 * 60 * 1000,
      days180: 180 * 24 * 60 * 60 * 1000,
      days365: 365 * 24 * 60 * 60 * 1000
    };

    for (const user of allUsers) {
      const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || 'Unknown';
      const uac = parseInt(user.attributes.find(a => a.type === 'userAccountControl')?.values[0] || '0');
      const dn = user.objectName;

      // Disabled
      if (uac & 0x2) {
        accountStatus.disabled.push(getUserDetails(user));
      }

      // Locked
      const lockoutTime = user.attributes.find(a => a.type === 'lockoutTime')?.values[0];
      if (lockoutTime && lockoutTime !== '0') {
        accountStatus.locked.push(getUserDetails(user));
      }

      // Expired account
      const accountExpires = user.attributes.find(a => a.type === 'accountExpires')?.values[0];
      if (accountExpires && accountExpires !== '0' && accountExpires !== '9223372036854775807') {
        const expiryDate = fileTimeToDate(accountExpires);
        if (expiryDate && expiryDate.getTime() < now) {
          accountStatus.expired.push({ ...getUserDetails(user), expiryDate: formatDate(expiryDate) });
        }
      }

      // Never logged on
      const lastLogon = user.attributes.find(a => a.type === 'lastLogonTimestamp')?.values[0];
      if (!lastLogon || lastLogon === '0') {
        const whenCreated = user.attributes.find(a => a.type === 'whenCreated')?.values[0];
        accountStatus.neverLoggedOn.push({ ...getUserDetails(user), created: whenCreated });
      } else {
        // Inactive accounts
        const lastLogonDate = fileTimeToDate(lastLogon);
        if (lastLogonDate) {
          const inactive = now - lastLogonDate.getTime();
          const daysInactive = Math.floor(inactive / (24 * 60 * 60 * 1000));

          if (inactive > inactivityThresholds.days365) {
            accountStatus.inactive365.push({ ...getUserDetails(user), daysInactive });
            findings.medium.push({ type: 'INACTIVE_365_DAYS', ...getUserDetails(user), daysInactive });
          } else if (inactive > inactivityThresholds.days180) {
            accountStatus.inactive180.push({ ...getUserDetails(user), daysInactive });
          } else if (inactive > inactivityThresholds.days90) {
            accountStatus.inactive90.push({ ...getUserDetails(user), daysInactive });
          }
        }
      }
    }

    trackStep('STEP_05_ACCOUNT_STATUS', 'Account status analysis', {
      count: accountStatus.disabled.length + accountStatus.locked.length +
             accountStatus.expired.length + accountStatus.neverLoggedOn.length,
      findings: {
        disabled: accountStatus.disabled.length,
        locked: accountStatus.locked.length,
        inactive365: accountStatus.inactive365.length
      }
    });
    stepStart = Date.now();

    // STEP 06: Privileged Accounts Analysis
    const privilegedAccounts = {
      domainAdmins: [],
      enterpriseAdmins: [],
      schemaAdmins: [],
      administrators: [],
      accountOperators: [],
      backupOperators: [],
      serverOperators: [],
      printOperators: [],
      remoteDesktopUsers: [],
      gpCreatorOwners: [],
      dnsAdmins: [],
      adminCount: [],
      protectedUsers: []
    };

    // Get privileged groups
    const privGroups = {
      'Domain Admins': 'domainAdmins',
      'Enterprise Admins': 'enterpriseAdmins',
      'Schema Admins': 'schemaAdmins',
      'Administrators': 'administrators',
      'Account Operators': 'accountOperators',
      'Backup Operators': 'backupOperators',
      'Server Operators': 'serverOperators',
      'Print Operators': 'printOperators',
      'Remote Desktop Users': 'remoteDesktopUsers',
      'Group Policy Creator Owners': 'gpCreatorOwners',
      'DnsAdmins': 'dnsAdmins',
      'Protected Users': 'protectedUsers'
    };

    for (const [groupName, key] of Object.entries(privGroups)) {
      try {
        const group = await searchOne(`(sAMAccountName=${escapeLdap(groupName)})`);
        const members = group.attributes.find(a => a.type === 'member')?.values || [];
        privilegedAccounts[key] = members.map(dn => ({ dn }));

        if (['domainAdmins', 'enterpriseAdmins', 'schemaAdmins'].includes(key)) {
          findings.info.push({ type: `PRIVILEGED_GROUP_${key.toUpperCase()}`, count: members.length });
        }
      } catch (e) {
        // Group doesn't exist
      }
    }

    // AdminCount = 1 (protected accounts)
    for (const user of allUsers) {
      const adminCount = user.attributes.find(a => a.type === 'adminCount')?.values[0];
      if (adminCount === '1') {
        const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0];
        const dn = user.objectName;
        privilegedAccounts.adminCount.push(getUserDetails(user));
      }
    }

    trackStep('STEP_06_PRIVILEGED_ACCTS', 'Privileged accounts analysis', {
      count: privilegedAccounts.domainAdmins.length + privilegedAccounts.enterpriseAdmins.length +
             privilegedAccounts.administrators.length,
      findings: {
        domainAdmins: privilegedAccounts.domainAdmins.length,
        enterpriseAdmins: privilegedAccounts.enterpriseAdmins.length,
        adminCount: privilegedAccounts.adminCount.length
      }
    });
    stepStart = Date.now();

    // STEP 07: Service Accounts Detection
    const serviceAccounts = {
      detectedBySPN: [],
      detectedByName: [],
      detectedByDescription: []
    };

    const servicePatterns = /^(svc|service|sql|apache|nginx|iis|app|api|bot)/i;
    const descPatterns = /(service|application|automated|api|bot)/i;

    for (const user of allUsers) {
      const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || '';
      const desc = user.attributes.find(a => a.type === 'description')?.values[0] || '';
      const spn = user.attributes.find(a => a.type === 'servicePrincipalName')?.values || [];
      const dn = user.objectName;

      if (spn.length > 0) {
        serviceAccounts.detectedBySPN.push({ ...getUserDetails(user), spnCount: spn.length });
      } else if (servicePatterns.test(sam)) {
        serviceAccounts.detectedByName.push(getUserDetails(user));
      } else if (descPatterns.test(desc)) {
        serviceAccounts.detectedByDescription.push({ ...getUserDetails(user), description: desc });
      }
    }

    trackStep('STEP_07_SERVICE_ACCTS', 'Service accounts detection', {
      count: serviceAccounts.detectedBySPN.length + serviceAccounts.detectedByName.length,
      findings: {
        bySPN: serviceAccounts.detectedBySPN.length,
        byName: serviceAccounts.detectedByName.length
      }
    });
    stepStart = Date.now();

    // STEP 08: Dangerous Patterns and Advanced Security Detection
    const dangerousPatterns = {
      passwordInDescription: [],
      testAccounts: [],
      sharedAccounts: [],
      defaultAccounts: [],
      unixUserPassword: [],
      sidHistory: []
    };

    const advancedSecurity = {
      lapsReadable: [],
      dcsyncCapable: [],
      protectedUsersBypass: [],
      weakEncryption: [],
      sensitiveDelegation: [],
      gpoModifyRights: [],
      dnsAdmins: [],
      delegationPrivilege: [],
      replicationRights: []
    };

    const pwdPatterns = /(password|passwd|pwd|motdepasse|mdp)[:=]\s*[\w!@#$%^&*()]+/i;
    const testPatterns = /^(test|demo|temp|sample|example)/i;
    const sharedPatterns = /^(shared|common|generic|team)/i;
    const defaultNames = ['Administrator', 'Guest', 'krbtgt'];

    for (const user of allUsers) {
      const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || '';
      const desc = user.attributes.find(a => a.type === 'description')?.values[0] || '';
      const info = user.attributes.find(a => a.type === 'info')?.values[0] || '';
      const dn = user.objectName;

      // Password in description/info
      if (pwdPatterns.test(desc) || pwdPatterns.test(info)) {
        dangerousPatterns.passwordInDescription.push({ ...getUserDetails(user), field: pwdPatterns.test(desc) ? 'description' : 'info' });
        findings.critical.push({ type: 'PASSWORD_IN_DESCRIPTION', ...getUserDetails(user) });
      }

      // Test/demo accounts
      if (testPatterns.test(sam)) {
        dangerousPatterns.testAccounts.push(getUserDetails(user));
        findings.low.push({ type: 'TEST_ACCOUNT', ...getUserDetails(user) });
      }

      // Shared accounts
      if (sharedPatterns.test(sam)) {
        dangerousPatterns.sharedAccounts.push(getUserDetails(user));
        findings.medium.push({ type: 'SHARED_ACCOUNT', ...getUserDetails(user) });
      }

      // Default accounts
      if (defaultNames.includes(sam)) {
        dangerousPatterns.defaultAccounts.push(getUserDetails(user));
      }

      // UnixUserPassword attribute (dangerous - stores Unix passwords)
      const unixUserPassword = user.attributes.find(a => a.type === 'unixUserPassword')?.values[0];
      if (unixUserPassword) {
        dangerousPatterns.unixUserPassword.push(getUserDetails(user));
        findings.critical.push({ type: 'UNIX_USER_PASSWORD', ...getUserDetails(user) });
      }

      // SID History (potential privilege escalation)
      const sidHistory = user.attributes.find(a => a.type === 'sIDHistory')?.values || [];
      if (sidHistory.length > 0) {
        dangerousPatterns.sidHistory.push({ ...getUserDetails(user), sidCount: sidHistory.length });
        findings.high.push({ type: 'SID_HISTORY', ...getUserDetails(user), sidCount: sidHistory.length });
      }

      // ADVANCED SECURITY CHECKS

      // Weak Kerberos encryption (DES-only, RC4-only)
      const uac = parseInt(user.attributes.find(a => a.type === 'userAccountControl')?.values[0] || '0');
      const supportedEncTypes = user.attributes.find(a => a.type === 'msDS-SupportedEncryptionTypes')?.values[0];

      // DES only (0x2 = DES_CBC_CRC, 0x4 = DES_CBC_MD5)
      if (supportedEncTypes && (parseInt(supportedEncTypes) & 0x6) && !(parseInt(supportedEncTypes) & 0x18)) {
        advancedSecurity.weakEncryption.push({ ...getUserDetails(user), reason: 'DES-only' });
        findings.high.push({ type: 'WEAK_ENCRYPTION_DES', ...getUserDetails(user) });
      }
      // Use DES keys flag
      else if (uac & 0x200000) {
        advancedSecurity.weakEncryption.push({ ...getUserDetails(user), reason: 'USE_DES_KEY_ONLY' });
        findings.medium.push({ type: 'WEAK_ENCRYPTION_FLAG', ...getUserDetails(user) });
      }

      // Sensitive account with delegation enabled (not recommended)
      const adminCount = user.attributes.find(a => a.type === 'adminCount')?.values[0];
      const trustedForDelegation = uac & 0x80000; // TRUSTED_FOR_DELEGATION
      const trustedToAuthForDelegation = user.attributes.find(a => a.type === 'userAccountControl')?.values[0];

      if (adminCount === '1' && trustedForDelegation) {
        advancedSecurity.sensitiveDelegation.push({ ...getUserDetails(user), reason: 'Admin with unconstrained delegation' });
        findings.critical.push({ type: 'SENSITIVE_DELEGATION', ...getUserDetails(user) });
      }
    }

    // Check for LAPS readable permissions (simplified - check if ms-Mcs-AdmPwd is set)
    // In a full implementation, this would check ACLs, but we'll check if the attribute exists
    for (const user of allUsers) {
      const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || '';
      const dn = user.objectName;
      const lapsPassword = user.attributes.find(a => a.type === 'ms-Mcs-AdmPwd')?.values[0];

      if (lapsPassword) {
        advancedSecurity.lapsReadable.push(getUserDetails(user));
        findings.info.push({ type: 'LAPS_PASSWORD_SET', ...getUserDetails(user) });
      }
    }

    // Check for DCSync capable users (Replicating Directory Changes rights)
    // This requires checking specific extended rights on the domain object
    // Simplified: Check for users in groups known to have DCSync rights
    const dcsyncGroups = ['Domain Admins', 'Enterprise Admins', 'Administrators'];
    for (const groupName of dcsyncGroups) {
      try {
        const group = await searchOne(`(sAMAccountName=${escapeLdap(groupName)})`);
        const members = group.attributes.find(a => a.type === 'member')?.values || [];
        for (const memberDn of members) {
          // Extract CN from DN
          const cnMatch = memberDn.match(/^CN=([^,]+)/);
          if (cnMatch) {
            const memberCn = cnMatch[1];
            advancedSecurity.dcsyncCapable.push({ dn: memberDn, group: groupName });
            findings.info.push({ type: 'DCSYNC_CAPABLE', member: memberCn, group: groupName });
          }
        }
      } catch (e) {
        // Group doesn't exist
      }
    }

    // Check for Protected Users bypass (privileged accounts NOT in Protected Users)
    const protectedUsersMembers = privilegedAccounts.protectedUsers.map(u => u.dn);
    const highPrivilegeAccounts = [
      ...privilegedAccounts.domainAdmins,
      ...privilegedAccounts.enterpriseAdmins,
      ...privilegedAccounts.schemaAdmins
    ];

    for (const account of highPrivilegeAccounts) {
      if (!protectedUsersMembers.includes(account.dn)) {
        advancedSecurity.protectedUsersBypass.push(account);
        findings.medium.push({ type: 'NOT_IN_PROTECTED_USERS', dn: account.dn });
      }
    }

    // GPO Modify Rights (Group Policy Creator Owners members)
    for (const member of privilegedAccounts.gpCreatorOwners) {
      advancedSecurity.gpoModifyRights.push(member);
      findings.high.push({ type: 'GPO_MODIFY_RIGHTS', dn: member.dn });
    }

    // DnsAdmins members (can execute code on DC via DLL loading)
    for (const member of privilegedAccounts.dnsAdmins) {
      advancedSecurity.dnsAdmins.push(member);
      findings.high.push({ type: 'DNS_ADMINS_MEMBER', dn: member.dn });
    }

    // Detect accounts with replication rights (potential DCSync without being in DA/EA)
    // These are accounts with adminCount=1 but NOT in standard admin groups
    const standardAdminDns = [
      ...privilegedAccounts.domainAdmins.map(a => a.dn),
      ...privilegedAccounts.enterpriseAdmins.map(a => a.dn),
      ...privilegedAccounts.administrators.map(a => a.dn)
    ];

    for (const account of privilegedAccounts.adminCount) {
      if (!standardAdminDns.includes(account.dn)) {
        advancedSecurity.replicationRights.push(account);
        findings.high.push({ type: 'REPLICATION_RIGHTS', dn: account.dn });
      }
    }

    // Detect accounts with delegation privilege
    // Accounts in specific privileged groups that can modify delegation settings
    const delegationGroups = [
      ...privilegedAccounts.accountOperators,
      ...privilegedAccounts.serverOperators
    ];

    for (const account of delegationGroups) {
      advancedSecurity.delegationPrivilege.push(account);
      findings.medium.push({ type: 'DELEGATION_PRIVILEGE', dn: account.dn });
    }

    trackStep('STEP_08_DANGEROUS_PATTERNS', 'Dangerous patterns and advanced security detection', {
      count: dangerousPatterns.passwordInDescription.length + dangerousPatterns.testAccounts.length,
      findings: {
        passwordInDesc: dangerousPatterns.passwordInDescription.length,
        testAccounts: dangerousPatterns.testAccounts.length
      }
    });
    stepStart = Date.now();

    // STEP 09: Temporal Analysis
    const temporalAnalysis = {
      created7days: [],
      created30days: [],
      created90days: [],
      modified7days: [],
      modified30days: []
    };

    const timeThresholds = {
      days7: 7 * 24 * 60 * 60 * 1000,
      days30: 30 * 24 * 60 * 60 * 1000,
      days90: 90 * 24 * 60 * 60 * 1000
    };

    for (const user of allUsers) {
      const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0];
      const whenCreatedStr = user.attributes.find(a => a.type === 'whenCreated')?.values[0];
      const whenChangedStr = user.attributes.find(a => a.type === 'whenChanged')?.values[0];
      const dn = user.objectName;

      if (whenCreatedStr) {
        const created = new Date(whenCreatedStr).getTime();
        const age = now - created;

        if (age < timeThresholds.days7) {
          temporalAnalysis.created7days.push({ ...getUserDetails(user), created: whenCreatedStr });
        } else if (age < timeThresholds.days30) {
          temporalAnalysis.created30days.push({ ...getUserDetails(user), created: whenCreatedStr });
        } else if (age < timeThresholds.days90) {
          temporalAnalysis.created90days.push({ ...getUserDetails(user), created: whenCreatedStr });
        }
      }

      if (whenChangedStr) {
        const changed = new Date(whenChangedStr).getTime();
        const age = now - changed;

        if (age < timeThresholds.days7) {
          temporalAnalysis.modified7days.push({ ...getUserDetails(user), modified: whenChangedStr });
        } else if (age < timeThresholds.days30) {
          temporalAnalysis.modified30days.push({ ...getUserDetails(user), modified: whenChangedStr });
        }
      }
    }

    trackStep('STEP_09_TEMPORAL_ANALYSIS', 'Temporal analysis', {
      count: temporalAnalysis.created7days.length + temporalAnalysis.created30days.length,
      findings: {
        created7days: temporalAnalysis.created7days.length,
        modified7days: temporalAnalysis.modified7days.length
      }
    });
    stepStart = Date.now();

    // STEP 10: Group Analysis
    const allGroups = await searchMany('(objectClass=group)', ['*'], 10000);
    trackStep('STEP_10_GROUP_ENUM', 'Group enumeration', { count: allGroups.length });
    stepStart = Date.now();

    const groupAnalysis = {
      emptyGroups: [],
      oversizedGroups: [],
      recentlyModified: []
    };

    for (const group of allGroups) {
      const sam = group.attributes.find(a => a.type === 'sAMAccountName')?.values[0];
      const members = group.attributes.find(a => a.type === 'member')?.values || [];
      const whenChanged = group.attributes.find(a => a.type === 'whenChanged')?.values[0];
      const dn = group.objectName;

      // Empty groups
      if (members.length === 0) {
        groupAnalysis.emptyGroups.push({ sam, dn });
      }

      // Oversized groups (>100 members = info, >500 = high, >1000 = critical)
      if (members.length > 1000) {
        groupAnalysis.oversizedGroups.push({ sam, dn, memberCount: members.length, severity: 'critical' });
        findings.high.push({ type: 'OVERSIZED_GROUP_CRITICAL', sam, dn, memberCount: members.length });
      } else if (members.length > 500) {
        groupAnalysis.oversizedGroups.push({ sam, dn, memberCount: members.length, severity: 'high' });
        findings.medium.push({ type: 'OVERSIZED_GROUP_HIGH', sam, dn, memberCount: members.length });
      } else if (members.length > 100) {
        groupAnalysis.oversizedGroups.push({ sam, dn, memberCount: members.length, severity: 'info' });
        findings.info.push({ type: 'OVERSIZED_GROUP', sam, dn, memberCount: members.length });
      }

      // Recently modified (7 days)
      if (whenChanged) {
        const changedDate = new Date(whenChanged).getTime();
        if (now - changedDate < timeThresholds.days7) {
          groupAnalysis.recentlyModified.push({ sam, dn, modified: whenChanged });
        }
      }
    }

    trackStep('STEP_11_GROUP_ANALYSIS', 'Group analysis', {
      count: groupAnalysis.emptyGroups.length + groupAnalysis.oversizedGroups.length,
      findings: {
        emptyGroups: groupAnalysis.emptyGroups.length,
        oversizedGroups: groupAnalysis.oversizedGroups.length
      }
    });
    stepStart = Date.now();

    // STEP 12: Computer Analysis (if requested)
    let computerAnalysis = null;
    if (includeComputers) {
      const allComputers = await searchMany('(objectClass=computer)', ['*'], 10000);
      computerAnalysis = {
        total: allComputers.length,
        enabled: 0,
        disabled: 0,
        inactive90: [],
        inactive180: [],
        servers: [],
        workstations: [],
        domainControllers: []
      };

      for (const computer of allComputers) {
        const name = computer.attributes.find(a => a.type === 'name')?.values[0];
        const uac = parseInt(computer.attributes.find(a => a.type === 'userAccountControl')?.values[0] || '0');
        const os = computer.attributes.find(a => a.type === 'operatingSystem')?.values[0] || '';
        const lastLogon = fileTimeToDate(computer.attributes.find(a => a.type === 'lastLogonTimestamp')?.values[0]);
        const dn = computer.objectName;

        if (uac & 0x2) {
          computerAnalysis.disabled++;
        } else {
          computerAnalysis.enabled++;
        }

        // Inactive computers
        if (lastLogon) {
          const inactive = now - lastLogon.getTime();
          const daysInactive = Math.floor(inactive / (24 * 60 * 60 * 1000));

          if (inactive > inactivityThresholds.days180) {
            computerAnalysis.inactive180.push({ name, dn, daysInactive });
          } else if (inactive > inactivityThresholds.days90) {
            computerAnalysis.inactive90.push({ name, dn, daysInactive });
          }
        }

        // Type detection
        if (uac & 0x2000) {
          computerAnalysis.domainControllers.push({ name, dn, os });
        } else if (os.toLowerCase().includes('server')) {
          computerAnalysis.servers.push({ name, dn, os });
        } else {
          computerAnalysis.workstations.push({ name, dn, os });
        }
      }

      trackStep('STEP_12_COMPUTER_ANALYSIS', 'Computer analysis', {
        count: allComputers.length,
        findings: {
          enabled: computerAnalysis.enabled,
          disabled: computerAnalysis.disabled,
          inactive90: computerAnalysis.inactive90.length
        }
      });
      stepStart = Date.now();
    }

    // STEP 13: OU Analysis
    const allOUs = await searchMany('(objectClass=organizationalUnit)', ['*'], 10000);
    const ouAnalysis = {
      total: allOUs.length,
      distribution: {}
    };

    trackStep('STEP_13_OU_ANALYSIS', 'OU analysis', { count: allOUs.length });
    stepStart = Date.now();

    // STEP 14: Risk Scoring
    const riskScore = {
      critical: findings.critical.length,
      high: findings.high.length,
      medium: findings.medium.length,
      low: findings.low.length,
      total: findings.critical.length + findings.high.length + findings.medium.length + findings.low.length,
      score: 0
    };

    // Calculate security score (100 = perfect, 0 = terrible)
    // HYBRID APPROACH: Combines weighted points + direct penalties

    // 1. Weighted risk points (heavier weights than before)
    const weightedRiskPoints = (findings.critical.length * 15) + (findings.high.length * 8) +
                                (findings.medium.length * 2) + (findings.low.length * 1);

    // 2. Max risk with stricter denominator (2.5 instead of 5)
    const maxRiskPoints = allUsers.length * 2.5;

    // 3. Percentage-based deduction
    const percentageDeduction = Math.floor((weightedRiskPoints / maxRiskPoints) * 100);

    // 4. Direct penalty per finding (flat deduction)
    const directPenalty = Math.floor((findings.critical.length * 0.3) + (findings.high.length * 0.1));

    // 5. Final score: base 100 - percentage deduction - direct penalty
    riskScore.score = Math.max(0, Math.min(100, 100 - percentageDeduction - directPenalty));

    trackStep('STEP_14_RISK_SCORING', 'Risk scoring calculation', {
      count: riskScore.total,
      findings: {
        critical: riskScore.critical,
        high: riskScore.high,
        score: riskScore.score
      }
    });

    const totalDuration = ((Date.now() - auditStart) / 1000).toFixed(2);
    trackStep('STEP_15_COMPLETED', 'Audit completed', { count: 1 });

    // Build final response
    const response = {
      success: true,
      audit: {
        metadata: {
          timestamp: new Date().toISOString(),
          duration: `${totalDuration}s`,
          includeDetails,
          includeComputers
        },
        progress,
        summary: {
          users: allUsers.length,
          groups: allGroups.length,
          ous: allOUs.length,
          computers: computerAnalysis ? computerAnalysis.total : 0
        },
        riskScore,
        findings: includeDetails ? findings : {
          critical: findings.critical.length,
          high: findings.high.length,
          medium: findings.medium.length,
          low: findings.low.length,
          total: riskScore.total
        },
        passwordSecurity: {
          neverExpires: includeDetails ? passwordIssues.neverExpires : passwordIssues.neverExpires.length,
          notRequired: includeDetails ? passwordIssues.notRequired : passwordIssues.notRequired.length,
          reversibleEncryption: includeDetails ? passwordIssues.reversibleEncryption : passwordIssues.reversibleEncryption.length,
          expired: includeDetails ? passwordIssues.expired : passwordIssues.expired.length,
          veryOld: includeDetails ? passwordIssues.veryOld : passwordIssues.veryOld.length,
          cannotChange: includeDetails ? passwordIssues.cannotChange : passwordIssues.cannotChange.length
        },
        kerberosSecurity: {
          spnAccounts: includeDetails ? kerberosIssues.spnAccounts : kerberosIssues.spnAccounts.length,
          noPreauth: includeDetails ? kerberosIssues.noPreauth : kerberosIssues.noPreauth.length,
          unconstrainedDelegation: includeDetails ? kerberosIssues.unconstrainedDelegation : kerberosIssues.unconstrainedDelegation.length,
          constrainedDelegation: includeDetails ? kerberosIssues.constrainedDelegation : kerberosIssues.constrainedDelegation.length
        },
        accountStatus: {
          disabled: includeDetails ? accountStatus.disabled : accountStatus.disabled.length,
          locked: includeDetails ? accountStatus.locked : accountStatus.locked.length,
          expired: includeDetails ? accountStatus.expired : accountStatus.expired.length,
          neverLoggedOn: includeDetails ? accountStatus.neverLoggedOn : accountStatus.neverLoggedOn.length,
          inactive90: includeDetails ? accountStatus.inactive90 : accountStatus.inactive90.length,
          inactive180: includeDetails ? accountStatus.inactive180 : accountStatus.inactive180.length,
          inactive365: includeDetails ? accountStatus.inactive365 : accountStatus.inactive365.length
        },
        privilegedAccounts: {
          domainAdmins: includeDetails ? privilegedAccounts.domainAdmins : privilegedAccounts.domainAdmins.length,
          enterpriseAdmins: includeDetails ? privilegedAccounts.enterpriseAdmins : privilegedAccounts.enterpriseAdmins.length,
          schemaAdmins: includeDetails ? privilegedAccounts.schemaAdmins : privilegedAccounts.schemaAdmins.length,
          administrators: includeDetails ? privilegedAccounts.administrators : privilegedAccounts.administrators.length,
          accountOperators: includeDetails ? privilegedAccounts.accountOperators : privilegedAccounts.accountOperators.length,
          backupOperators: includeDetails ? privilegedAccounts.backupOperators : privilegedAccounts.backupOperators.length,
          serverOperators: includeDetails ? privilegedAccounts.serverOperators : privilegedAccounts.serverOperators.length,
          printOperators: includeDetails ? privilegedAccounts.printOperators : privilegedAccounts.printOperators.length,
          remoteDesktopUsers: includeDetails ? privilegedAccounts.remoteDesktopUsers : privilegedAccounts.remoteDesktopUsers.length,
          gpCreatorOwners: includeDetails ? privilegedAccounts.gpCreatorOwners : privilegedAccounts.gpCreatorOwners.length,
          dnsAdmins: includeDetails ? privilegedAccounts.dnsAdmins : privilegedAccounts.dnsAdmins.length,
          adminCount: includeDetails ? privilegedAccounts.adminCount : privilegedAccounts.adminCount.length,
          protectedUsers: includeDetails ? privilegedAccounts.protectedUsers : privilegedAccounts.protectedUsers.length
        },
        serviceAccounts: {
          detectedBySPN: includeDetails ? serviceAccounts.detectedBySPN : serviceAccounts.detectedBySPN.length,
          detectedByName: includeDetails ? serviceAccounts.detectedByName : serviceAccounts.detectedByName.length,
          detectedByDescription: includeDetails ? serviceAccounts.detectedByDescription : serviceAccounts.detectedByDescription.length
        },
        dangerousPatterns: {
          passwordInDescription: includeDetails ? dangerousPatterns.passwordInDescription : dangerousPatterns.passwordInDescription.length,
          testAccounts: includeDetails ? dangerousPatterns.testAccounts : dangerousPatterns.testAccounts.length,
          sharedAccounts: includeDetails ? dangerousPatterns.sharedAccounts : dangerousPatterns.sharedAccounts.length,
          defaultAccounts: includeDetails ? dangerousPatterns.defaultAccounts : dangerousPatterns.defaultAccounts.length,
          unixUserPassword: includeDetails ? dangerousPatterns.unixUserPassword : dangerousPatterns.unixUserPassword.length,
          sidHistory: includeDetails ? dangerousPatterns.sidHistory : dangerousPatterns.sidHistory.length
        },
        advancedSecurity: {
          lapsReadable: includeDetails ? advancedSecurity.lapsReadable : advancedSecurity.lapsReadable.length,
          dcsyncCapable: includeDetails ? advancedSecurity.dcsyncCapable : advancedSecurity.dcsyncCapable.length,
          protectedUsersBypass: includeDetails ? advancedSecurity.protectedUsersBypass : advancedSecurity.protectedUsersBypass.length,
          weakEncryption: includeDetails ? advancedSecurity.weakEncryption : advancedSecurity.weakEncryption.length,
          sensitiveDelegation: includeDetails ? advancedSecurity.sensitiveDelegation : advancedSecurity.sensitiveDelegation.length,
          gpoModifyRights: includeDetails ? advancedSecurity.gpoModifyRights : advancedSecurity.gpoModifyRights.length,
          dnsAdmins: includeDetails ? advancedSecurity.dnsAdmins : advancedSecurity.dnsAdmins.length,
          delegationPrivilege: includeDetails ? advancedSecurity.delegationPrivilege : advancedSecurity.delegationPrivilege.length,
          replicationRights: includeDetails ? advancedSecurity.replicationRights : advancedSecurity.replicationRights.length
        },
        temporalAnalysis: {
          created7days: includeDetails ? temporalAnalysis.created7days : temporalAnalysis.created7days.length,
          created30days: includeDetails ? temporalAnalysis.created30days : temporalAnalysis.created30days.length,
          created90days: includeDetails ? temporalAnalysis.created90days : temporalAnalysis.created90days.length,
          modified7days: includeDetails ? temporalAnalysis.modified7days : temporalAnalysis.modified7days.length,
          modified30days: includeDetails ? temporalAnalysis.modified30days : temporalAnalysis.modified30days.length
        },
        groupAnalysis: {
          emptyGroups: includeDetails ? groupAnalysis.emptyGroups : groupAnalysis.emptyGroups.length,
          oversizedGroups: includeDetails ? groupAnalysis.oversizedGroups : groupAnalysis.oversizedGroups.length,
          recentlyModified: includeDetails ? groupAnalysis.recentlyModified : groupAnalysis.recentlyModified.length
        }
      }
    };

    if (computerAnalysis) {
      response.audit.computerAnalysis = {
        total: computerAnalysis.total,
        enabled: computerAnalysis.enabled,
        disabled: computerAnalysis.disabled,
        inactive90: includeDetails ? computerAnalysis.inactive90 : computerAnalysis.inactive90.length,
        inactive180: includeDetails ? computerAnalysis.inactive180 : computerAnalysis.inactive180.length,
        servers: includeDetails ? computerAnalysis.servers : computerAnalysis.servers.length,
        workstations: includeDetails ? computerAnalysis.workstations : computerAnalysis.workstations.length,
        domainControllers: includeDetails ? computerAnalysis.domainControllers : computerAnalysis.domainControllers.length
      };
    }

    // Cache the result for fallback (5 min TTL)
    lastAuditCache = {
      result: response,
      timestamp: Date.now()
    };

    res.json(response);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message, stack: error.stack });
  }
});

// ========== AUDIT WITH STREAMING (SSE) ==========
app.post('/api/audit/stream', authenticate, async (req, res) => {
  try {
    const { includeDetails, includeComputers } = req.body;
    const auditStart = Date.now();
    const progress = [];
    const findings = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: []
    };

    // Configure SSE headers
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no'); // Disable nginx buffering

    // Helper to send SSE events
    function sendEvent(eventType, data) {
      res.write(`event: ${eventType}\n`);
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    }

    // Helper to track progress AND send event
    function trackStep(code, description, data) {
      const stepData = {
        step: code,
        description,
        status: 'completed',
        count: data.count || 0,
        duration: `${((Date.now() - stepStart) / 1000).toFixed(2)}s`
      };
      if (data.findings) stepData.findings = data.findings;
      progress.push(stepData);

      // Send real-time event
      sendEvent('progress', stepData);

      console.log(`[AUDIT] ${code}: ${description} - ${stepData.count} items - ${stepData.duration}`);
    }

    let stepStart = Date.now();

    // Send initial connection event
    sendEvent('connected', { message: 'Audit stream connected', timestamp: new Date().toISOString() });

    // STEP 01: Init
    trackStep('STEP_01_INIT', 'Audit initialization', { count: 1 });
    stepStart = Date.now();

    // STEP 02: User Enumeration
    const allUsers = await searchMany('(&(objectClass=user)(objectCategory=person))', ['*'], 10000);
    trackStep('STEP_02_USER_ENUM', 'User enumeration', { count: allUsers.length });
    stepStart = Date.now();

    // STEP 03: Password Security Analysis (reuse existing code)
    const passwordIssues = {
      neverExpires: [],
      notRequired: [],
      reversibleEncryption: [],
      expired: [],
      veryOld: [],
      cannotChange: []
    };

    const now = Date.now();
    const maxPwdAge = parseInt(process.env.MAX_PWD_AGE_DAYS) || 90;
    const veryOldThreshold = 365;

    for (const user of allUsers) {
      const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || 'Unknown';
      const uac = parseInt(user.attributes.find(a => a.type === 'userAccountControl')?.values[0] || '0');
      const dn = user.objectName;

      if (uac & 0x10000) passwordIssues.neverExpires.push(getUserDetails(user));
      if (uac & 0x20) {
        passwordIssues.notRequired.push(getUserDetails(user));
        findings.critical.push({ type: 'PASSWORD_NOT_REQUIRED', ...getUserDetails(user) });
      }
      if (uac & 0x80) {
        passwordIssues.reversibleEncryption.push(getUserDetails(user));
        findings.critical.push({ type: 'REVERSIBLE_ENCRYPTION', ...getUserDetails(user) });
      }
      if (uac & 0x40) passwordIssues.cannotChange.push(getUserDetails(user));

      const pwdLastSet = fileTimeToDate(user.attributes.find(a => a.type === 'pwdLastSet')?.values[0]);
      if (pwdLastSet) {
        const pwdAge = Math.floor((now - pwdLastSet.getTime()) / (24 * 60 * 60 * 1000));
        if (pwdAge > maxPwdAge && !(uac & 0x10000) && !(uac & 0x2)) {
          passwordIssues.expired.push({ ...getUserDetails(user), daysExpired: pwdAge - maxPwdAge });
        }
        if (pwdAge > veryOldThreshold) {
          passwordIssues.veryOld.push({ ...getUserDetails(user), daysOld: pwdAge });
          findings.medium.push({ type: 'PASSWORD_VERY_OLD', ...getUserDetails(user), daysOld: pwdAge });
        }
      }
    }

    trackStep('STEP_03_PASSWORD_SEC', 'Password security analysis', {
      count: passwordIssues.neverExpires.length + passwordIssues.notRequired.length +
             passwordIssues.reversibleEncryption.length + passwordIssues.expired.length,
      findings: {
        neverExpires: passwordIssues.neverExpires.length,
        notRequired: passwordIssues.notRequired.length,
        reversibleEncryption: passwordIssues.reversibleEncryption.length,
        expired: passwordIssues.expired.length
      }
    });
    stepStart = Date.now();

    // STEP 04: Kerberos Security Analysis
    const kerberosIssues = {
      spnAccounts: [],
      noPreauth: [],
      unconstrainedDelegation: [],
      constrainedDelegation: []
    };

    for (const user of allUsers) {
      const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || 'Unknown';
      const uac = parseInt(user.attributes.find(a => a.type === 'userAccountControl')?.values[0] || '0');
      const dn = user.objectName;
      const spn = user.attributes.find(a => a.type === 'servicePrincipalName')?.values || [];

      if (spn.length > 0) {
        kerberosIssues.spnAccounts.push({ ...getUserDetails(user), spnCount: spn.length, spns: spn });
        findings.high.push({ type: 'KERBEROASTING_RISK', ...getUserDetails(user), spnCount: spn.length });
      }

      if (uac & 0x400000) {
        kerberosIssues.noPreauth.push(getUserDetails(user));
        findings.critical.push({ type: 'ASREP_ROASTING_RISK', ...getUserDetails(user) });
      }

      if (uac & 0x80000) {
        kerberosIssues.unconstrainedDelegation.push(getUserDetails(user));
        findings.critical.push({ type: 'UNCONSTRAINED_DELEGATION', ...getUserDetails(user) });
      }

      const allowedToDelegateTo = user.attributes.find(a => a.type === 'msDS-AllowedToDelegateTo')?.values || [];
      if (allowedToDelegateTo.length > 0) {
        kerberosIssues.constrainedDelegation.push({ ...getUserDetails(user), delegateTo: allowedToDelegateTo });
        findings.high.push({ type: 'CONSTRAINED_DELEGATION', ...getUserDetails(user), targetCount: allowedToDelegateTo.length });
      }
    }

    trackStep('STEP_04_KERBEROS_SEC', 'Kerberos security analysis', {
      count: kerberosIssues.spnAccounts.length + kerberosIssues.noPreauth.length +
             kerberosIssues.unconstrainedDelegation.length,
      findings: {
        spnAccounts: kerberosIssues.spnAccounts.length,
        noPreauth: kerberosIssues.noPreauth.length,
        unconstrainedDelegation: kerberosIssues.unconstrainedDelegation.length
      }
    });
    stepStart = Date.now();

    // STEP 05: Account Status Analysis
    const accountStatus = {
      disabled: [],
      locked: [],
      expired: [],
      neverLoggedOn: [],
      inactive90: [],
      inactive180: [],
      inactive365: []
    };

    const inactivityThresholds = {
      days90: 90 * 24 * 60 * 60 * 1000,
      days180: 180 * 24 * 60 * 60 * 1000,
      days365: 365 * 24 * 60 * 60 * 1000
    };

    for (const user of allUsers) {
      const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || 'Unknown';
      const uac = parseInt(user.attributes.find(a => a.type === 'userAccountControl')?.values[0] || '0');
      const dn = user.objectName;

      if (uac & 0x2) {
        accountStatus.disabled.push(getUserDetails(user));
      }

      const lockoutTime = user.attributes.find(a => a.type === 'lockoutTime')?.values[0];
      if (lockoutTime && lockoutTime !== '0') {
        accountStatus.locked.push(getUserDetails(user));
      }

      const accountExpires = user.attributes.find(a => a.type === 'accountExpires')?.values[0];
      if (accountExpires && accountExpires !== '0' && accountExpires !== '9223372036854775807') {
        const expiryDate = fileTimeToDate(accountExpires);
        if (expiryDate && expiryDate.getTime() < now) {
          accountStatus.expired.push({ ...getUserDetails(user), expiryDate: formatDate(expiryDate) });
        }
      }

      const lastLogon = user.attributes.find(a => a.type === 'lastLogonTimestamp')?.values[0];
      if (!lastLogon || lastLogon === '0') {
        const whenCreated = user.attributes.find(a => a.type === 'whenCreated')?.values[0];
        accountStatus.neverLoggedOn.push({ ...getUserDetails(user), created: whenCreated });
      } else {
        const lastLogonDate = fileTimeToDate(lastLogon);
        if (lastLogonDate) {
          const inactive = now - lastLogonDate.getTime();
          const daysInactive = Math.floor(inactive / (24 * 60 * 60 * 1000));

          if (inactive > inactivityThresholds.days365) {
            accountStatus.inactive365.push({ ...getUserDetails(user), daysInactive });
            findings.medium.push({ type: 'INACTIVE_365_DAYS', ...getUserDetails(user), daysInactive });
          } else if (inactive > inactivityThresholds.days180) {
            accountStatus.inactive180.push({ ...getUserDetails(user), daysInactive });
          } else if (inactive > inactivityThresholds.days90) {
            accountStatus.inactive90.push({ ...getUserDetails(user), daysInactive });
          }
        }
      }
    }

    trackStep('STEP_05_ACCOUNT_STATUS', 'Account status analysis', {
      count: accountStatus.disabled.length + accountStatus.locked.length +
             accountStatus.expired.length + accountStatus.neverLoggedOn.length,
      findings: {
        disabled: accountStatus.disabled.length,
        locked: accountStatus.locked.length,
        inactive365: accountStatus.inactive365.length
      }
    });
    stepStart = Date.now();

    // STEP 06: Privileged Accounts Analysis
    const privilegedAccounts = {
      domainAdmins: [],
      enterpriseAdmins: [],
      schemaAdmins: [],
      administrators: [],
      accountOperators: [],
      backupOperators: [],
      serverOperators: [],
      printOperators: [],
      remoteDesktopUsers: [],
      gpCreatorOwners: [],
      dnsAdmins: [],
      adminCount: [],
      protectedUsers: []
    };

    const privGroups = {
      'Domain Admins': 'domainAdmins',
      'Enterprise Admins': 'enterpriseAdmins',
      'Schema Admins': 'schemaAdmins',
      'Administrators': 'administrators',
      'Account Operators': 'accountOperators',
      'Backup Operators': 'backupOperators',
      'Server Operators': 'serverOperators',
      'Print Operators': 'printOperators',
      'Remote Desktop Users': 'remoteDesktopUsers',
      'Group Policy Creator Owners': 'gpCreatorOwners',
      'DnsAdmins': 'dnsAdmins',
      'Protected Users': 'protectedUsers'
    };

    for (const [groupName, key] of Object.entries(privGroups)) {
      try {
        const group = await searchOne(`(sAMAccountName=${escapeLdap(groupName)})`);
        const members = group.attributes.find(a => a.type === 'member')?.values || [];
        privilegedAccounts[key] = members.map(dn => ({ dn }));

        if (['domainAdmins', 'enterpriseAdmins', 'schemaAdmins'].includes(key)) {
          findings.info.push({ type: `PRIVILEGED_GROUP_${key.toUpperCase()}`, count: members.length });
        }
      } catch (e) {
        // Group doesn't exist
      }
    }

    for (const user of allUsers) {
      const adminCount = user.attributes.find(a => a.type === 'adminCount')?.values[0];
      if (adminCount === '1') {
        const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0];
        const dn = user.objectName;
        privilegedAccounts.adminCount.push(getUserDetails(user));
      }
    }

    trackStep('STEP_06_PRIVILEGED_ACCTS', 'Privileged accounts analysis', {
      count: privilegedAccounts.domainAdmins.length + privilegedAccounts.enterpriseAdmins.length +
             privilegedAccounts.administrators.length,
      findings: {
        domainAdmins: privilegedAccounts.domainAdmins.length,
        enterpriseAdmins: privilegedAccounts.enterpriseAdmins.length,
        adminCount: privilegedAccounts.adminCount.length
      }
    });
    stepStart = Date.now();

    // STEP 07: Service Accounts Detection
    const serviceAccounts = {
      detectedBySPN: [],
      detectedByName: [],
      detectedByDescription: []
    };

    const servicePatterns = /^(svc|service|sql|apache|nginx|iis|app|api|bot)/i;
    const descPatterns = /(service|application|automated|api|bot)/i;

    for (const user of allUsers) {
      const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || '';
      const desc = user.attributes.find(a => a.type === 'description')?.values[0] || '';
      const spn = user.attributes.find(a => a.type === 'servicePrincipalName')?.values || [];
      const dn = user.objectName;

      if (spn.length > 0) {
        serviceAccounts.detectedBySPN.push({ ...getUserDetails(user), spnCount: spn.length });
      } else if (servicePatterns.test(sam)) {
        serviceAccounts.detectedByName.push(getUserDetails(user));
      } else if (descPatterns.test(desc)) {
        serviceAccounts.detectedByDescription.push({ ...getUserDetails(user), description: desc });
      }
    }

    trackStep('STEP_07_SERVICE_ACCTS', 'Service accounts detection', {
      count: serviceAccounts.detectedBySPN.length + serviceAccounts.detectedByName.length,
      findings: {
        bySPN: serviceAccounts.detectedBySPN.length,
        byName: serviceAccounts.detectedByName.length
      }
    });
    stepStart = Date.now();

    // STEP 08: Dangerous Patterns and Advanced Security Detection
    const dangerousPatterns = {
      passwordInDescription: [],
      testAccounts: [],
      sharedAccounts: [],
      defaultAccounts: [],
      unixUserPassword: [],
      sidHistory: []
    };

    const advancedSecurity = {
      lapsReadable: [],
      dcsyncCapable: [],
      protectedUsersBypass: [],
      weakEncryption: [],
      sensitiveDelegation: [],
      gpoModifyRights: [],
      dnsAdmins: [],
      delegationPrivilege: [],
      replicationRights: []
    };

    const pwdPatterns = /(password|passwd|pwd|motdepasse|mdp)[:=]\s*[\w!@#$%^&*()]+/i;
    const testPatterns = /^(test|demo|temp|sample|example)/i;
    const sharedPatterns = /^(shared|common|generic|team)/i;
    const defaultNames = ['Administrator', 'Guest', 'krbtgt'];

    for (const user of allUsers) {
      const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || '';
      const desc = user.attributes.find(a => a.type === 'description')?.values[0] || '';
      const info = user.attributes.find(a => a.type === 'info')?.values[0] || '';
      const dn = user.objectName;

      if (pwdPatterns.test(desc) || pwdPatterns.test(info)) {
        dangerousPatterns.passwordInDescription.push({ ...getUserDetails(user), field: pwdPatterns.test(desc) ? 'description' : 'info' });
        findings.critical.push({ type: 'PASSWORD_IN_DESCRIPTION', ...getUserDetails(user) });
      }

      if (testPatterns.test(sam)) {
        dangerousPatterns.testAccounts.push(getUserDetails(user));
        findings.low.push({ type: 'TEST_ACCOUNT', ...getUserDetails(user) });
      }

      if (sharedPatterns.test(sam)) {
        dangerousPatterns.sharedAccounts.push(getUserDetails(user));
        findings.medium.push({ type: 'SHARED_ACCOUNT', ...getUserDetails(user) });
      }

      if (defaultNames.includes(sam)) {
        dangerousPatterns.defaultAccounts.push(getUserDetails(user));
      }

      const unixUserPassword = user.attributes.find(a => a.type === 'unixUserPassword')?.values[0];
      if (unixUserPassword) {
        dangerousPatterns.unixUserPassword.push(getUserDetails(user));
        findings.critical.push({ type: 'UNIX_USER_PASSWORD', ...getUserDetails(user) });
      }

      const sidHistory = user.attributes.find(a => a.type === 'sIDHistory')?.values || [];
      if (sidHistory.length > 0) {
        dangerousPatterns.sidHistory.push({ ...getUserDetails(user), sidCount: sidHistory.length });
        findings.high.push({ type: 'SID_HISTORY', ...getUserDetails(user), sidCount: sidHistory.length });
      }

      // ADVANCED SECURITY CHECKS
      const uac = parseInt(user.attributes.find(a => a.type === 'userAccountControl')?.values[0] || '0');
      const supportedEncTypes = user.attributes.find(a => a.type === 'msDS-SupportedEncryptionTypes')?.values[0];

      if (supportedEncTypes && (parseInt(supportedEncTypes) & 0x6) && !(parseInt(supportedEncTypes) & 0x18)) {
        advancedSecurity.weakEncryption.push({ ...getUserDetails(user), reason: 'DES-only' });
        findings.high.push({ type: 'WEAK_ENCRYPTION_DES', ...getUserDetails(user) });
      } else if (uac & 0x200000) {
        advancedSecurity.weakEncryption.push({ ...getUserDetails(user), reason: 'USE_DES_KEY_ONLY' });
        findings.medium.push({ type: 'WEAK_ENCRYPTION_FLAG', ...getUserDetails(user) });
      }

      const adminCount = user.attributes.find(a => a.type === 'adminCount')?.values[0];
      const trustedForDelegation = uac & 0x80000;

      if (adminCount === '1' && trustedForDelegation) {
        advancedSecurity.sensitiveDelegation.push({ ...getUserDetails(user), reason: 'Admin with unconstrained delegation' });
        findings.critical.push({ type: 'SENSITIVE_DELEGATION', ...getUserDetails(user) });
      }
    }

    for (const user of allUsers) {
      const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || '';
      const dn = user.objectName;
      const lapsPassword = user.attributes.find(a => a.type === 'ms-Mcs-AdmPwd')?.values[0];

      if (lapsPassword) {
        advancedSecurity.lapsReadable.push(getUserDetails(user));
        findings.info.push({ type: 'LAPS_PASSWORD_SET', ...getUserDetails(user) });
      }
    }

    const dcsyncGroups = ['Domain Admins', 'Enterprise Admins', 'Administrators'];
    for (const groupName of dcsyncGroups) {
      try {
        const group = await searchOne(`(sAMAccountName=${escapeLdap(groupName)})`);
        const members = group.attributes.find(a => a.type === 'member')?.values || [];
        for (const memberDn of members) {
          const cnMatch = memberDn.match(/^CN=([^,]+)/);
          if (cnMatch) {
            const memberCn = cnMatch[1];
            advancedSecurity.dcsyncCapable.push({ dn: memberDn, group: groupName });
            findings.info.push({ type: 'DCSYNC_CAPABLE', member: memberCn, group: groupName });
          }
        }
      } catch (e) {
        // Group doesn't exist
      }
    }

    const protectedUsersMembers = privilegedAccounts.protectedUsers.map(u => u.dn);
    const highPrivilegeAccounts = [
      ...privilegedAccounts.domainAdmins,
      ...privilegedAccounts.enterpriseAdmins,
      ...privilegedAccounts.schemaAdmins
    ];

    for (const account of highPrivilegeAccounts) {
      if (!protectedUsersMembers.includes(account.dn)) {
        advancedSecurity.protectedUsersBypass.push(account);
        findings.medium.push({ type: 'NOT_IN_PROTECTED_USERS', dn: account.dn });
      }
    }

    for (const member of privilegedAccounts.gpCreatorOwners) {
      advancedSecurity.gpoModifyRights.push(member);
      findings.high.push({ type: 'GPO_MODIFY_RIGHTS', dn: member.dn });
    }

    for (const member of privilegedAccounts.dnsAdmins) {
      advancedSecurity.dnsAdmins.push(member);
      findings.high.push({ type: 'DNS_ADMINS_MEMBER', dn: member.dn });
    }

    const standardAdminDns = [
      ...privilegedAccounts.domainAdmins.map(a => a.dn),
      ...privilegedAccounts.enterpriseAdmins.map(a => a.dn),
      ...privilegedAccounts.administrators.map(a => a.dn)
    ];

    for (const account of privilegedAccounts.adminCount) {
      if (!standardAdminDns.includes(account.dn)) {
        advancedSecurity.replicationRights.push(account);
        findings.high.push({ type: 'REPLICATION_RIGHTS', dn: account.dn });
      }
    }

    const delegationGroups = [
      ...privilegedAccounts.accountOperators,
      ...privilegedAccounts.serverOperators
    ];

    for (const account of delegationGroups) {
      advancedSecurity.delegationPrivilege.push(account);
      findings.medium.push({ type: 'DELEGATION_PRIVILEGE', dn: account.dn });
    }

    trackStep('STEP_08_DANGEROUS_PATTERNS', 'Dangerous patterns and advanced security detection', {
      count: dangerousPatterns.passwordInDescription.length + dangerousPatterns.testAccounts.length,
      findings: {
        passwordInDesc: dangerousPatterns.passwordInDescription.length,
        testAccounts: dangerousPatterns.testAccounts.length
      }
    });
    stepStart = Date.now();

    // STEP 09: Temporal Analysis
    const temporalAnalysis = {
      created7days: [],
      created30days: [],
      created90days: [],
      modified7days: [],
      modified30days: []
    };

    const timeThresholds = {
      days7: 7 * 24 * 60 * 60 * 1000,
      days30: 30 * 24 * 60 * 60 * 1000,
      days90: 90 * 24 * 60 * 60 * 1000
    };

    for (const user of allUsers) {
      const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0];
      const whenCreatedStr = user.attributes.find(a => a.type === 'whenCreated')?.values[0];
      const whenChangedStr = user.attributes.find(a => a.type === 'whenChanged')?.values[0];
      const dn = user.objectName;

      if (whenCreatedStr) {
        const created = new Date(whenCreatedStr).getTime();
        const age = now - created;

        if (age < timeThresholds.days7) {
          temporalAnalysis.created7days.push({ ...getUserDetails(user), created: whenCreatedStr });
        } else if (age < timeThresholds.days30) {
          temporalAnalysis.created30days.push({ ...getUserDetails(user), created: whenCreatedStr });
        } else if (age < timeThresholds.days90) {
          temporalAnalysis.created90days.push({ ...getUserDetails(user), created: whenCreatedStr });
        }
      }

      if (whenChangedStr) {
        const changed = new Date(whenChangedStr).getTime();
        const age = now - changed;

        if (age < timeThresholds.days7) {
          temporalAnalysis.modified7days.push({ ...getUserDetails(user), modified: whenChangedStr });
        } else if (age < timeThresholds.days30) {
          temporalAnalysis.modified30days.push({ ...getUserDetails(user), modified: whenChangedStr });
        }
      }
    }

    trackStep('STEP_09_TEMPORAL_ANALYSIS', 'Temporal analysis', {
      count: temporalAnalysis.created7days.length + temporalAnalysis.created30days.length,
      findings: {
        created7days: temporalAnalysis.created7days.length,
        modified7days: temporalAnalysis.modified7days.length
      }
    });
    stepStart = Date.now();

    // STEP 10: Group Analysis
    const allGroups = await searchMany('(objectClass=group)', ['*'], 10000);
    trackStep('STEP_10_GROUP_ENUM', 'Group enumeration', { count: allGroups.length });
    stepStart = Date.now();

    const groupAnalysis = {
      emptyGroups: [],
      oversizedGroups: [],
      recentlyModified: []
    };

    for (const group of allGroups) {
      const sam = group.attributes.find(a => a.type === 'sAMAccountName')?.values[0];
      const members = group.attributes.find(a => a.type === 'member')?.values || [];
      const whenChanged = group.attributes.find(a => a.type === 'whenChanged')?.values[0];
      const dn = group.objectName;

      if (members.length === 0) {
        groupAnalysis.emptyGroups.push({ sam, dn });
      }

      if (members.length > 1000) {
        groupAnalysis.oversizedGroups.push({ sam, dn, memberCount: members.length, severity: 'critical' });
        findings.high.push({ type: 'OVERSIZED_GROUP_CRITICAL', sam, dn, memberCount: members.length });
      } else if (members.length > 500) {
        groupAnalysis.oversizedGroups.push({ sam, dn, memberCount: members.length, severity: 'high' });
        findings.medium.push({ type: 'OVERSIZED_GROUP_HIGH', sam, dn, memberCount: members.length });
      } else if (members.length > 100) {
        groupAnalysis.oversizedGroups.push({ sam, dn, memberCount: members.length, severity: 'info' });
        findings.info.push({ type: 'OVERSIZED_GROUP', sam, dn, memberCount: members.length });
      }

      if (whenChanged) {
        const changedDate = new Date(whenChanged).getTime();
        if (now - changedDate < timeThresholds.days7) {
          groupAnalysis.recentlyModified.push({ sam, dn, modified: whenChanged });
        }
      }
    }

    trackStep('STEP_11_GROUP_ANALYSIS', 'Group analysis', {
      count: groupAnalysis.emptyGroups.length + groupAnalysis.oversizedGroups.length,
      findings: {
        emptyGroups: groupAnalysis.emptyGroups.length,
        oversizedGroups: groupAnalysis.oversizedGroups.length
      }
    });
    stepStart = Date.now();

    // STEP 12: Computer Analysis (if requested)
    let computerAnalysis = null;
    if (includeComputers) {
      const allComputers = await searchMany('(objectClass=computer)', ['*'], 10000);
      computerAnalysis = {
        total: allComputers.length,
        enabled: 0,
        disabled: 0,
        inactive90: [],
        inactive180: [],
        servers: [],
        workstations: [],
        domainControllers: []
      };

      for (const computer of allComputers) {
        const name = computer.attributes.find(a => a.type === 'name')?.values[0];
        const uac = parseInt(computer.attributes.find(a => a.type === 'userAccountControl')?.values[0] || '0');
        const os = computer.attributes.find(a => a.type === 'operatingSystem')?.values[0] || '';
        const lastLogon = fileTimeToDate(computer.attributes.find(a => a.type === 'lastLogonTimestamp')?.values[0]);
        const dn = computer.objectName;

        if (uac & 0x2) {
          computerAnalysis.disabled++;
        } else {
          computerAnalysis.enabled++;
        }

        if (lastLogon) {
          const inactive = now - lastLogon.getTime();
          const daysInactive = Math.floor(inactive / (24 * 60 * 60 * 1000));

          if (inactive > inactivityThresholds.days180) {
            computerAnalysis.inactive180.push({ name, dn, daysInactive });
          } else if (inactive > inactivityThresholds.days90) {
            computerAnalysis.inactive90.push({ name, dn, daysInactive });
          }
        }

        if (uac & 0x2000) {
          computerAnalysis.domainControllers.push({ name, dn, os });
        } else if (os.toLowerCase().includes('server')) {
          computerAnalysis.servers.push({ name, dn, os });
        } else {
          computerAnalysis.workstations.push({ name, dn, os });
        }
      }

      trackStep('STEP_12_COMPUTER_ANALYSIS', 'Computer analysis', {
        count: allComputers.length,
        findings: {
          enabled: computerAnalysis.enabled,
          disabled: computerAnalysis.disabled,
          inactive90: computerAnalysis.inactive90.length
        }
      });
      stepStart = Date.now();
    }

    // STEP 13: OU Analysis
    const allOUs = await searchMany('(objectClass=organizationalUnit)', ['*'], 10000);
    const ouAnalysis = {
      total: allOUs.length,
      distribution: {}
    };

    trackStep('STEP_13_OU_ANALYSIS', 'OU analysis', { count: allOUs.length });
    stepStart = Date.now();

    // STEP 14: Risk Scoring
    const riskScore = {
      critical: findings.critical.length,
      high: findings.high.length,
      medium: findings.medium.length,
      low: findings.low.length,
      total: findings.critical.length + findings.high.length + findings.medium.length + findings.low.length,
      score: 0
    };

    const weightedRiskPoints = (findings.critical.length * 15) + (findings.high.length * 8) +
                                (findings.medium.length * 2) + (findings.low.length * 1);
    const maxRiskPoints = allUsers.length * 2.5;
    const percentageDeduction = Math.floor((weightedRiskPoints / maxRiskPoints) * 100);
    const directPenalty = Math.floor((findings.critical.length * 0.3) + (findings.high.length * 0.1));
    riskScore.score = Math.max(0, Math.min(100, 100 - percentageDeduction - directPenalty));

    trackStep('STEP_14_RISK_SCORING', 'Risk scoring calculation', {
      count: riskScore.total,
      findings: {
        critical: riskScore.critical,
        high: riskScore.high,
        score: riskScore.score
      }
    });

    trackStep('STEP_15_COMPLETED', 'Audit completed', { count: 1 });

    // Calculate final response
    const totalDuration = ((Date.now() - auditStart) / 1000).toFixed(2);

    const finalResponse = {
      success: true,
      audit: {
        metadata: {
          timestamp: new Date().toISOString(),
          duration: `${totalDuration}s`,
          includeDetails,
          includeComputers
        },
        progress,
        summary: {
          users: allUsers.length,
          groups: allGroups.length,
          ous: allOUs.length,
          computers: computerAnalysis ? computerAnalysis.total : 0
        },
        riskScore,
        findings: includeDetails ? findings : {
          critical: findings.critical.length,
          high: findings.high.length,
          medium: findings.medium.length,
          low: findings.low.length,
          total: riskScore.total
        },
        passwordSecurity: {
          neverExpires: includeDetails ? passwordIssues.neverExpires : passwordIssues.neverExpires.length,
          notRequired: includeDetails ? passwordIssues.notRequired : passwordIssues.notRequired.length,
          reversibleEncryption: includeDetails ? passwordIssues.reversibleEncryption : passwordIssues.reversibleEncryption.length,
          expired: includeDetails ? passwordIssues.expired : passwordIssues.expired.length,
          veryOld: includeDetails ? passwordIssues.veryOld : passwordIssues.veryOld.length,
          cannotChange: includeDetails ? passwordIssues.cannotChange : passwordIssues.cannotChange.length
        },
        kerberosSecurity: {
          spnAccounts: includeDetails ? kerberosIssues.spnAccounts : kerberosIssues.spnAccounts.length,
          noPreauth: includeDetails ? kerberosIssues.noPreauth : kerberosIssues.noPreauth.length,
          unconstrainedDelegation: includeDetails ? kerberosIssues.unconstrainedDelegation : kerberosIssues.unconstrainedDelegation.length,
          constrainedDelegation: includeDetails ? kerberosIssues.constrainedDelegation : kerberosIssues.constrainedDelegation.length
        },
        accountStatus: {
          disabled: includeDetails ? accountStatus.disabled : accountStatus.disabled.length,
          locked: includeDetails ? accountStatus.locked : accountStatus.locked.length,
          expired: includeDetails ? accountStatus.expired : accountStatus.expired.length,
          neverLoggedOn: includeDetails ? accountStatus.neverLoggedOn : accountStatus.neverLoggedOn.length,
          inactive90: includeDetails ? accountStatus.inactive90 : accountStatus.inactive90.length,
          inactive180: includeDetails ? accountStatus.inactive180 : accountStatus.inactive180.length,
          inactive365: includeDetails ? accountStatus.inactive365 : accountStatus.inactive365.length
        },
        privilegedAccounts: {
          domainAdmins: includeDetails ? privilegedAccounts.domainAdmins : privilegedAccounts.domainAdmins.length,
          enterpriseAdmins: includeDetails ? privilegedAccounts.enterpriseAdmins : privilegedAccounts.enterpriseAdmins.length,
          schemaAdmins: includeDetails ? privilegedAccounts.schemaAdmins : privilegedAccounts.schemaAdmins.length,
          administrators: includeDetails ? privilegedAccounts.administrators : privilegedAccounts.administrators.length,
          accountOperators: includeDetails ? privilegedAccounts.accountOperators : privilegedAccounts.accountOperators.length,
          backupOperators: includeDetails ? privilegedAccounts.backupOperators : privilegedAccounts.backupOperators.length,
          serverOperators: includeDetails ? privilegedAccounts.serverOperators : privilegedAccounts.serverOperators.length,
          printOperators: includeDetails ? privilegedAccounts.printOperators : privilegedAccounts.printOperators.length,
          remoteDesktopUsers: includeDetails ? privilegedAccounts.remoteDesktopUsers : privilegedAccounts.remoteDesktopUsers.length,
          gpCreatorOwners: includeDetails ? privilegedAccounts.gpCreatorOwners : privilegedAccounts.gpCreatorOwners.length,
          dnsAdmins: includeDetails ? privilegedAccounts.dnsAdmins : privilegedAccounts.dnsAdmins.length,
          adminCount: includeDetails ? privilegedAccounts.adminCount : privilegedAccounts.adminCount.length,
          protectedUsers: includeDetails ? privilegedAccounts.protectedUsers : privilegedAccounts.protectedUsers.length
        },
        serviceAccounts: {
          detectedBySPN: includeDetails ? serviceAccounts.detectedBySPN : serviceAccounts.detectedBySPN.length,
          detectedByName: includeDetails ? serviceAccounts.detectedByName : serviceAccounts.detectedByName.length,
          detectedByDescription: includeDetails ? serviceAccounts.detectedByDescription : serviceAccounts.detectedByDescription.length
        },
        dangerousPatterns: {
          passwordInDescription: includeDetails ? dangerousPatterns.passwordInDescription : dangerousPatterns.passwordInDescription.length,
          testAccounts: includeDetails ? dangerousPatterns.testAccounts : dangerousPatterns.testAccounts.length,
          sharedAccounts: includeDetails ? dangerousPatterns.sharedAccounts : dangerousPatterns.sharedAccounts.length,
          defaultAccounts: includeDetails ? dangerousPatterns.defaultAccounts : dangerousPatterns.defaultAccounts.length,
          unixUserPassword: includeDetails ? dangerousPatterns.unixUserPassword : dangerousPatterns.unixUserPassword.length,
          sidHistory: includeDetails ? dangerousPatterns.sidHistory : dangerousPatterns.sidHistory.length
        },
        advancedSecurity: {
          lapsReadable: includeDetails ? advancedSecurity.lapsReadable : advancedSecurity.lapsReadable.length,
          dcsyncCapable: includeDetails ? advancedSecurity.dcsyncCapable : advancedSecurity.dcsyncCapable.length,
          protectedUsersBypass: includeDetails ? advancedSecurity.protectedUsersBypass : advancedSecurity.protectedUsersBypass.length,
          weakEncryption: includeDetails ? advancedSecurity.weakEncryption : advancedSecurity.weakEncryption.length,
          sensitiveDelegation: includeDetails ? advancedSecurity.sensitiveDelegation : advancedSecurity.sensitiveDelegation.length,
          gpoModifyRights: includeDetails ? advancedSecurity.gpoModifyRights : advancedSecurity.gpoModifyRights.length,
          dnsAdmins: includeDetails ? advancedSecurity.dnsAdmins : advancedSecurity.dnsAdmins.length,
          delegationPrivilege: includeDetails ? advancedSecurity.delegationPrivilege : advancedSecurity.delegationPrivilege.length,
          replicationRights: includeDetails ? advancedSecurity.replicationRights : advancedSecurity.replicationRights.length
        },
        temporalAnalysis: {
          created7days: includeDetails ? temporalAnalysis.created7days : temporalAnalysis.created7days.length,
          created30days: includeDetails ? temporalAnalysis.created30days : temporalAnalysis.created30days.length,
          created90days: includeDetails ? temporalAnalysis.created90days : temporalAnalysis.created90days.length,
          modified7days: includeDetails ? temporalAnalysis.modified7days : temporalAnalysis.modified7days.length,
          modified30days: includeDetails ? temporalAnalysis.modified30days : temporalAnalysis.modified30days.length
        },
        groupAnalysis: {
          emptyGroups: includeDetails ? groupAnalysis.emptyGroups : groupAnalysis.emptyGroups.length,
          oversizedGroups: includeDetails ? groupAnalysis.oversizedGroups : groupAnalysis.oversizedGroups.length,
          recentlyModified: includeDetails ? groupAnalysis.recentlyModified : groupAnalysis.recentlyModified.length
        }
      }
    };

    if (computerAnalysis) {
      finalResponse.audit.computerAnalysis = {
        total: computerAnalysis.total,
        enabled: computerAnalysis.enabled,
        disabled: computerAnalysis.disabled,
        inactive90: includeDetails ? computerAnalysis.inactive90 : computerAnalysis.inactive90.length,
        inactive180: includeDetails ? computerAnalysis.inactive180 : computerAnalysis.inactive180.length,
        servers: includeDetails ? computerAnalysis.servers : computerAnalysis.servers.length,
        workstations: includeDetails ? computerAnalysis.workstations : computerAnalysis.workstations.length,
        domainControllers: includeDetails ? computerAnalysis.domainControllers : computerAnalysis.domainControllers.length
      };
    }

    // Cache the result for fallback (5 min TTL)
    lastAuditCache = {
      result: finalResponse,
      timestamp: Date.now()
    };

    // Send final result
    sendEvent('complete', finalResponse);

    // Force flush before closing (important for SSE!)
    // Use setImmediate to ensure the event is written before res.end()
    setImmediate(() => {
      res.end();
    });

  } catch (error) {
    res.write(`event: error\n`);
    res.write(`data: ${JSON.stringify({ success: false, error: error.message })}\n\n`);
    res.end();
  }
});

// Get last audit result (cached, no re-run)
app.get('/api/audit/last', authenticate, (req, res) => {
  try {
    // Check if cache exists and is not expired
    if (!lastAuditCache.result) {
      return res.status(404).json({
        success: false,
        error: 'No cached audit result available. Run an audit first.',
        cacheStatus: 'empty'
      });
    }

    const cacheAge = Date.now() - lastAuditCache.timestamp;
    if (cacheAge > lastAuditCache.ttl) {
      return res.status(410).json({
        success: false,
        error: 'Cached audit result expired. Please run a new audit.',
        cacheStatus: 'expired',
        cacheAge: `${Math.floor(cacheAge / 1000)}s`
      });
    }

    console.log(`[Audit Cache] Returning cached result (age: ${Math.floor(cacheAge / 1000)}s)`);

    // Return cached result with cache metadata
    res.json({
      ...lastAuditCache.result,
      cacheMetadata: {
        cached: true,
        cacheAge: `${Math.floor(cacheAge / 1000)}s`,
        cachedAt: new Date(lastAuditCache.timestamp).toISOString()
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========== GROUP OPERATIONS ==========

// Get group
app.post('/api/groups/get', authenticate, async (req, res) => {
  try {
    const { dn, samAccountName } = req.body;

    let filter;
    if (dn) {
      filter = `(distinguishedName=${escapeLdap(dn)})`;
    } else if (samAccountName) {
      filter = `(sAMAccountName=${escapeLdap(samAccountName)})`;
    } else {
      return res.status(400).json({
        success: false,
        error: 'Either dn or samAccountName is required'
      });
    }

    const group = await searchOne(filter);
    res.json({ success: true, group });
  } catch (error) {
    if (error.message === 'Entry not found') {
      res.status(404).json({ success: false, error: 'Group not found' });
    } else {
      res.status(500).json({ success: false, error: error.message });
    }
  }
});

// List groups
app.post('/api/groups/list', authenticate, async (req, res) => {
  try {
    const { filter, maxResults, attributes } = req.body;

    const ldapFilter = filter || '(objectClass=group)';
    const attrs = attributes || ['*'];
    const limit = maxResults || 1000;

    const groups = await searchMany(ldapFilter, attrs, limit);
    res.json({ success: true, groups, count: groups.length });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create group
app.post('/api/groups/create', authenticate, async (req, res) => {
  try {
    const client = await createLdapClient();
    const { samAccountName, name, ou, description, groupType } = req.body;

    if (!samAccountName || !name) {
      return res.status(400).json({
        success: false,
        error: 'samAccountName and name are required'
      });
    }

    const dn = `CN=${name},${ou || config.ldap.baseDN}`;

    const entry = {
      objectClass: ['top', 'group'],
      cn: name,
      sAMAccountName: samAccountName,
      groupType: groupType || '-2147483646'
    };

    if (description) entry.description = description;

    return new Promise((resolve, reject) => {
      client.add(dn, entry, (err) => {
        client.unbind();
        if (err) {
          return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, dn, created: true });
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Modify group
app.post('/api/groups/modify', authenticate, async (req, res) => {
  try {
    const { dn, samAccountName, attributes } = req.body;

    let groupDn = dn;
    if (!groupDn && samAccountName) {
      const group = await searchOne(`(sAMAccountName=${escapeLdap(samAccountName)})`);
      groupDn = group.objectName;
    }

    if (!groupDn) {
      return res.status(400).json({
        success: false,
        error: 'Either dn or samAccountName is required'
      });
    }

    if (!attributes || Object.keys(attributes).length === 0) {
      return res.status(400).json({ success: false, error: 'attributes object is required' });
    }

    const client = await createLdapClient();
    const changes = [];

    for (const [key, value] of Object.entries(attributes)) {
      changes.push(new ldap.Change({
        operation: 'replace',
        modification: {
          type: key,
          values: Array.isArray(value) ? value : [value]
        }
      }));
    }

    return new Promise((resolve, reject) => {
      client.modify(groupDn, changes, (err) => {
        client.unbind();
        if (err) {
          return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, dn: groupDn, modified: true });
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete group
app.post('/api/groups/delete', authenticate, async (req, res) => {
  try {
    const { dn, samAccountName } = req.body;

    let groupDn = dn;
    if (!groupDn && samAccountName) {
      const group = await searchOne(`(sAMAccountName=${escapeLdap(samAccountName)})`);
      groupDn = group.objectName;
    }

    if (!groupDn) {
      return res.status(400).json({
        success: false,
        error: 'Either dn or samAccountName is required'
      });
    }

    const client = await createLdapClient();

    return new Promise((resolve, reject) => {
      client.del(groupDn, (err) => {
        client.unbind();
        if (err) {
          return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, dn: groupDn, deleted: true });
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Add group member
app.post('/api/groups/add-member', authenticate, async (req, res) => {
  try {
    const { userDn, groupDn, skipIfMember } = req.body;

    if (!userDn || !groupDn) {
      return res.status(400).json({
        success: false,
        error: 'userDn and groupDn are required'
      });
    }

    const client = await createLdapClient();
    const change = new ldap.Change({
      operation: 'add',
      modification: {
        type: 'member',
        values: [userDn]
      }
    });

    return new Promise((resolve, reject) => {
      client.modify(groupDn, change, (err) => {
        client.unbind();
        if (err) {
          if (skipIfMember && err.message && err.message.includes('ENTRY_EXISTS')) {
            return res.json({ success: true, dn: groupDn, memberAdded: false, alreadyMember: true });
          }
          return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, dn: groupDn, memberAdded: true });
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Remove group member
app.post('/api/groups/remove-member', authenticate, async (req, res) => {
  try {
    const { userDn, groupDn, skipIfNotMember } = req.body;

    if (!userDn || !groupDn) {
      return res.status(400).json({
        success: false,
        error: 'userDn and groupDn are required'
      });
    }

    const client = await createLdapClient();
    const change = new ldap.Change({
      operation: 'delete',
      modification: {
        type: 'member',
        values: [userDn]
      }
    });

    return new Promise((resolve, reject) => {
      client.modify(groupDn, change, (err) => {
        client.unbind();
        if (err) {
          if (skipIfNotMember && err.message && err.message.includes('NO_SUCH_ATTRIBUTE')) {
            return res.json({ success: true, dn: groupDn, memberRemoved: false, notMember: true });
          }
          return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, dn: groupDn, memberRemoved: true });
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Search groups
app.post('/api/groups/search', authenticate, async (req, res) => {
  try {
    const { searchTerm, maxResults } = req.body;

    if (!searchTerm) {
      return res.status(400).json({ success: false, error: 'searchTerm is required' });
    }

    const escapedTerm = escapeLdap(searchTerm);
    const filter = `(&(objectClass=group)(|(cn=*${escapedTerm}*)(sAMAccountName=*${escapedTerm}*)))`;
    const limit = maxResults || 100;

    const groups = await searchMany(filter, ['*'], limit);
    res.json({ success: true, groups, count: groups.length });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========== OU OPERATIONS ==========

// Get OU
app.post('/api/ous/get', authenticate, async (req, res) => {
  try {
    const { dn } = req.body;

    if (!dn) {
      return res.status(400).json({ success: false, error: 'dn is required' });
    }

    const ou = await searchOne(`(distinguishedName=${escapeLdap(dn)})`);
    res.json({ success: true, ou });
  } catch (error) {
    if (error.message === 'Entry not found') {
      res.status(404).json({ success: false, error: 'OU not found' });
    } else {
      res.status(500).json({ success: false, error: error.message });
    }
  }
});

// List OUs
app.post('/api/ous/list', authenticate, async (req, res) => {
  try {
    const { parentDn, searchFilter, maxResults } = req.body;

    const filter = searchFilter || '(objectClass=organizationalUnit)';
    const limit = maxResults || 1000;

    const ous = await searchMany(filter, ['*'], limit);
    res.json({ success: true, ous, count: ous.length });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create OU
app.post('/api/ous/create', authenticate, async (req, res) => {
  try {
    const client = await createLdapClient();
    const { name, parentDn, description } = req.body;

    if (!name) {
      return res.status(400).json({ success: false, error: 'name is required' });
    }

    const dn = `OU=${name},${parentDn || config.ldap.baseDN}`;

    const entry = {
      objectClass: ['top', 'organizationalUnit'],
      ou: name
    };

    if (description) entry.description = description;

    return new Promise((resolve, reject) => {
      client.add(dn, entry, (err) => {
        client.unbind();
        if (err) {
          return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, dn, created: true });
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Modify OU
app.post('/api/ous/modify', authenticate, async (req, res) => {
  try {
    const { dn, attributes } = req.body;

    if (!dn) {
      return res.status(400).json({ success: false, error: 'dn is required' });
    }

    if (!attributes || Object.keys(attributes).length === 0) {
      return res.status(400).json({ success: false, error: 'attributes object is required' });
    }

    const client = await createLdapClient();
    const changes = [];

    for (const [key, value] of Object.entries(attributes)) {
      changes.push(new ldap.Change({
        operation: 'replace',
        modification: {
          type: key,
          values: Array.isArray(value) ? value : [value]
        }
      }));
    }

    return new Promise((resolve, reject) => {
      client.modify(dn, changes, (err) => {
        client.unbind();
        if (err) {
          return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, dn, modified: true });
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete OU
app.post('/api/ous/delete', authenticate, async (req, res) => {
  try {
    const { dn } = req.body;

    if (!dn) {
      return res.status(400).json({ success: false, error: 'dn is required' });
    }

    const client = await createLdapClient();

    return new Promise((resolve, reject) => {
      client.del(dn, (err) => {
        client.unbind();
        if (err) {
          return res.status(500).json({ success: false, error: err.message });
        }
        res.json({ success: true, dn, deleted: true });
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Search OUs
app.post('/api/ous/search', authenticate, async (req, res) => {
  try {
    const { searchTerm, maxResults } = req.body;

    if (!searchTerm) {
      return res.status(400).json({ success: false, error: 'searchTerm is required' });
    }

    const escapedTerm = escapeLdap(searchTerm);
    const filter = `(&(objectClass=organizationalUnit)(ou=*${escapedTerm}*))`;
    const limit = maxResults || 100;

    const ous = await searchMany(filter, ['*'], limit);
    res.json({ success: true, ous, count: ous.length });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Start server
const PORT = config.port;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ AD Collector listening on port ${PORT}`);
  console.log(`📍 Health check: http://localhost:${PORT}/health`);
  console.log(`🧪 Test endpoint: POST http://localhost:${PORT}/api/test-connection`);
  console.log('');
});
