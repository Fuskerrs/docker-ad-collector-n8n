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
console.log('AD Collector for n8n - v1.1.2');
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

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'ad-collector', version: '1.1.2' });
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
