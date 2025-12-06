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
console.log('AD Collector for n8n - v2.1.0');
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

// Helper to parse Windows Security Descriptor (nTSecurityDescriptor)
// Returns simplified ACL information for vulnerability detection
function parseSecurityDescriptor(sdBuffer) {
  if (!sdBuffer || !Buffer.isBuffer(sdBuffer)) {
    return { aces: [], error: 'Invalid buffer' };
  }

  try {
    // Security Descriptor structure (simplified):
    // Offset 0: Revision (1 byte) - Should be 0x01
    // Offset 1: Sbz1 (1 byte) - Reserved, should be 0x00
    // Offset 2-3: Control flags (2 bytes, little-endian)
    // Offset 4-7: Owner SID offset (4 bytes, little-endian)
    // Offset 8-11: Group SID offset (4 bytes, little-endian)
    // Offset 12-15: SACL offset (4 bytes, little-endian)
    // Offset 16-19: DACL offset (4 bytes, little-endian)

    const revision = sdBuffer.readUInt8(0);
    if (revision !== 0x01) {
      return { aces: [], error: `Unsupported revision: ${revision}` };
    }

    const daclOffset = sdBuffer.readUInt32LE(16);
    if (daclOffset === 0 || daclOffset >= sdBuffer.length) {
      return { aces: [], error: 'No DACL found' };
    }

    // Parse DACL
    // DACL structure:
    // Offset 0: AclRevision (1 byte)
    // Offset 1: Sbz1 (1 byte)
    // Offset 2-3: AclSize (2 bytes, little-endian)
    // Offset 4-5: AceCount (2 bytes, little-endian)
    // Offset 6-7: Sbz2 (2 bytes)
    // Offset 8+: ACEs

    const aclRevision = sdBuffer.readUInt8(daclOffset);
    const aceCount = sdBuffer.readUInt16LE(daclOffset + 4);

    const aces = [];
    let aceOffset = daclOffset + 8; // Start of first ACE

    for (let i = 0; i < aceCount && aceOffset < sdBuffer.length; i++) {
      try {
        // ACE structure (simplified):
        // Offset 0: AceType (1 byte)
        // Offset 1: AceFlags (1 byte)
        // Offset 2-3: AceSize (2 bytes, little-endian)
        // Offset 4-7: Access Mask (4 bytes, little-endian)
        // Offset 8+: SID

        const aceType = sdBuffer.readUInt8(aceOffset);
        const aceFlags = sdBuffer.readUInt8(aceOffset + 1);
        const aceSize = sdBuffer.readUInt16LE(aceOffset + 2);
        const accessMask = sdBuffer.readUInt32LE(aceOffset + 4);

        // Parse SID (simplified - just extract key parts)
        const sidOffset = aceOffset + 8;
        const sidRevision = sdBuffer.readUInt8(sidOffset);
        const sidSubAuthorityCount = sdBuffer.readUInt8(sidOffset + 1);
        const sidIdentifierAuthority = sdBuffer.readUIntBE(sidOffset + 2, 6);

        // Read sub-authorities
        let sid = `S-${sidRevision}-${sidIdentifierAuthority}`;
        for (let j = 0; j < sidSubAuthorityCount && (sidOffset + 8 + j * 4) < sdBuffer.length; j++) {
          const subAuth = sdBuffer.readUInt32LE(sidOffset + 8 + j * 4);
          sid += `-${subAuth}`;
        }

        // Check for well-known SIDs and dangerous permissions
        const isEveryone = sid === 'S-1-1-0';
        const isAuthenticatedUsers = sid === 'S-1-5-11';
        const isAnonymous = sid === 'S-1-5-7';

        // Access Mask flags (from Windows SDK)
        const GENERIC_ALL = 0x10000000;
        const GENERIC_WRITE = 0x40000000;
        const WRITE_DACL = 0x00040000;
        const WRITE_OWNER = 0x00080000;
        const CONTROL_ACCESS = 0x00000100; // ExtendedRight (includes ForceChangePassword)
        const WRITE_PROPERTY = 0x00000020; // Includes WriteSPN

        const hasGenericAll = (accessMask & GENERIC_ALL) !== 0;
        const hasGenericWrite = (accessMask & GENERIC_WRITE) !== 0;
        const hasWriteDACL = (accessMask & WRITE_DACL) !== 0;
        const hasWriteOwner = (accessMask & WRITE_OWNER) !== 0;
        const hasControlAccess = (accessMask & CONTROL_ACCESS) !== 0;
        const hasWriteProperty = (accessMask & WRITE_PROPERTY) !== 0;

        aces.push({
          type: aceType,
          flags: aceFlags,
          accessMask: accessMask,
          sid: sid,
          isEveryone,
          isAuthenticatedUsers,
          isAnonymous,
          permissions: {
            genericAll: hasGenericAll,
            genericWrite: hasGenericWrite,
            writeDACL: hasWriteDACL,
            writeOwner: hasWriteOwner,
            controlAccess: hasControlAccess,
            writeProperty: hasWriteProperty
          }
        });

        aceOffset += aceSize;
      } catch (e) {
        // Skip malformed ACE
        break;
      }
    }

    return { aces, daclOffset, aceCount };
  } catch (e) {
    return { aces: [], error: e.message };
  }
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
  res.json({ status: 'ok', service: 'ad-collector', version: '2.1.0' });
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
        findings.medium.push({ type: 'PASSWORD_NEVER_EXPIRES', ...getUserDetails(user) });
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
        findings.low.push({ type: 'USER_CANNOT_CHANGE_PASSWORD', ...getUserDetails(user) });
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
      protectedUsers: [],
      preWindows2000Access: []
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
      'Protected Users': 'protectedUsers',
      'Pre-Windows 2000 Compatible Access': 'preWindows2000Access'
    };

    for (const [groupName, key] of Object.entries(privGroups)) {
      try {
        const group = await searchOne(`(sAMAccountName=${escapeLdap(groupName)})`);
        const members = group.attributes.find(a => a.type === 'member')?.values || [];
        privilegedAccounts[key] = members.map(dn => ({ dn }));

        // Add findings for group memberships
        for (const memberDn of members) {
          if (key === 'backupOperators') {
            findings.high.push({ type: 'BACKUP_OPERATORS_MEMBER', dn: memberDn });
          } else if (key === 'accountOperators') {
            findings.high.push({ type: 'ACCOUNT_OPERATORS_MEMBER', dn: memberDn });
          } else if (key === 'serverOperators') {
            findings.high.push({ type: 'SERVER_OPERATORS_MEMBER', dn: memberDn });
          } else if (key === 'printOperators') {
            findings.high.push({ type: 'PRINT_OPERATORS_MEMBER', dn: memberDn });
          } else if (key === 'schemaAdmins') {
            findings.medium.push({ type: 'SCHEMA_ADMINS_MEMBER', dn: memberDn });
          } else if (key === 'enterpriseAdmins') {
            findings.medium.push({ type: 'ENTERPRISE_ADMINS_MEMBER', dn: memberDn });
          } else if (key === 'domainAdmins') {
            findings.medium.push({ type: 'DOMAIN_ADMINS_MEMBER', dn: memberDn });
          } else if (key === 'administrators') {
            findings.medium.push({ type: 'ADMINISTRATORS_MEMBER', dn: memberDn });
          }
        }

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

    // Check Pre-Windows 2000 Compatible Access group for Everyone/Authenticated Users (Phase 2)
    const preWin2000Members = privilegedAccounts.preWindows2000Access.map(m => m.dn);
    for (const memberDn of preWin2000Members) {
      // Check for Everyone (S-1-1-0) or Authenticated Users (S-1-5-11)
      // These are typically represented as CN=S-1-1-0 or similar in the DN
      if (memberDn.includes('S-1-1-0') || memberDn.toLowerCase().includes('cn=everyone')) {
        findings.medium.push({
          type: 'PRE_WINDOWS_2000_ACCESS',
          dn: memberDn,
          member: 'Everyone',
          message: 'Everyone has Pre-Windows 2000 Compatible Access (full AD read access)'
        });
      } else if (memberDn.includes('S-1-5-11') || memberDn.toLowerCase().includes('cn=authenticated users')) {
        findings.medium.push({
          type: 'PRE_WINDOWS_2000_ACCESS',
          dn: memberDn,
          member: 'Authenticated Users',
          message: 'Authenticated Users has Pre-Windows 2000 Compatible Access'
        });
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

    // STEP 06b: Golden Ticket Risk Assessment
    try {
      const krbtgtUser = await searchOne('(sAMAccountName=krbtgt)');
      if (krbtgtUser) {
        const pwdLastSet = fileTimeToDate(krbtgtUser.attributes.find(a => a.type === 'pwdLastSet')?.values[0]);
        if (pwdLastSet) {
          const pwdAge = Math.floor((now - pwdLastSet.getTime()) / (24 * 60 * 60 * 1000));
          const goldenTicketThreshold = 180; // 180 days

          if (pwdAge > goldenTicketThreshold) {
            findings.critical.push({
              type: 'GOLDEN_TICKET_RISK',
              dn: krbtgtUser.objectName,
              samAccountName: 'krbtgt',
              passwordAge: pwdAge,
              threshold: goldenTicketThreshold,
              message: `krbtgt password is ${pwdAge} days old (threshold: ${goldenTicketThreshold} days)`
            });
          }
        }
      }
      trackStep('STEP_06b_GOLDEN_TICKET', 'Golden Ticket risk assessment', { count: 1 });
    } catch (e) {
      // krbtgt account not found (unlikely but possible in test environments)
    }
    stepStart = Date.now();

    // STEP 07: Service Accounts Detection
    const serviceAccounts = {
      detectedBySPN: [],
      detectedByName: [],
      detectedByDescription: []
    };

    const servicePatterns = /^(svc|service|sql|apache|nginx|iis|app|api|bot)/i;
    const descPatterns = /(service|application|automated|api|bot)/i;

    const spnMap = new Map(); // Map to track SPN -> [users]

    for (const user of allUsers) {
      const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || '';
      const desc = user.attributes.find(a => a.type === 'description')?.values[0] || '';
      const spn = user.attributes.find(a => a.type === 'servicePrincipalName')?.values || [];
      const dn = user.objectName;

      if (spn.length > 0) {
        serviceAccounts.detectedBySPN.push({ ...getUserDetails(user), spnCount: spn.length });

        // Track SPNs for duplicate detection (Phase 2)
        for (const spnValue of spn) {
          if (!spnMap.has(spnValue)) {
            spnMap.set(spnValue, []);
          }
          spnMap.get(spnValue).push({ sam, dn });
        }
      } else if (servicePatterns.test(sam)) {
        serviceAccounts.detectedByName.push(getUserDetails(user));
      } else if (descPatterns.test(desc)) {
        serviceAccounts.detectedByDescription.push({ ...getUserDetails(user), description: desc });
      }
    }

    // Detect duplicate SPNs (Phase 2)
    for (const [spnValue, users] of spnMap.entries()) {
      if (users.length > 1) {
        findings.low.push({
          type: 'DUPLICATE_SPN',
          spn: spnValue,
          accountCount: users.length,
          accounts: users.map(u => u.sam).join(', '),
          message: `SPN "${spnValue}" is registered on ${users.length} accounts`
        });
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

      // Domain admin in description (Phase 2)
      const domainAdminPattern = /(domain\s*admin|administrateur|admin\s*domain)/i;
      if (domainAdminPattern.test(desc) || domainAdminPattern.test(info)) {
        findings.medium.push({ type: 'DOMAIN_ADMIN_IN_DESCRIPTION', ...getUserDetails(user), description: desc || info });
      }

      // LAPS password leaked in description (Phase 2)
      const lapsPattern = /(laps|local\s*admin\s*password)/i;
      if (lapsPattern.test(desc) || lapsPattern.test(info)) {
        findings.medium.push({ type: 'LAPS_PASSWORD_LEAKED', ...getUserDetails(user), description: desc || info });
      }

      // Dangerous logon scripts (Phase 2)
      const scriptPath = user.attributes.find(a => a.type === 'scriptPath')?.values[0];
      if (scriptPath) {
        findings.medium.push({ type: 'DANGEROUS_LOGON_SCRIPTS', ...getUserDetails(user), scriptPath });
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

      // Weak Kerberos encryption detection
      // msDS-SupportedEncryptionTypes flags:
      // 0x1 = DES_CBC_CRC, 0x2 = DES_CBC_MD5, 0x4 = RC4_HMAC_MD5
      // 0x8 = AES128_CTS_HMAC_SHA1_96, 0x10 = AES256_CTS_HMAC_SHA1_96
      const uac = parseInt(user.attributes.find(a => a.type === 'userAccountControl')?.values[0] || '0');
      const supportedEncTypes = user.attributes.find(a => a.type === 'msDS-SupportedEncryptionTypes')?.values[0];

      if (supportedEncTypes) {
        const encTypes = parseInt(supportedEncTypes);
        const hasDES = encTypes & 0x3;    // DES_CBC_CRC or DES_CBC_MD5
        const hasRC4 = encTypes & 0x4;    // RC4_HMAC_MD5
        const hasAES = encTypes & 0x18;   // AES128 or AES256

        // Critical: DES enabled (extremely weak, crackable in hours)
        if (hasDES) {
          const encList = [];
          if (encTypes & 0x1) encList.push('DES-CBC-CRC');
          if (encTypes & 0x2) encList.push('DES-CBC-MD5');
          advancedSecurity.weakEncryption.push({ ...getUserDetails(user), reason: `DES enabled: ${encList.join(', ')}`, severity: 'critical' });
          findings.critical.push({ type: 'WEAK_ENCRYPTION_DES', ...getUserDetails(user), algorithms: encList.join(', ') });
        }
        // High: RC4-only or no AES (RC4 has known weaknesses)
        else if (hasRC4 && !hasAES) {
          advancedSecurity.weakEncryption.push({ ...getUserDetails(user), reason: 'RC4-only (no AES)', severity: 'high' });
          findings.high.push({ type: 'WEAK_ENCRYPTION_RC4', ...getUserDetails(user), algorithms: 'RC4-HMAC-MD5' });
        }
        // Medium: RC4 enabled alongside AES (not ideal but less critical)
        else if (hasRC4 && hasAES) {
          advancedSecurity.weakEncryption.push({ ...getUserDetails(user), reason: 'RC4 enabled (AES available)', severity: 'medium' });
          findings.medium.push({ type: 'WEAK_ENCRYPTION_RC4_WITH_AES', ...getUserDetails(user), algorithms: 'RC4-HMAC-MD5' });
        }
      }
      // Use DES keys flag in UAC
      if (uac & 0x200000) {
        advancedSecurity.weakEncryption.push({ ...getUserDetails(user), reason: 'USE_DES_KEY_ONLY flag set', severity: 'high' });
        findings.high.push({ type: 'WEAK_ENCRYPTION_FLAG', ...getUserDetails(user) });
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

    // Check for privileged accounts without smartcard required
    for (const account of highPrivilegeAccounts) {
      // Find the user object to check UAC
      const user = allUsers.find(u => u.objectName === account.dn);
      if (user) {
        const uac = parseInt(user.attributes.find(a => a.type === 'userAccountControl')?.values[0] || '0');
        const smartcardRequired = uac & 0x40000; // SMARTCARD_REQUIRED flag
        if (!smartcardRequired) {
          findings.low.push({ type: 'SMARTCARD_NOT_REQUIRED', dn: account.dn });
        }
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

    // Check for expired accounts in admin groups (Phase 2)
    const allAdminDns = [
      ...privilegedAccounts.domainAdmins.map(a => a.dn),
      ...privilegedAccounts.enterpriseAdmins.map(a => a.dn),
      ...privilegedAccounts.schemaAdmins.map(a => a.dn),
      ...privilegedAccounts.administrators.map(a => a.dn)
    ];

    for (const user of allUsers) {
      const dn = user.objectName;
      if (allAdminDns.includes(dn)) {
        const uac = parseInt(user.attributes.find(a => a.type === 'userAccountControl')?.values[0] || '0');
        const accountExpires = user.attributes.find(a => a.type === 'accountExpires')?.values[0];

        // Expired account in admin group
        if (accountExpires && accountExpires !== '0' && accountExpires !== '9223372036854775807') {
          const expiryDate = fileTimeToDate(accountExpires);
          if (expiryDate && expiryDate.getTime() < now) {
            findings.medium.push({ type: 'EXPIRED_ACCOUNT_IN_ADMIN_GROUP', ...getUserDetails(user), expiryDate: formatDate(expiryDate) });
          }
        }

        // Disabled account in admin group
        if (uac & 0x2) {
          findings.medium.push({ type: 'DISABLED_ACCOUNT_IN_ADMIN_GROUP', ...getUserDetails(user) });
        }
      }

      // PrimaryGroupID spoofing (primaryGroupID=512 but not in DA memberOf)
      const primaryGroupID = user.attributes.find(a => a.type === 'primaryGroupID')?.values[0];
      if (primaryGroupID === '512') { // 512 = Domain Admins RID
        const memberOf = user.attributes.find(a => a.type === 'memberOf')?.values || [];
        const isDomainAdminMember = memberOf.some(dn => dn.includes('CN=Domain Admins,'));
        if (!isDomainAdminMember) {
          findings.medium.push({ type: 'PRIMARYGROUPID_SPOOFING', ...getUserDetails(user), primaryGroupID: '512' });
        }
      }
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

    // STEP 13b: Domain Configuration Security Checks (Phase 2)
    try {
      // Get domain object
      const domainObj = await searchOne('(objectClass=domain)');
      if (domainObj) {
        // Check Machine Account Quota (HIGH risk if > 0, allows any user to join computers)
        const machineAccountQuota = domainObj.attributes.find(a => a.type === 'ms-DS-MachineAccountQuota')?.values[0];
        if (machineAccountQuota && parseInt(machineAccountQuota) > 0) {
          findings.high.push({
            type: 'MACHINE_ACCOUNT_QUOTA_ABUSE',
            quota: parseInt(machineAccountQuota),
            message: `Machine Account Quota is ${machineAccountQuota} (allows users to join computers to domain)`
          });
        }

        // Check Kerberos Policy (LOW risk if MaxTicketAge > 10 hours)
        const maxTicketAge = domainObj.attributes.find(a => a.type === 'maxTicketAge')?.values[0];
        if (maxTicketAge) {
          const maxTicketAgeHours = parseInt(maxTicketAge) / 10000000 / 3600; // Convert to hours
          if (maxTicketAgeHours > 10) {
            findings.low.push({
              type: 'WEAK_KERBEROS_POLICY',
              maxTicketAge: Math.floor(maxTicketAgeHours),
              threshold: 10,
              message: `MaxTicketAge is ${Math.floor(maxTicketAgeHours)} hours (threshold: 10 hours)`
            });
          }
        }

        // Check Password Policy (MEDIUM risk if weak settings)
        const minPwdLength = domainObj.attributes.find(a => a.type === 'minPwdLength')?.values[0];
        const pwdHistoryLength = domainObj.attributes.find(a => a.type === 'pwdHistoryLength')?.values[0];
        const minPwdAge = domainObj.attributes.find(a => a.type === 'minPwdAge')?.values[0];

        const weakPolicyIssues = [];
        if (minPwdLength && parseInt(minPwdLength) < 14) {
          weakPolicyIssues.push(`MinPasswordLength=${minPwdLength} (recommended: 14+)`);
        }
        if (pwdHistoryLength && parseInt(pwdHistoryLength) < 24) {
          weakPolicyIssues.push(`PasswordHistoryLength=${pwdHistoryLength} (recommended: 24+)`);
        }
        if (minPwdAge) {
          const minPwdAgeDays = Math.abs(parseInt(minPwdAge)) / 10000000 / 86400;
          if (minPwdAgeDays < 1) {
            weakPolicyIssues.push(`MinPasswordAge=${Math.floor(minPwdAgeDays)} days (recommended: 1+)`);
          }
        }

        if (weakPolicyIssues.length > 0) {
          findings.medium.push({
            type: 'WEAK_PASSWORD_POLICY',
            issues: weakPolicyIssues.join(', '),
            minPwdLength: parseInt(minPwdLength || 0),
            pwdHistoryLength: parseInt(pwdHistoryLength || 0)
          });
        }
      }
      trackStep('STEP_13b_DOMAIN_CONFIG', 'Domain configuration security checks', { count: 1 });
    } catch (e) {
      // Domain object query failed
    }
    stepStart = Date.now();

    // STEP 13c: Computer Unconstrained Delegation Check (Phase 2)
    try {
      const computersWithDelegation = await searchMany('(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))', ['sAMAccountName', 'dNSHostName'], 100);
      for (const computer of computersWithDelegation) {
        const sam = computer.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || 'Unknown';
        const dnsHostName = computer.attributes.find(a => a.type === 'dNSHostName')?.values[0] || sam;
        findings.high.push({
          type: 'COMPUTER_UNCONSTRAINED_DELEGATION',
          samAccountName: sam,
          dnsHostName: dnsHostName,
          dn: computer.objectName,
          message: 'Computer has unconstrained delegation (vulnerable to PrinterBug/PetitPotam attacks)'
        });
      }
      trackStep('STEP_13c_COMPUTER_DELEGATION', 'Computer delegation security check', { count: computersWithDelegation.length });
    } catch (e) {
      // Computer query failed
    }
    stepStart = Date.now();

    // STEP 13d: Phase 3+4 Advanced Security Checks
    try {
      // FOREIGN_SECURITY_PRINCIPALS (051 - MEDIUM) - Check for external forest principals in sensitive groups
      try {
        const foreignPrincipals = await searchMany('(objectClass=foreignSecurityPrincipal)', ['*'], 100);
        for (const fsp of foreignPrincipals) {
          const memberOf = fsp.attributes.find(a => a.type === 'memberOf')?.values || [];
          const sensitiveGroups = memberOf.filter(dn =>
            dn.includes('Domain Admins') || dn.includes('Enterprise Admins') ||
            dn.includes('Schema Admins') || dn.includes('Administrators')
          );
          if (sensitiveGroups.length > 0) {
            findings.medium.push({
              type: 'FOREIGN_SECURITY_PRINCIPALS',
              dn: fsp.objectName,
              groups: sensitiveGroups.join('; '),
              message: 'External forest principal in sensitive group'
            });
          }
        }
      } catch (e) {}

      // NTLM_RELAY_OPPORTUNITY (065 - LOW) - Informational: NTLM relay risk exists
      findings.low.push({
        type: 'NTLM_RELAY_OPPORTUNITY',
        message: 'NTLM authentication enabled (relay attacks possible if SMB signing not enforced)',
        recommendation: 'Enable SMB signing and disable NTLM where possible'
      });

      trackStep('STEP_13d_ADVANCED_CHECKS', 'Advanced security checks (Phase 2 partiel)', { count: 2 });
    } catch (e) {
      // Advanced checks failed
    }
    stepStart = Date.now();

    // ==========================================
    // STEP 13e: PHASE 3 - ACL & Advanced Checks
    // ==========================================
    try {
      // SHADOW_CREDENTIALS (066 - CRITICAL) - msDS-KeyCredentialLink abuse
      try {
        const shadowCredsAccounts = await searchMany(
          '(msDS-KeyCredentialLink=*)',
          ['sAMAccountName', 'msDS-KeyCredentialLink', 'userAccountControl'],
          200
        );

        for (const account of shadowCredsAccounts) {
          const sam = account.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || 'Unknown';
          const keyCredLink = account.attributes.find(a => a.type === 'msDS-KeyCredentialLink')?.values || [];

          if (keyCredLink.length > 0) {
            findings.critical.push({
              type: 'SHADOW_CREDENTIALS',
              samAccountName: sam,
              dn: account.objectName,
              keyCount: keyCredLink.length,
              message: 'Shadow Credentials configured (msDS-KeyCredentialLink) - Kerberos authentication bypass risk'
            });
          }
        }
      } catch (e) {}

      // RBCD_ABUSE (067 - CRITICAL) - Resource-Based Constrained Delegation abuse
      try {
        const rbcdAccounts = await searchMany(
          '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)',
          ['sAMAccountName', 'dNSHostName', 'msDS-AllowedToActOnBehalfOfOtherIdentity'],
          200
        );

        for (const account of rbcdAccounts) {
          const sam = account.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || 'Unknown';
          const dnsHostName = account.attributes.find(a => a.type === 'dNSHostName')?.values[0] || sam;

          findings.critical.push({
            type: 'RBCD_ABUSE',
            samAccountName: sam,
            dnsHostName: dnsHostName,
            dn: account.objectName,
            message: 'Resource-Based Constrained Delegation configured - Potential privilege escalation'
          });
        }
      } catch (e) {}

      // DANGEROUS_GROUP_NESTING (068 - MEDIUM) - Nested groups leading to unintended privilege escalation
      try {
        const nestedGroupIssues = [];
        const sensitiveGroupNames = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators'];

        for (const [groupName, members] of Object.entries(privilegedAccounts)) {
          if (['domainAdmins', 'enterpriseAdmins', 'schemaAdmins', 'administrators'].includes(groupName)) {
            // Check if any members are groups themselves
            for (const member of members) {
              const memberDn = member.dn || member;

              // If it's a group (contains "CN=...") and not a user
              if (memberDn.startsWith('CN=') && !memberDn.includes('CN=Users,')) {
                // Check if this is a nested group
                const isNestedGroup = allUsers.some(u => u.objectName === memberDn &&
                  u.attributes.find(a => a.type === 'objectClass')?.values.includes('group'));

                if (isNestedGroup) {
                  findings.medium.push({
                    type: 'DANGEROUS_GROUP_NESTING',
                    parentGroup: groupName,
                    nestedGroup: memberDn,
                    message: `Nested group in ${groupName} - May grant unintended privileges`
                  });
                }
              }
            }
          }
        }
      } catch (e) {}

      // ADMINSDHOLDER_BACKDOOR (069 - MEDIUM) - AdminSDHolder modifications for persistence
      try {
        const adminSDHolder = await searchOne('(cn=AdminSDHolder)');
        if (adminSDHolder) {
          const whenChanged = adminSDHolder.attributes.find(a => a.type === 'whenChanged')?.values[0];
          const whenCreated = adminSDHolder.attributes.find(a => a.type === 'whenCreated')?.values[0];

          // If AdminSDHolder was modified recently (within last 90 days), flag it
          if (whenChanged && whenCreated) {
            const changedDate = new Date(whenChanged);
            const createdDate = new Date(whenCreated);
            const daysSinceChange = Math.floor((now - changedDate.getTime()) / (24 * 60 * 60 * 1000));
            const daysSinceCreation = Math.floor((now - createdDate.getTime()) / (24 * 60 * 60 * 1000));

            // If changed after creation and within last 90 days, might be backdoor
            if (daysSinceChange < 90 && daysSinceChange < daysSinceCreation) {
              findings.medium.push({
                type: 'ADMINSDHOLDER_BACKDOOR',
                dn: adminSDHolder.objectName,
                whenChanged: whenChanged,
                daysSinceChange: daysSinceChange,
                message: 'AdminSDHolder modified recently - Potential ACL backdoor for persistence'
              });
            }
          }
        }
      } catch (e) {}

      // ACL-Based Detections - Analyze nTSecurityDescriptor for dangerous permissions
      try {
        // Get sensitive objects to check ACLs on (Domain root, AdminSDHolder, Domain Admins group, etc.)
        const sensitiveObjects = [];

        // Add domain root
        try {
          const domainRoot = await searchOne('(objectClass=domain)');
          if (domainRoot) sensitiveObjects.push({ obj: domainRoot, type: 'Domain Root' });
        } catch (e) {}

        // Add AdminSDHolder
        try {
          const adminSDHolder = await searchOne('(cn=AdminSDHolder)');
          if (adminSDHolder) sensitiveObjects.push({ obj: adminSDHolder, type: 'AdminSDHolder' });
        } catch (e) {}

        // Add Domain Admins group
        try {
          const domainAdminsGroup = await searchOne('(cn=Domain Admins)');
          if (domainAdminsGroup) sensitiveObjects.push({ obj: domainAdminsGroup, type: 'Domain Admins Group' });
        } catch (e) {}

        // Add Enterprise Admins group
        try {
          const enterpriseAdminsGroup = await searchOne('(cn=Enterprise Admins)');
          if (enterpriseAdminsGroup) sensitiveObjects.push({ obj: enterpriseAdminsGroup, type: 'Enterprise Admins Group' });
        } catch (e) {}

        // Analyze ACLs on sensitive objects
        for (const { obj, type } of sensitiveObjects) {
          try {
            const ntSecDesc = obj.attributes.find(a => a.type === 'nTSecurityDescriptor')?.values[0];
            if (!ntSecDesc) continue;

            // Convert to Buffer if needed
            const sdBuffer = Buffer.isBuffer(ntSecDesc) ? ntSecDesc : Buffer.from(ntSecDesc);
            const aclData = parseSecurityDescriptor(sdBuffer);

            if (aclData.error || !aclData.aces || aclData.aces.length === 0) continue;

            // Check each ACE for dangerous permissions
            for (const ace of aclData.aces) {
              const targetDn = obj.objectName;

              // ACL_GENERICALL (070 - HIGH) - GenericAll on sensitive objects
              if (ace.permissions.genericAll && !ace.sid.includes('S-1-5-32-544')) { // Exclude BUILTIN\Administrators
                findings.high.push({
                  type: 'ACL_GENERICALL',
                  targetObject: type,
                  targetDn: targetDn,
                  trusteeSid: ace.sid,
                  message: `GenericAll permission on ${type} - Full control abuse risk`
                });
              }

              // ACL_WRITEDACL (071 - HIGH) - WriteDACL on sensitive objects
              if (ace.permissions.writeDACL && !ace.sid.includes('S-1-5-32-544')) {
                findings.high.push({
                  type: 'ACL_WRITEDACL',
                  targetObject: type,
                  targetDn: targetDn,
                  trusteeSid: ace.sid,
                  message: `WriteDACL permission on ${type} - ACL modification risk`
                });
              }

              // ACL_WRITEOWNER (072 - HIGH) - WriteOwner on sensitive objects
              if (ace.permissions.writeOwner && !ace.sid.includes('S-1-5-32-544')) {
                findings.high.push({
                  type: 'ACL_WRITEOWNER',
                  targetObject: type,
                  targetDn: targetDn,
                  trusteeSid: ace.sid,
                  message: `WriteOwner permission on ${type} - Ownership takeover risk`
                });
              }

              // EVERYONE_IN_ACL (073 - MEDIUM) - Everyone/Authenticated Users with dangerous permissions
              if ((ace.isEveryone || ace.isAuthenticatedUsers) &&
                  (ace.permissions.genericAll || ace.permissions.genericWrite ||
                   ace.permissions.writeDACL || ace.permissions.writeOwner)) {
                findings.medium.push({
                  type: 'EVERYONE_IN_ACL',
                  targetObject: type,
                  targetDn: targetDn,
                  trusteeSid: ace.sid,
                  trusteeType: ace.isEveryone ? 'Everyone' : 'Authenticated Users',
                  permissions: Object.keys(ace.permissions).filter(k => ace.permissions[k]).join(', '),
                  message: `${ace.isEveryone ? 'Everyone' : 'Authenticated Users'} has dangerous permissions on ${type}`
                });
              }

              // ACL_GENERICWRITE (074 - MEDIUM) - GenericWrite on sensitive objects
              if (ace.permissions.genericWrite && !ace.sid.includes('S-1-5-32-544')) {
                findings.medium.push({
                  type: 'ACL_GENERICWRITE',
                  targetObject: type,
                  targetDn: targetDn,
                  trusteeSid: ace.sid,
                  message: `GenericWrite permission on ${type} - Attribute modification risk`
                });
              }

              // ACL_FORCECHANGEPASSWORD (075 - MEDIUM) - ControlAccess (ExtendedRight) for password reset
              if (ace.permissions.controlAccess && type.includes('Domain Admins')) {
                findings.medium.push({
                  type: 'ACL_FORCECHANGEPASSWORD',
                  targetObject: type,
                  targetDn: targetDn,
                  trusteeSid: ace.sid,
                  message: `Extended rights on ${type} - Potential password reset abuse`
                });
              }

              // WRITESPN_ABUSE (076 - MEDIUM) - WriteProperty for targeted Kerberoasting
              if (ace.permissions.writeProperty && type.includes('Domain')) {
                findings.medium.push({
                  type: 'WRITESPN_ABUSE',
                  targetObject: type,
                  targetDn: targetDn,
                  trusteeSid: ace.sid,
                  message: `WriteProperty permission on ${type} - WriteSPN for targeted Kerberoasting`
                });
              }
            }
          } catch (e) {
            // Failed to parse ACL for this object
          }
        }

        // GPO_LINK_POISONING (077 - MEDIUM) - Weak ACLs on GPO links
        try {
          const gpos = await searchMany('(objectClass=groupPolicyContainer)', ['displayName', 'nTSecurityDescriptor'], 50);

          for (const gpo of gpos) {
            const displayName = gpo.attributes.find(a => a.type === 'displayName')?.values[0] || 'Unknown GPO';
            const ntSecDesc = gpo.attributes.find(a => a.type === 'nTSecurityDescriptor')?.values[0];

            if (ntSecDesc) {
              const sdBuffer = Buffer.isBuffer(ntSecDesc) ? ntSecDesc : Buffer.from(ntSecDesc);
              const aclData = parseSecurityDescriptor(sdBuffer);

              if (aclData.aces) {
                for (const ace of aclData.aces) {
                  // Check if non-admin has write access to GPO
                  if ((ace.permissions.genericAll || ace.permissions.genericWrite || ace.permissions.writeDACL) &&
                      (ace.isEveryone || ace.isAuthenticatedUsers)) {
                    findings.medium.push({
                      type: 'GPO_LINK_POISONING',
                      gpoName: displayName,
                      gpoDn: gpo.objectName,
                      trusteeSid: ace.sid,
                      trusteeType: ace.isEveryone ? 'Everyone' : 'Authenticated Users',
                      message: `Weak ACL on GPO "${displayName}" - GPO modification risk`
                    });
                  }
                }
              }
            }
          }
        } catch (e) {}

      } catch (e) {
        // ACL analysis failed
      }

      trackStep('STEP_13e_PHASE3', 'Phase 3 security checks (ACL + Advanced)', { count: 12 });
    } catch (e) {
      // Phase 3 checks failed
    }
    stepStart = Date.now();

    // STEP 13f: PHASE 4 - ADCS/PKI + LAPS Security Checks
    try {
      // Get Configuration naming context for ADCS objects
      const configurationNC = domainRoot.attributes.find(a => a.type === 'configurationNamingContext')?.values[0];

      if (configurationNC) {
        // ADCS Certificate Templates Analysis
        try {
          const certTemplates = await searchMany(
            '(objectClass=pKICertificateTemplate)',
            ['cn', 'displayName', 'pKIExtendedKeyUsage', 'msPKI-Certificate-Name-Flag',
             'msPKI-Enrollment-Flag', 'nTSecurityDescriptor', 'msPKI-Certificate-Application-Policy'],
            100,
            configurationNC
          );

          for (const template of certTemplates) {
            const cn = template.attributes.find(a => a.type === 'cn')?.values[0] || 'Unknown';
            const displayName = template.attributes.find(a => a.type === 'displayName')?.values[0] || cn;
            const ekus = template.attributes.find(a => a.type === 'pKIExtendedKeyUsage')?.values || [];
            const appPolicies = template.attributes.find(a => a.type === 'msPKI-Certificate-Application-Policy')?.values || [];
            const nameFlags = template.attributes.find(a => a.type === 'msPKI-Certificate-Name-Flag')?.values[0];
            const enrollFlags = template.attributes.find(a => a.type === 'msPKI-Enrollment-Flag')?.values[0];

            // Combine EKUs and Application Policies
            const allEkus = [...ekus, ...appPolicies];

            // Client Authentication OID
            const CLIENT_AUTH_OID = '1.3.6.1.5.5.7.3.2';
            const ANY_PURPOSE_OID = '2.5.29.37.0';
            const ENROLLMENT_AGENT_OID = '1.3.6.1.4.1.311.20.2.1';

            const hasClientAuth = allEkus.includes(CLIENT_AUTH_OID);
            const hasAnyPurpose = allEkus.includes(ANY_PURPOSE_OID) || allEkus.length === 0;
            const hasEnrollmentAgent = allEkus.includes(ENROLLMENT_AGENT_OID);

            // Certificate name flags (bitwise)
            const ENROLLEE_SUPPLIES_SUBJECT = 0x00000001;
            const SUBJECT_ALT_REQUIRE_UPN = 0x01000000;
            const SUBJECT_ALT_REQUIRE_DNS = 0x08000000;

            const enrolleeSuppliesSubject = nameFlags && (nameFlags & ENROLLEE_SUPPLIES_SUBJECT);

            // ESC1_VULNERABLE_TEMPLATE (078 - CRITICAL)
            if (hasClientAuth && enrolleeSuppliesSubject) {
              findings.critical.push({
                type: 'ESC1_VULNERABLE_TEMPLATE',
                templateName: displayName,
                templateCN: cn,
                dn: template.objectName,
                message: `Certificate template "${displayName}" allows client authentication with enrollee-supplied subject (ESC1) - Domain takeover risk`,
                ekus: allEkus,
                nameFlags: nameFlags
              });
            }

            // ESC2_ANY_PURPOSE (079 - CRITICAL)
            if (hasAnyPurpose && !hasClientAuth) {
              findings.critical.push({
                type: 'ESC2_ANY_PURPOSE',
                templateName: displayName,
                templateCN: cn,
                dn: template.objectName,
                message: `Certificate template "${displayName}" allows Any Purpose EKU (ESC2) - Can be used for any authentication`,
                ekus: allEkus.length === 0 ? ['No EKU restrictions'] : allEkus
              });
            }

            // ESC3_ENROLLMENT_AGENT (080 - HIGH)
            if (hasEnrollmentAgent) {
              findings.high.push({
                type: 'ESC3_ENROLLMENT_AGENT',
                templateName: displayName,
                templateCN: cn,
                dn: template.objectName,
                message: `Certificate template "${displayName}" is an Enrollment Agent template (ESC3) - Can request certificates on behalf of others`,
                ekus: allEkus
              });
            }

            // ESC4_VULNERABLE_TEMPLATE_ACL (081 - HIGH)
            const ntSecDesc = template.attributes.find(a => a.type === 'nTSecurityDescriptor')?.values[0];
            if (ntSecDesc) {
              const sdBuffer = Buffer.isBuffer(ntSecDesc) ? ntSecDesc : Buffer.from(ntSecDesc);
              const aclData = parseSecurityDescriptor(sdBuffer);

              if (aclData.aces) {
                for (const ace of aclData.aces) {
                  // Check for weak permissions (not built-in admins)
                  if ((ace.permissions.genericAll || ace.permissions.writeDACL || ace.permissions.writeOwner) &&
                      !ace.sid.includes('S-1-5-32-544') && // Not BUILTIN\Administrators
                      (ace.isEveryone || ace.isAuthenticatedUsers || ace.sid.includes('S-1-5-11'))) {
                    findings.high.push({
                      type: 'ESC4_VULNERABLE_TEMPLATE_ACL',
                      templateName: displayName,
                      templateCN: cn,
                      dn: template.objectName,
                      trusteeSid: ace.sid,
                      trusteeType: ace.isEveryone ? 'Everyone' : 'Authenticated Users',
                      message: `Certificate template "${displayName}" has weak ACL (ESC4) - ${ace.isEveryone ? 'Everyone' : 'Authenticated Users'} can modify template`
                    });
                    break; // One finding per template is enough
                  }
                }
              }
            }
          }
        } catch (e) {
          // ADCS templates not found (ADCS may not be deployed)
        }

        // ADCS Certificate Authorities Analysis
        try {
          const certAuthorities = await searchMany(
            '(objectClass=pKIEnrollmentService)',
            ['cn', 'dNSHostName', 'certificateTemplates', 'flags', 'msPKI-Enrollment-Servers'],
            50,
            configurationNC
          );

          for (const ca of certAuthorities) {
            const caName = ca.attributes.find(a => a.type === 'cn')?.values[0] || 'Unknown CA';
            const dnsHostName = ca.attributes.find(a => a.type === 'dNSHostName')?.values[0];
            const flags = ca.attributes.find(a => a.type === 'flags')?.values[0];

            // ESC6_EDITF_ATTRIBUTESUBJECTALTNAME2 (082 - HIGH)
            const EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000;
            if (flags && (flags & EDITF_ATTRIBUTESUBJECTALTNAME2)) {
              findings.high.push({
                type: 'ESC6_EDITF_ATTRIBUTESUBJECTALTNAME2',
                caName: caName,
                dnsHostName: dnsHostName,
                dn: ca.objectName,
                message: `CA "${caName}" has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled (ESC6) - Allows arbitrary SAN in certificate requests`
              });
            }

            // ESC8_HTTP_ENROLLMENT (083 - MEDIUM)
            const enrollServers = ca.attributes.find(a => a.type === 'msPKI-Enrollment-Servers')?.values || [];
            for (const server of enrollServers) {
              if (server.toLowerCase().includes('http://') && !server.toLowerCase().includes('https://')) {
                findings.medium.push({
                  type: 'ESC8_HTTP_ENROLLMENT',
                  caName: caName,
                  enrollmentUrl: server,
                  dn: ca.objectName,
                  message: `CA "${caName}" has HTTP (non-HTTPS) enrollment endpoint (ESC8) - NTLM relay vulnerability`
                });
              }
            }
          }
        } catch (e) {
          // CAs not found
        }
      }

      // LAPS (Local Admin Password Solution) Analysis
      try {
        // LAPS_NOT_DEPLOYED (084 - MEDIUM)
        const computersWithoutLAPS = await searchMany(
          '(&(objectClass=computer)(!(ms-Mcs-AdmPwd=*)(!(msLAPS-Password=*))))',
          ['cn', 'dNSHostName', 'operatingSystem'],
          100
        );

        if (computersWithoutLAPS.length > 0) {
          findings.medium.push({
            type: 'LAPS_NOT_DEPLOYED',
            count: computersWithoutLAPS.length,
            message: `${computersWithoutLAPS.length} computers without LAPS deployment - Local admin passwords may be static`,
            samples: computersWithoutLAPS.slice(0, 5).map(c => ({
              cn: c.attributes.find(a => a.type === 'cn')?.values[0],
              dnsHostName: c.attributes.find(a => a.type === 'dNSHostName')?.values[0]
            }))
          });
        }

        // LAPS_PASSWORD_READABLE (085 - HIGH)
        // Check if non-admin users can read LAPS password attributes
        const computersWithLAPS = await searchMany(
          '(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*))',
          ['cn', 'dNSHostName', 'ms-Mcs-AdmPwd', 'msLAPS-Password', 'nTSecurityDescriptor'],
          50
        );

        for (const computer of computersWithLAPS) {
          const cn = computer.attributes.find(a => a.type === 'cn')?.values[0] || 'Unknown';
          const ntSecDesc = computer.attributes.find(a => a.type === 'nTSecurityDescriptor')?.values[0];

          if (ntSecDesc) {
            const sdBuffer = Buffer.isBuffer(ntSecDesc) ? ntSecDesc : Buffer.from(ntSecDesc);
            const aclData = parseSecurityDescriptor(sdBuffer);

            if (aclData.aces) {
              for (const ace of aclData.aces) {
                // Check for read permissions on LAPS attributes by non-admins
                if ((ace.permissions.genericAll || ace.permissions.controlAccess || ace.permissions.writeProperty) &&
                    (ace.isEveryone || ace.isAuthenticatedUsers)) {
                  findings.high.push({
                    type: 'LAPS_PASSWORD_READABLE',
                    computerName: cn,
                    dn: computer.objectName,
                    trusteeSid: ace.sid,
                    trusteeType: ace.isEveryone ? 'Everyone' : 'Authenticated Users',
                    message: `LAPS password on "${cn}" readable by ${ace.isEveryone ? 'Everyone' : 'Authenticated Users'} - Weak ACL on computer object`
                  });
                  break;
                }
              }
            }
          }
        }

        // LAPS_LEGACY_ATTRIBUTE (086 - MEDIUM)
        const computersWithLegacyLAPS = await searchMany(
          '(&(ms-Mcs-AdmPwd=*)(!(msLAPS-Password=*)))',
          ['cn', 'dNSHostName', 'ms-Mcs-AdmPwd'],
          100
        );

        if (computersWithLegacyLAPS.length > 0) {
          findings.medium.push({
            type: 'LAPS_LEGACY_ATTRIBUTE',
            count: computersWithLegacyLAPS.length,
            message: `${computersWithLegacyLAPS.length} computers using legacy LAPS (ms-Mcs-AdmPwd) instead of Windows LAPS 2.0 (msLAPS-Password)`,
            samples: computersWithLegacyLAPS.slice(0, 5).map(c => ({
              cn: c.attributes.find(a => a.type === 'cn')?.values[0],
              dnsHostName: c.attributes.find(a => a.type === 'dNSHostName')?.values[0]
            }))
          });
        }

        // ADCS_WEAK_PERMISSIONS (087 - MEDIUM)
        if (configurationNC) {
          try {
            const pkiContainers = await searchMany(
              '(|(objectClass=pKIEnrollmentService)(objectClass=certificationAuthority))',
              ['cn', 'nTSecurityDescriptor'],
              50,
              configurationNC
            );

            for (const pkiObj of pkiContainers) {
              const cn = pkiObj.attributes.find(a => a.type === 'cn')?.values[0] || 'Unknown';
              const ntSecDesc = pkiObj.attributes.find(a => a.type === 'nTSecurityDescriptor')?.values[0];

              if (ntSecDesc) {
                const sdBuffer = Buffer.isBuffer(ntSecDesc) ? ntSecDesc : Buffer.from(ntSecDesc);
                const aclData = parseSecurityDescriptor(sdBuffer);

                if (aclData.aces) {
                  for (const ace of aclData.aces) {
                    if ((ace.permissions.genericAll || ace.permissions.writeDACL) &&
                        (ace.isEveryone || ace.isAuthenticatedUsers)) {
                      findings.medium.push({
                        type: 'ADCS_WEAK_PERMISSIONS',
                        objectName: cn,
                        dn: pkiObj.objectName,
                        trusteeSid: ace.sid,
                        trusteeType: ace.isEveryone ? 'Everyone' : 'Authenticated Users',
                        message: `PKI object "${cn}" has weak permissions - ${ace.isEveryone ? 'Everyone' : 'Authenticated Users'} can modify CA/enrollment service`
                      });
                      break;
                    }
                  }
                }
              }
            }
          } catch (e) {
            // PKI containers not found
          }
        }

      } catch (e) {
        // LAPS analysis failed
      }

      trackStep('STEP_13f_PHASE4', 'Phase 4 security checks (ADCS/PKI + LAPS)', { count: 10 });
    } catch (e) {
      // Phase 4 checks failed
    }
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
      protectedUsers: [],
      preWindows2000Access: []
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

        // Add findings for group memberships
        for (const memberDn of members) {
          if (key === 'backupOperators') {
            findings.high.push({ type: 'BACKUP_OPERATORS_MEMBER', dn: memberDn });
          } else if (key === 'accountOperators') {
            findings.high.push({ type: 'ACCOUNT_OPERATORS_MEMBER', dn: memberDn });
          } else if (key === 'serverOperators') {
            findings.high.push({ type: 'SERVER_OPERATORS_MEMBER', dn: memberDn });
          } else if (key === 'printOperators') {
            findings.high.push({ type: 'PRINT_OPERATORS_MEMBER', dn: memberDn });
          } else if (key === 'schemaAdmins') {
            findings.medium.push({ type: 'SCHEMA_ADMINS_MEMBER', dn: memberDn });
          } else if (key === 'enterpriseAdmins') {
            findings.medium.push({ type: 'ENTERPRISE_ADMINS_MEMBER', dn: memberDn });
          } else if (key === 'domainAdmins') {
            findings.medium.push({ type: 'DOMAIN_ADMINS_MEMBER', dn: memberDn });
          } else if (key === 'administrators') {
            findings.medium.push({ type: 'ADMINISTRATORS_MEMBER', dn: memberDn });
          }
        }

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

    // STEP 06b: Golden Ticket Risk Assessment
    try {
      const krbtgtUser = await searchOne('(sAMAccountName=krbtgt)');
      if (krbtgtUser) {
        const pwdLastSet = fileTimeToDate(krbtgtUser.attributes.find(a => a.type === 'pwdLastSet')?.values[0]);
        if (pwdLastSet) {
          const pwdAge = Math.floor((now - pwdLastSet.getTime()) / (24 * 60 * 60 * 1000));
          const goldenTicketThreshold = 180; // 180 days

          if (pwdAge > goldenTicketThreshold) {
            findings.critical.push({
              type: 'GOLDEN_TICKET_RISK',
              dn: krbtgtUser.objectName,
              samAccountName: 'krbtgt',
              passwordAge: pwdAge,
              threshold: goldenTicketThreshold,
              message: `krbtgt password is ${pwdAge} days old (threshold: ${goldenTicketThreshold} days)`
            });
          }
        }
      }
      trackStep('STEP_06b_GOLDEN_TICKET', 'Golden Ticket risk assessment', { count: 1 });
    } catch (e) {
      // krbtgt account not found (unlikely but possible in test environments)
    }
    stepStart = Date.now();

    // STEP 07: Service Accounts Detection
    const serviceAccounts = {
      detectedBySPN: [],
      detectedByName: [],
      detectedByDescription: []
    };

    const servicePatterns = /^(svc|service|sql|apache|nginx|iis|app|api|bot)/i;
    const descPatterns = /(service|application|automated|api|bot)/i;

    const spnMap = new Map(); // Map to track SPN -> [users]

    for (const user of allUsers) {
      const sam = user.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || '';
      const desc = user.attributes.find(a => a.type === 'description')?.values[0] || '';
      const spn = user.attributes.find(a => a.type === 'servicePrincipalName')?.values || [];
      const dn = user.objectName;

      if (spn.length > 0) {
        serviceAccounts.detectedBySPN.push({ ...getUserDetails(user), spnCount: spn.length });

        // Track SPNs for duplicate detection (Phase 2)
        for (const spnValue of spn) {
          if (!spnMap.has(spnValue)) {
            spnMap.set(spnValue, []);
          }
          spnMap.get(spnValue).push({ sam, dn });
        }
      } else if (servicePatterns.test(sam)) {
        serviceAccounts.detectedByName.push(getUserDetails(user));
      } else if (descPatterns.test(desc)) {
        serviceAccounts.detectedByDescription.push({ ...getUserDetails(user), description: desc });
      }
    }

    // Detect duplicate SPNs (Phase 2)
    for (const [spnValue, users] of spnMap.entries()) {
      if (users.length > 1) {
        findings.low.push({
          type: 'DUPLICATE_SPN',
          spn: spnValue,
          accountCount: users.length,
          accounts: users.map(u => u.sam).join(', '),
          message: `SPN "${spnValue}" is registered on ${users.length} accounts`
        });
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
      // Weak Kerberos encryption detection
      // msDS-SupportedEncryptionTypes flags:
      // 0x1 = DES_CBC_CRC, 0x2 = DES_CBC_MD5, 0x4 = RC4_HMAC_MD5
      // 0x8 = AES128_CTS_HMAC_SHA1_96, 0x10 = AES256_CTS_HMAC_SHA1_96
      const uac = parseInt(user.attributes.find(a => a.type === 'userAccountControl')?.values[0] || '0');
      const supportedEncTypes = user.attributes.find(a => a.type === 'msDS-SupportedEncryptionTypes')?.values[0];

      if (supportedEncTypes) {
        const encTypes = parseInt(supportedEncTypes);
        const hasDES = encTypes & 0x3;    // DES_CBC_CRC or DES_CBC_MD5
        const hasRC4 = encTypes & 0x4;    // RC4_HMAC_MD5
        const hasAES = encTypes & 0x18;   // AES128 or AES256

        // Critical: DES enabled (extremely weak, crackable in hours)
        if (hasDES) {
          const encList = [];
          if (encTypes & 0x1) encList.push('DES-CBC-CRC');
          if (encTypes & 0x2) encList.push('DES-CBC-MD5');
          advancedSecurity.weakEncryption.push({ ...getUserDetails(user), reason: `DES enabled: ${encList.join(', ')}`, severity: 'critical' });
          findings.critical.push({ type: 'WEAK_ENCRYPTION_DES', ...getUserDetails(user), algorithms: encList.join(', ') });
        }
        // High: RC4-only or no AES (RC4 has known weaknesses)
        else if (hasRC4 && !hasAES) {
          advancedSecurity.weakEncryption.push({ ...getUserDetails(user), reason: 'RC4-only (no AES)', severity: 'high' });
          findings.high.push({ type: 'WEAK_ENCRYPTION_RC4', ...getUserDetails(user), algorithms: 'RC4-HMAC-MD5' });
        }
        // Medium: RC4 enabled alongside AES (not ideal but less critical)
        else if (hasRC4 && hasAES) {
          advancedSecurity.weakEncryption.push({ ...getUserDetails(user), reason: 'RC4 enabled (AES available)', severity: 'medium' });
          findings.medium.push({ type: 'WEAK_ENCRYPTION_RC4_WITH_AES', ...getUserDetails(user), algorithms: 'RC4-HMAC-MD5' });
        }
      }
      // Use DES keys flag in UAC
      if (uac & 0x200000) {
        advancedSecurity.weakEncryption.push({ ...getUserDetails(user), reason: 'USE_DES_KEY_ONLY flag set', severity: 'high' });
        findings.high.push({ type: 'WEAK_ENCRYPTION_FLAG', ...getUserDetails(user) });
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

    // Check for privileged accounts without smartcard required
    for (const account of highPrivilegeAccounts) {
      // Find the user object to check UAC
      const user = allUsers.find(u => u.objectName === account.dn);
      if (user) {
        const uac = parseInt(user.attributes.find(a => a.type === 'userAccountControl')?.values[0] || '0');
        const smartcardRequired = uac & 0x40000; // SMARTCARD_REQUIRED flag
        if (!smartcardRequired) {
          findings.low.push({ type: 'SMARTCARD_NOT_REQUIRED', dn: account.dn });
        }
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

    // Check for expired accounts in admin groups (Phase 2)
    const allAdminDns = [
      ...privilegedAccounts.domainAdmins.map(a => a.dn),
      ...privilegedAccounts.enterpriseAdmins.map(a => a.dn),
      ...privilegedAccounts.schemaAdmins.map(a => a.dn),
      ...privilegedAccounts.administrators.map(a => a.dn)
    ];

    for (const user of allUsers) {
      const dn = user.objectName;
      if (allAdminDns.includes(dn)) {
        const uac = parseInt(user.attributes.find(a => a.type === 'userAccountControl')?.values[0] || '0');
        const accountExpires = user.attributes.find(a => a.type === 'accountExpires')?.values[0];

        // Expired account in admin group
        if (accountExpires && accountExpires !== '0' && accountExpires !== '9223372036854775807') {
          const expiryDate = fileTimeToDate(accountExpires);
          if (expiryDate && expiryDate.getTime() < now) {
            findings.medium.push({ type: 'EXPIRED_ACCOUNT_IN_ADMIN_GROUP', ...getUserDetails(user), expiryDate: formatDate(expiryDate) });
          }
        }

        // Disabled account in admin group
        if (uac & 0x2) {
          findings.medium.push({ type: 'DISABLED_ACCOUNT_IN_ADMIN_GROUP', ...getUserDetails(user) });
        }
      }

      // PrimaryGroupID spoofing (primaryGroupID=512 but not in DA memberOf)
      const primaryGroupID = user.attributes.find(a => a.type === 'primaryGroupID')?.values[0];
      if (primaryGroupID === '512') { // 512 = Domain Admins RID
        const memberOf = user.attributes.find(a => a.type === 'memberOf')?.values || [];
        const isDomainAdminMember = memberOf.some(dn => dn.includes('CN=Domain Admins,'));
        if (!isDomainAdminMember) {
          findings.medium.push({ type: 'PRIMARYGROUPID_SPOOFING', ...getUserDetails(user), primaryGroupID: '512' });
        }
      }
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

    // STEP 13b: Domain Configuration Security Checks (Phase 2)
    try {
      // Get domain object
      const domainObj = await searchOne('(objectClass=domain)');
      if (domainObj) {
        // Check Machine Account Quota (HIGH risk if > 0, allows any user to join computers)
        const machineAccountQuota = domainObj.attributes.find(a => a.type === 'ms-DS-MachineAccountQuota')?.values[0];
        if (machineAccountQuota && parseInt(machineAccountQuota) > 0) {
          findings.high.push({
            type: 'MACHINE_ACCOUNT_QUOTA_ABUSE',
            quota: parseInt(machineAccountQuota),
            message: `Machine Account Quota is ${machineAccountQuota} (allows users to join computers to domain)`
          });
        }

        // Check Kerberos Policy (LOW risk if MaxTicketAge > 10 hours)
        const maxTicketAge = domainObj.attributes.find(a => a.type === 'maxTicketAge')?.values[0];
        if (maxTicketAge) {
          const maxTicketAgeHours = parseInt(maxTicketAge) / 10000000 / 3600; // Convert to hours
          if (maxTicketAgeHours > 10) {
            findings.low.push({
              type: 'WEAK_KERBEROS_POLICY',
              maxTicketAge: Math.floor(maxTicketAgeHours),
              threshold: 10,
              message: `MaxTicketAge is ${Math.floor(maxTicketAgeHours)} hours (threshold: 10 hours)`
            });
          }
        }

        // Check Password Policy (MEDIUM risk if weak settings)
        const minPwdLength = domainObj.attributes.find(a => a.type === 'minPwdLength')?.values[0];
        const pwdHistoryLength = domainObj.attributes.find(a => a.type === 'pwdHistoryLength')?.values[0];
        const minPwdAge = domainObj.attributes.find(a => a.type === 'minPwdAge')?.values[0];

        const weakPolicyIssues = [];
        if (minPwdLength && parseInt(minPwdLength) < 14) {
          weakPolicyIssues.push(`MinPasswordLength=${minPwdLength} (recommended: 14+)`);
        }
        if (pwdHistoryLength && parseInt(pwdHistoryLength) < 24) {
          weakPolicyIssues.push(`PasswordHistoryLength=${pwdHistoryLength} (recommended: 24+)`);
        }
        if (minPwdAge) {
          const minPwdAgeDays = Math.abs(parseInt(minPwdAge)) / 10000000 / 86400;
          if (minPwdAgeDays < 1) {
            weakPolicyIssues.push(`MinPasswordAge=${Math.floor(minPwdAgeDays)} days (recommended: 1+)`);
          }
        }

        if (weakPolicyIssues.length > 0) {
          findings.medium.push({
            type: 'WEAK_PASSWORD_POLICY',
            issues: weakPolicyIssues.join(', '),
            minPwdLength: parseInt(minPwdLength || 0),
            pwdHistoryLength: parseInt(pwdHistoryLength || 0)
          });
        }
      }
      trackStep('STEP_13b_DOMAIN_CONFIG', 'Domain configuration security checks', { count: 1 });
    } catch (e) {
      // Domain object query failed
    }
    stepStart = Date.now();

    // STEP 13c: Computer Unconstrained Delegation Check (Phase 2)
    try {
      const computersWithDelegation = await searchMany('(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))', ['sAMAccountName', 'dNSHostName'], 100);
      for (const computer of computersWithDelegation) {
        const sam = computer.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || 'Unknown';
        const dnsHostName = computer.attributes.find(a => a.type === 'dNSHostName')?.values[0] || sam;
        findings.high.push({
          type: 'COMPUTER_UNCONSTRAINED_DELEGATION',
          samAccountName: sam,
          dnsHostName: dnsHostName,
          dn: computer.objectName,
          message: 'Computer has unconstrained delegation (vulnerable to PrinterBug/PetitPotam attacks)'
        });
      }
      trackStep('STEP_13c_COMPUTER_DELEGATION', 'Computer delegation security check', { count: computersWithDelegation.length });
    } catch (e) {
      // Computer query failed
    }
    stepStart = Date.now();

    // STEP 13d: Phase 3+4 Advanced Security Checks
    try {
      // FOREIGN_SECURITY_PRINCIPALS (051 - MEDIUM) - Check for external forest principals in sensitive groups
      try {
        const foreignPrincipals = await searchMany('(objectClass=foreignSecurityPrincipal)', ['*'], 100);
        for (const fsp of foreignPrincipals) {
          const memberOf = fsp.attributes.find(a => a.type === 'memberOf')?.values || [];
          const sensitiveGroups = memberOf.filter(dn =>
            dn.includes('Domain Admins') || dn.includes('Enterprise Admins') ||
            dn.includes('Schema Admins') || dn.includes('Administrators')
          );
          if (sensitiveGroups.length > 0) {
            findings.medium.push({
              type: 'FOREIGN_SECURITY_PRINCIPALS',
              dn: fsp.objectName,
              groups: sensitiveGroups.join('; '),
              message: 'External forest principal in sensitive group'
            });
          }
        }
      } catch (e) {}

      // NTLM_RELAY_OPPORTUNITY (065 - LOW) - Informational: NTLM relay risk exists
      findings.low.push({
        type: 'NTLM_RELAY_OPPORTUNITY',
        message: 'NTLM authentication enabled (relay attacks possible if SMB signing not enforced)',
        recommendation: 'Enable SMB signing and disable NTLM where possible'
      });

      trackStep('STEP_13d_ADVANCED_CHECKS', 'Advanced security checks (Phase 2 partiel)', { count: 2 });
    } catch (e) {
      // Advanced checks failed
    }
    stepStart = Date.now();

    // ==========================================
    // STEP 13e: PHASE 3 - ACL & Advanced Checks
    // ==========================================
    try {
      // SHADOW_CREDENTIALS (066 - CRITICAL) - msDS-KeyCredentialLink abuse
      try {
        const shadowCredsAccounts = await searchMany(
          '(msDS-KeyCredentialLink=*)',
          ['sAMAccountName', 'msDS-KeyCredentialLink', 'userAccountControl'],
          200
        );

        for (const account of shadowCredsAccounts) {
          const sam = account.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || 'Unknown';
          const keyCredLink = account.attributes.find(a => a.type === 'msDS-KeyCredentialLink')?.values || [];

          if (keyCredLink.length > 0) {
            findings.critical.push({
              type: 'SHADOW_CREDENTIALS',
              samAccountName: sam,
              dn: account.objectName,
              keyCount: keyCredLink.length,
              message: 'Shadow Credentials configured (msDS-KeyCredentialLink) - Kerberos authentication bypass risk'
            });
          }
        }
      } catch (e) {}

      // RBCD_ABUSE (067 - CRITICAL) - Resource-Based Constrained Delegation abuse
      try {
        const rbcdAccounts = await searchMany(
          '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)',
          ['sAMAccountName', 'dNSHostName', 'msDS-AllowedToActOnBehalfOfOtherIdentity'],
          200
        );

        for (const account of rbcdAccounts) {
          const sam = account.attributes.find(a => a.type === 'sAMAccountName')?.values[0] || 'Unknown';
          const dnsHostName = account.attributes.find(a => a.type === 'dNSHostName')?.values[0] || sam;

          findings.critical.push({
            type: 'RBCD_ABUSE',
            samAccountName: sam,
            dnsHostName: dnsHostName,
            dn: account.objectName,
            message: 'Resource-Based Constrained Delegation configured - Potential privilege escalation'
          });
        }
      } catch (e) {}

      // DANGEROUS_GROUP_NESTING (068 - MEDIUM) - Nested groups leading to unintended privilege escalation
      try {
        const nestedGroupIssues = [];
        const sensitiveGroupNames = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators'];

        for (const [groupName, members] of Object.entries(privilegedAccounts)) {
          if (['domainAdmins', 'enterpriseAdmins', 'schemaAdmins', 'administrators'].includes(groupName)) {
            // Check if any members are groups themselves
            for (const member of members) {
              const memberDn = member.dn || member;

              // If it's a group (contains "CN=...") and not a user
              if (memberDn.startsWith('CN=') && !memberDn.includes('CN=Users,')) {
                // Check if this is a nested group
                const isNestedGroup = allUsers.some(u => u.objectName === memberDn &&
                  u.attributes.find(a => a.type === 'objectClass')?.values.includes('group'));

                if (isNestedGroup) {
                  findings.medium.push({
                    type: 'DANGEROUS_GROUP_NESTING',
                    parentGroup: groupName,
                    nestedGroup: memberDn,
                    message: `Nested group in ${groupName} - May grant unintended privileges`
                  });
                }
              }
            }
          }
        }
      } catch (e) {}

      // ADMINSDHOLDER_BACKDOOR (069 - MEDIUM) - AdminSDHolder modifications for persistence
      try {
        const adminSDHolder = await searchOne('(cn=AdminSDHolder)');
        if (adminSDHolder) {
          const whenChanged = adminSDHolder.attributes.find(a => a.type === 'whenChanged')?.values[0];
          const whenCreated = adminSDHolder.attributes.find(a => a.type === 'whenCreated')?.values[0];

          // If AdminSDHolder was modified recently (within last 90 days), flag it
          if (whenChanged && whenCreated) {
            const changedDate = new Date(whenChanged);
            const createdDate = new Date(whenCreated);
            const daysSinceChange = Math.floor((now - changedDate.getTime()) / (24 * 60 * 60 * 1000));
            const daysSinceCreation = Math.floor((now - createdDate.getTime()) / (24 * 60 * 60 * 1000));

            // If changed after creation and within last 90 days, might be backdoor
            if (daysSinceChange < 90 && daysSinceChange < daysSinceCreation) {
              findings.medium.push({
                type: 'ADMINSDHOLDER_BACKDOOR',
                dn: adminSDHolder.objectName,
                whenChanged: whenChanged,
                daysSinceChange: daysSinceChange,
                message: 'AdminSDHolder modified recently - Potential ACL backdoor for persistence'
              });
            }
          }
        }
      } catch (e) {}

      // ACL-Based Detections - Analyze nTSecurityDescriptor for dangerous permissions
      try {
        // Get sensitive objects to check ACLs on (Domain root, AdminSDHolder, Domain Admins group, etc.)
        const sensitiveObjects = [];

        // Add domain root
        try {
          const domainRoot = await searchOne('(objectClass=domain)');
          if (domainRoot) sensitiveObjects.push({ obj: domainRoot, type: 'Domain Root' });
        } catch (e) {}

        // Add AdminSDHolder
        try {
          const adminSDHolder = await searchOne('(cn=AdminSDHolder)');
          if (adminSDHolder) sensitiveObjects.push({ obj: adminSDHolder, type: 'AdminSDHolder' });
        } catch (e) {}

        // Add Domain Admins group
        try {
          const domainAdminsGroup = await searchOne('(cn=Domain Admins)');
          if (domainAdminsGroup) sensitiveObjects.push({ obj: domainAdminsGroup, type: 'Domain Admins Group' });
        } catch (e) {}

        // Add Enterprise Admins group
        try {
          const enterpriseAdminsGroup = await searchOne('(cn=Enterprise Admins)');
          if (enterpriseAdminsGroup) sensitiveObjects.push({ obj: enterpriseAdminsGroup, type: 'Enterprise Admins Group' });
        } catch (e) {}

        // Analyze ACLs on sensitive objects
        for (const { obj, type } of sensitiveObjects) {
          try {
            const ntSecDesc = obj.attributes.find(a => a.type === 'nTSecurityDescriptor')?.values[0];
            if (!ntSecDesc) continue;

            // Convert to Buffer if needed
            const sdBuffer = Buffer.isBuffer(ntSecDesc) ? ntSecDesc : Buffer.from(ntSecDesc);
            const aclData = parseSecurityDescriptor(sdBuffer);

            if (aclData.error || !aclData.aces || aclData.aces.length === 0) continue;

            // Check each ACE for dangerous permissions
            for (const ace of aclData.aces) {
              const targetDn = obj.objectName;

              // ACL_GENERICALL (070 - HIGH) - GenericAll on sensitive objects
              if (ace.permissions.genericAll && !ace.sid.includes('S-1-5-32-544')) { // Exclude BUILTIN\Administrators
                findings.high.push({
                  type: 'ACL_GENERICALL',
                  targetObject: type,
                  targetDn: targetDn,
                  trusteeSid: ace.sid,
                  message: `GenericAll permission on ${type} - Full control abuse risk`
                });
              }

              // ACL_WRITEDACL (071 - HIGH) - WriteDACL on sensitive objects
              if (ace.permissions.writeDACL && !ace.sid.includes('S-1-5-32-544')) {
                findings.high.push({
                  type: 'ACL_WRITEDACL',
                  targetObject: type,
                  targetDn: targetDn,
                  trusteeSid: ace.sid,
                  message: `WriteDACL permission on ${type} - ACL modification risk`
                });
              }

              // ACL_WRITEOWNER (072 - HIGH) - WriteOwner on sensitive objects
              if (ace.permissions.writeOwner && !ace.sid.includes('S-1-5-32-544')) {
                findings.high.push({
                  type: 'ACL_WRITEOWNER',
                  targetObject: type,
                  targetDn: targetDn,
                  trusteeSid: ace.sid,
                  message: `WriteOwner permission on ${type} - Ownership takeover risk`
                });
              }

              // EVERYONE_IN_ACL (073 - MEDIUM) - Everyone/Authenticated Users with dangerous permissions
              if ((ace.isEveryone || ace.isAuthenticatedUsers) &&
                  (ace.permissions.genericAll || ace.permissions.genericWrite ||
                   ace.permissions.writeDACL || ace.permissions.writeOwner)) {
                findings.medium.push({
                  type: 'EVERYONE_IN_ACL',
                  targetObject: type,
                  targetDn: targetDn,
                  trusteeSid: ace.sid,
                  trusteeType: ace.isEveryone ? 'Everyone' : 'Authenticated Users',
                  permissions: Object.keys(ace.permissions).filter(k => ace.permissions[k]).join(', '),
                  message: `${ace.isEveryone ? 'Everyone' : 'Authenticated Users'} has dangerous permissions on ${type}`
                });
              }

              // ACL_GENERICWRITE (074 - MEDIUM) - GenericWrite on sensitive objects
              if (ace.permissions.genericWrite && !ace.sid.includes('S-1-5-32-544')) {
                findings.medium.push({
                  type: 'ACL_GENERICWRITE',
                  targetObject: type,
                  targetDn: targetDn,
                  trusteeSid: ace.sid,
                  message: `GenericWrite permission on ${type} - Attribute modification risk`
                });
              }

              // ACL_FORCECHANGEPASSWORD (075 - MEDIUM) - ControlAccess (ExtendedRight) for password reset
              if (ace.permissions.controlAccess && type.includes('Domain Admins')) {
                findings.medium.push({
                  type: 'ACL_FORCECHANGEPASSWORD',
                  targetObject: type,
                  targetDn: targetDn,
                  trusteeSid: ace.sid,
                  message: `Extended rights on ${type} - Potential password reset abuse`
                });
              }

              // WRITESPN_ABUSE (076 - MEDIUM) - WriteProperty for targeted Kerberoasting
              if (ace.permissions.writeProperty && type.includes('Domain')) {
                findings.medium.push({
                  type: 'WRITESPN_ABUSE',
                  targetObject: type,
                  targetDn: targetDn,
                  trusteeSid: ace.sid,
                  message: `WriteProperty permission on ${type} - WriteSPN for targeted Kerberoasting`
                });
              }
            }
          } catch (e) {
            // Failed to parse ACL for this object
          }
        }

        // GPO_LINK_POISONING (077 - MEDIUM) - Weak ACLs on GPO links
        try {
          const gpos = await searchMany('(objectClass=groupPolicyContainer)', ['displayName', 'nTSecurityDescriptor'], 50);

          for (const gpo of gpos) {
            const displayName = gpo.attributes.find(a => a.type === 'displayName')?.values[0] || 'Unknown GPO';
            const ntSecDesc = gpo.attributes.find(a => a.type === 'nTSecurityDescriptor')?.values[0];

            if (ntSecDesc) {
              const sdBuffer = Buffer.isBuffer(ntSecDesc) ? ntSecDesc : Buffer.from(ntSecDesc);
              const aclData = parseSecurityDescriptor(sdBuffer);

              if (aclData.aces) {
                for (const ace of aclData.aces) {
                  // Check if non-admin has write access to GPO
                  if ((ace.permissions.genericAll || ace.permissions.genericWrite || ace.permissions.writeDACL) &&
                      (ace.isEveryone || ace.isAuthenticatedUsers)) {
                    findings.medium.push({
                      type: 'GPO_LINK_POISONING',
                      gpoName: displayName,
                      gpoDn: gpo.objectName,
                      trusteeSid: ace.sid,
                      trusteeType: ace.isEveryone ? 'Everyone' : 'Authenticated Users',
                      message: `Weak ACL on GPO "${displayName}" - GPO modification risk`
                    });
                  }
                }
              }
            }
          }
        } catch (e) {}

      } catch (e) {
        // ACL analysis failed
      }

      trackStep('STEP_13e_PHASE3', 'Phase 3 security checks (ACL + Advanced)', { count: 12 });
    } catch (e) {
      // Phase 3 checks failed
    }
    stepStart = Date.now();

    // STEP 13f: PHASE 4 - ADCS/PKI + LAPS Security Checks
    try {
      // Get Configuration naming context for ADCS objects
      const configurationNC = domainRoot.attributes.find(a => a.type === 'configurationNamingContext')?.values[0];

      if (configurationNC) {
        // ADCS Certificate Templates Analysis
        try {
          const certTemplates = await searchMany(
            '(objectClass=pKICertificateTemplate)',
            ['cn', 'displayName', 'pKIExtendedKeyUsage', 'msPKI-Certificate-Name-Flag',
             'msPKI-Enrollment-Flag', 'nTSecurityDescriptor', 'msPKI-Certificate-Application-Policy'],
            100,
            configurationNC
          );

          for (const template of certTemplates) {
            const cn = template.attributes.find(a => a.type === 'cn')?.values[0] || 'Unknown';
            const displayName = template.attributes.find(a => a.type === 'displayName')?.values[0] || cn;
            const ekus = template.attributes.find(a => a.type === 'pKIExtendedKeyUsage')?.values || [];
            const appPolicies = template.attributes.find(a => a.type === 'msPKI-Certificate-Application-Policy')?.values || [];
            const nameFlags = template.attributes.find(a => a.type === 'msPKI-Certificate-Name-Flag')?.values[0];
            const enrollFlags = template.attributes.find(a => a.type === 'msPKI-Enrollment-Flag')?.values[0];

            // Combine EKUs and Application Policies
            const allEkus = [...ekus, ...appPolicies];

            // Client Authentication OID
            const CLIENT_AUTH_OID = '1.3.6.1.5.5.7.3.2';
            const ANY_PURPOSE_OID = '2.5.29.37.0';
            const ENROLLMENT_AGENT_OID = '1.3.6.1.4.1.311.20.2.1';

            const hasClientAuth = allEkus.includes(CLIENT_AUTH_OID);
            const hasAnyPurpose = allEkus.includes(ANY_PURPOSE_OID) || allEkus.length === 0;
            const hasEnrollmentAgent = allEkus.includes(ENROLLMENT_AGENT_OID);

            // Certificate name flags (bitwise)
            const ENROLLEE_SUPPLIES_SUBJECT = 0x00000001;
            const SUBJECT_ALT_REQUIRE_UPN = 0x01000000;
            const SUBJECT_ALT_REQUIRE_DNS = 0x08000000;

            const enrolleeSuppliesSubject = nameFlags && (nameFlags & ENROLLEE_SUPPLIES_SUBJECT);

            // ESC1_VULNERABLE_TEMPLATE (078 - CRITICAL)
            if (hasClientAuth && enrolleeSuppliesSubject) {
              findings.critical.push({
                type: 'ESC1_VULNERABLE_TEMPLATE',
                templateName: displayName,
                templateCN: cn,
                dn: template.objectName,
                message: `Certificate template "${displayName}" allows client authentication with enrollee-supplied subject (ESC1) - Domain takeover risk`,
                ekus: allEkus,
                nameFlags: nameFlags
              });
            }

            // ESC2_ANY_PURPOSE (079 - CRITICAL)
            if (hasAnyPurpose && !hasClientAuth) {
              findings.critical.push({
                type: 'ESC2_ANY_PURPOSE',
                templateName: displayName,
                templateCN: cn,
                dn: template.objectName,
                message: `Certificate template "${displayName}" allows Any Purpose EKU (ESC2) - Can be used for any authentication`,
                ekus: allEkus.length === 0 ? ['No EKU restrictions'] : allEkus
              });
            }

            // ESC3_ENROLLMENT_AGENT (080 - HIGH)
            if (hasEnrollmentAgent) {
              findings.high.push({
                type: 'ESC3_ENROLLMENT_AGENT',
                templateName: displayName,
                templateCN: cn,
                dn: template.objectName,
                message: `Certificate template "${displayName}" is an Enrollment Agent template (ESC3) - Can request certificates on behalf of others`,
                ekus: allEkus
              });
            }

            // ESC4_VULNERABLE_TEMPLATE_ACL (081 - HIGH)
            const ntSecDesc = template.attributes.find(a => a.type === 'nTSecurityDescriptor')?.values[0];
            if (ntSecDesc) {
              const sdBuffer = Buffer.isBuffer(ntSecDesc) ? ntSecDesc : Buffer.from(ntSecDesc);
              const aclData = parseSecurityDescriptor(sdBuffer);

              if (aclData.aces) {
                for (const ace of aclData.aces) {
                  // Check for weak permissions (not built-in admins)
                  if ((ace.permissions.genericAll || ace.permissions.writeDACL || ace.permissions.writeOwner) &&
                      !ace.sid.includes('S-1-5-32-544') && // Not BUILTIN\Administrators
                      (ace.isEveryone || ace.isAuthenticatedUsers || ace.sid.includes('S-1-5-11'))) {
                    findings.high.push({
                      type: 'ESC4_VULNERABLE_TEMPLATE_ACL',
                      templateName: displayName,
                      templateCN: cn,
                      dn: template.objectName,
                      trusteeSid: ace.sid,
                      trusteeType: ace.isEveryone ? 'Everyone' : 'Authenticated Users',
                      message: `Certificate template "${displayName}" has weak ACL (ESC4) - ${ace.isEveryone ? 'Everyone' : 'Authenticated Users'} can modify template`
                    });
                    break; // One finding per template is enough
                  }
                }
              }
            }
          }
        } catch (e) {
          // ADCS templates not found (ADCS may not be deployed)
        }

        // ADCS Certificate Authorities Analysis
        try {
          const certAuthorities = await searchMany(
            '(objectClass=pKIEnrollmentService)',
            ['cn', 'dNSHostName', 'certificateTemplates', 'flags', 'msPKI-Enrollment-Servers'],
            50,
            configurationNC
          );

          for (const ca of certAuthorities) {
            const caName = ca.attributes.find(a => a.type === 'cn')?.values[0] || 'Unknown CA';
            const dnsHostName = ca.attributes.find(a => a.type === 'dNSHostName')?.values[0];
            const flags = ca.attributes.find(a => a.type === 'flags')?.values[0];

            // ESC6_EDITF_ATTRIBUTESUBJECTALTNAME2 (082 - HIGH)
            const EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000;
            if (flags && (flags & EDITF_ATTRIBUTESUBJECTALTNAME2)) {
              findings.high.push({
                type: 'ESC6_EDITF_ATTRIBUTESUBJECTALTNAME2',
                caName: caName,
                dnsHostName: dnsHostName,
                dn: ca.objectName,
                message: `CA "${caName}" has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled (ESC6) - Allows arbitrary SAN in certificate requests`
              });
            }

            // ESC8_HTTP_ENROLLMENT (083 - MEDIUM)
            const enrollServers = ca.attributes.find(a => a.type === 'msPKI-Enrollment-Servers')?.values || [];
            for (const server of enrollServers) {
              if (server.toLowerCase().includes('http://') && !server.toLowerCase().includes('https://')) {
                findings.medium.push({
                  type: 'ESC8_HTTP_ENROLLMENT',
                  caName: caName,
                  enrollmentUrl: server,
                  dn: ca.objectName,
                  message: `CA "${caName}" has HTTP (non-HTTPS) enrollment endpoint (ESC8) - NTLM relay vulnerability`
                });
              }
            }
          }
        } catch (e) {
          // CAs not found
        }
      }

      // LAPS (Local Admin Password Solution) Analysis
      try {
        // LAPS_NOT_DEPLOYED (084 - MEDIUM)
        const computersWithoutLAPS = await searchMany(
          '(&(objectClass=computer)(!(ms-Mcs-AdmPwd=*)(!(msLAPS-Password=*))))',
          ['cn', 'dNSHostName', 'operatingSystem'],
          100
        );

        if (computersWithoutLAPS.length > 0) {
          findings.medium.push({
            type: 'LAPS_NOT_DEPLOYED',
            count: computersWithoutLAPS.length,
            message: `${computersWithoutLAPS.length} computers without LAPS deployment - Local admin passwords may be static`,
            samples: computersWithoutLAPS.slice(0, 5).map(c => ({
              cn: c.attributes.find(a => a.type === 'cn')?.values[0],
              dnsHostName: c.attributes.find(a => a.type === 'dNSHostName')?.values[0]
            }))
          });
        }

        // LAPS_PASSWORD_READABLE (085 - HIGH)
        // Check if non-admin users can read LAPS password attributes
        const computersWithLAPS = await searchMany(
          '(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*))',
          ['cn', 'dNSHostName', 'ms-Mcs-AdmPwd', 'msLAPS-Password', 'nTSecurityDescriptor'],
          50
        );

        for (const computer of computersWithLAPS) {
          const cn = computer.attributes.find(a => a.type === 'cn')?.values[0] || 'Unknown';
          const ntSecDesc = computer.attributes.find(a => a.type === 'nTSecurityDescriptor')?.values[0];

          if (ntSecDesc) {
            const sdBuffer = Buffer.isBuffer(ntSecDesc) ? ntSecDesc : Buffer.from(ntSecDesc);
            const aclData = parseSecurityDescriptor(sdBuffer);

            if (aclData.aces) {
              for (const ace of aclData.aces) {
                // Check for read permissions on LAPS attributes by non-admins
                if ((ace.permissions.genericAll || ace.permissions.controlAccess || ace.permissions.writeProperty) &&
                    (ace.isEveryone || ace.isAuthenticatedUsers)) {
                  findings.high.push({
                    type: 'LAPS_PASSWORD_READABLE',
                    computerName: cn,
                    dn: computer.objectName,
                    trusteeSid: ace.sid,
                    trusteeType: ace.isEveryone ? 'Everyone' : 'Authenticated Users',
                    message: `LAPS password on "${cn}" readable by ${ace.isEveryone ? 'Everyone' : 'Authenticated Users'} - Weak ACL on computer object`
                  });
                  break;
                }
              }
            }
          }
        }

        // LAPS_LEGACY_ATTRIBUTE (086 - MEDIUM)
        const computersWithLegacyLAPS = await searchMany(
          '(&(ms-Mcs-AdmPwd=*)(!(msLAPS-Password=*)))',
          ['cn', 'dNSHostName', 'ms-Mcs-AdmPwd'],
          100
        );

        if (computersWithLegacyLAPS.length > 0) {
          findings.medium.push({
            type: 'LAPS_LEGACY_ATTRIBUTE',
            count: computersWithLegacyLAPS.length,
            message: `${computersWithLegacyLAPS.length} computers using legacy LAPS (ms-Mcs-AdmPwd) instead of Windows LAPS 2.0 (msLAPS-Password)`,
            samples: computersWithLegacyLAPS.slice(0, 5).map(c => ({
              cn: c.attributes.find(a => a.type === 'cn')?.values[0],
              dnsHostName: c.attributes.find(a => a.type === 'dNSHostName')?.values[0]
            }))
          });
        }

        // ADCS_WEAK_PERMISSIONS (087 - MEDIUM)
        if (configurationNC) {
          try {
            const pkiContainers = await searchMany(
              '(|(objectClass=pKIEnrollmentService)(objectClass=certificationAuthority))',
              ['cn', 'nTSecurityDescriptor'],
              50,
              configurationNC
            );

            for (const pkiObj of pkiContainers) {
              const cn = pkiObj.attributes.find(a => a.type === 'cn')?.values[0] || 'Unknown';
              const ntSecDesc = pkiObj.attributes.find(a => a.type === 'nTSecurityDescriptor')?.values[0];

              if (ntSecDesc) {
                const sdBuffer = Buffer.isBuffer(ntSecDesc) ? ntSecDesc : Buffer.from(ntSecDesc);
                const aclData = parseSecurityDescriptor(sdBuffer);

                if (aclData.aces) {
                  for (const ace of aclData.aces) {
                    if ((ace.permissions.genericAll || ace.permissions.writeDACL) &&
                        (ace.isEveryone || ace.isAuthenticatedUsers)) {
                      findings.medium.push({
                        type: 'ADCS_WEAK_PERMISSIONS',
                        objectName: cn,
                        dn: pkiObj.objectName,
                        trusteeSid: ace.sid,
                        trusteeType: ace.isEveryone ? 'Everyone' : 'Authenticated Users',
                        message: `PKI object "${cn}" has weak permissions - ${ace.isEveryone ? 'Everyone' : 'Authenticated Users'} can modify CA/enrollment service`
                      });
                      break;
                    }
                  }
                }
              }
            }
          } catch (e) {
            // PKI containers not found
          }
        }

      } catch (e) {
        // LAPS analysis failed
      }

      trackStep('STEP_13f_PHASE4', 'Phase 4 security checks (ADCS/PKI + LAPS)', { count: 10 });
    } catch (e) {
      // Phase 4 checks failed
    }
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
    // Need actual delay for Node.js fetch to read the complete event
    // setImmediate is NOT enough for large payloads
    setTimeout(() => {
      res.end();
    }, 100);  // 100ms delay ensures buffer is flushed

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
