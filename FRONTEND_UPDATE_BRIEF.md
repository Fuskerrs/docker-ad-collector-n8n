# Frontend Update Brief - AD Collector Backend Changes

**Date:** December 8, 2025
**Backend Version:** v2.6.1
**Priority:** HIGH - Multiple missing features in frontend

---

## 🚨 Critical Updates Required

### 1. SSE Progress Steps: 58 → 74 Steps

**What Changed:**
- Previous implementation: **58 SSE audit steps**
- Current implementation: **74 SSE audit steps**
- Increase: **+16 steps** (mostly computer-specific detections)

**Step Breakdown:**
- **11 Process Steps:** Infrastructure/enumeration (STEP_01_INIT, STEP_02_USER_ENUM, STEP_09_SVC_SPN, etc.)
- **63 Detection Steps:** Actual vulnerability detection (some detect multiple vulnerabilities)

**Frontend Impact:**
- Progress bar must handle 74 steps instead of 58
- Update progress percentage calculation: `(currentStep / 74) * 100`
- Verify completion check: `step === 'STEP_58_COMPLETE'`

**Example SSE Event:**
```json
{
  "step": "STEP_32_1_COMP_CONSTR_DELEG",
  "description": "Computer constrained delegation check",
  "status": "completed",
  "count": 3,
  "duration": "0.52s",
  "findings": {
    "critical": 3,
    "high": 0,
    "medium": 0,
    "low": 0
  }
}
```

---

### 2. Vulnerability Count: 71 → 87 Vulnerabilities

**What Changed:**
- Previous count: **71 vulnerabilities**
- Current count: **87 vulnerabilities**
- Added: **+16 computer-specific vulnerabilities** (v2.5.0)

**New Vulnerability Distribution:**
- 🔴 **Critical:** 12 → **16** (+4 computer vulns)
- 🟠 **High:** 21 → **27** (+6 computer vulns)
- 🟡 **Medium:** 32 → **38** (+6 computer vulns - includes 1 from STEP_32_COMP_UNCONSTR counted in medium)
- 🔵 **Low:** 6 → **6** (unchanged - the 2 computer LOW vulns were already in the 6)

**Wait, let me recount from the documentation...**

Actually, checking the VULNERABILITIES.md:
- 🔴 **Critical:** 16 total (includes 4 new computer: #72-75)
- 🟠 **High:** 27 total (includes 6 new computer: #35-39)
- 🟡 **Medium:** 38 total (includes 5 new computer: #67-71)
- 🔵 **Low:** 6 total (includes 2 new computer: #72-73)

**New Computer-Specific Vulnerability Types:**

**CRITICAL (4):**
1. `COMPUTER_CONSTRAINED_DELEGATION` - STEP_32_1_COMP_CONSTR_DELEG
2. `COMPUTER_RBCD` - STEP_32_2_COMP_RBCD
3. `COMPUTER_IN_ADMIN_GROUP` - STEP_32_3_COMP_ADMIN_GROUP
4. `COMPUTER_DCSYNC_RIGHTS` - STEP_32_4_COMP_DCSYNC

**HIGH (6):**
5. `COMPUTER_STALE_INACTIVE` - STEP_32_5_COMP_STALE
6. `COMPUTER_PASSWORD_OLD` - STEP_32_6_COMP_PWD_OLD
7. `COMPUTER_WITH_SPNS` - STEP_32_7_COMP_SPNS
8. `COMPUTER_NO_LAPS` - STEP_32_8_COMP_NO_LAPS
9. `COMPUTER_ACL_ABUSE` - STEP_32_9_COMP_ACL_ABUSE
10. `COMPUTER_UNCONSTRAINED_DELEGATION` - STEP_32_COMP_UNCONSTR

**MEDIUM (5):**
11. `COMPUTER_DISABLED_NOT_DELETED` - STEP_32_10_COMP_DISABLED
12. `COMPUTER_WRONG_OU` - STEP_32_11_COMP_WRONG_OU
13. `COMPUTER_WEAK_ENCRYPTION` - STEP_32_12_COMP_WEAK_ENC
14. `COMPUTER_DESCRIPTION_SENSITIVE` - STEP_32_13_COMP_DESC_SENS
15. `COMPUTER_PRE_WINDOWS_2000` - STEP_32_14_COMP_PRE_W2K

**LOW (2):**
16. `COMPUTER_ADMIN_COUNT` - STEP_32_15_COMP_ADMIN_COUNT
17. `COMPUTER_SMB_SIGNING_DISABLED` - STEP_32_16_COMP_SMB_SIGN

**Frontend Requirements:**
- Add all 16 new vulnerability types to your type definitions
- Add computer icon (🖥️) vs user icon (👤) distinction
- Display computer-specific fields:
  - `dnsHostName` - Computer DNS name
  - `delegateTo` - Delegation targets (for constrained delegation)
  - `daysInactive` - Days since last logon
  - `daysOld` - Password age in days
  - `spns[]` - Service Principal Names
  - `operatingSystem` - OS version

---

### 3. Export/Import JSON (v2.6.0 & v2.6.1) ⚠️ **CRITICAL**

**Why This is Important:**
Many enterprises cannot expose the AD Collector API publicly or run live audits during business hours. The export/import feature allows:
- Export audit JSON to file (locally or via API)
- Transfer JSON to another machine
- Import JSON in frontend to view/analyze audit WITHOUT live API connection
- Generate reports from historical audit data

---

#### 3.1 Export Feature (Backend Implemented)

**Two Export Methods Available:**

**Method 1: API Export Endpoint** (v2.6.1)
```typescript
// Frontend calls this endpoint
POST /api/audit/export
Authorization: Bearer <TOKEN>
Content-Type: application/json

{
  "includeDetails": true,      // Include full vulnerability details
  "includeComputers": true,     // Include computer analysis
  "filename": "audit-2025-12-08.json",  // Custom filename
  "pretty": true                // Pretty-print JSON
}

// Response Headers
Content-Disposition: attachment; filename="audit-2025-12-08.json"
Content-Type: application/json
X-Audit-Duration: 45.23s
X-Audit-Security-Score: 72
X-Audit-Users: 1234
X-Audit-Computers: 567
X-Audit-Critical: 23
X-Audit-High: 45
X-Audit-Medium: 89
X-Audit-Low: 12

// Response Body: Full audit JSON (same format as /api/audit)
```

**Method 2: CLI Export** (v2.6.0)
```bash
# Users can run this directly on Docker container
docker exec ad-collector node export-audit.js --output /audits/export.json --include-details --include-computers
```

**Frontend Export Implementation Required:**
```typescript
async function handleExport() {
  const response = await fetch(`${collectorUrl}/api/audit/export`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      includeDetails: true,
      includeComputers: true,
      filename: `audit-${new Date().toISOString().split('T')[0]}.json`,
      pretty: true
    })
  });

  // Get filename from Content-Disposition header
  const contentDisposition = response.headers.get('Content-Disposition');
  const filename = contentDisposition?.match(/filename="(.+)"/)?.[1] || 'audit.json';

  // Download file
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(url);

  // Optional: Show metadata from headers
  const metadata = {
    duration: response.headers.get('X-Audit-Duration'),
    score: response.headers.get('X-Audit-Security-Score'),
    users: response.headers.get('X-Audit-Users'),
    computers: response.headers.get('X-Audit-Computers')
  };
  console.log('Export metadata:', metadata);
}
```

---

#### 3.2 Import Feature (Frontend MUST IMPLEMENT)

**Purpose:**
Allow users to **import a previously exported JSON** and view the audit results **WITHOUT connecting to the AD Collector API**.

**Use Cases:**
- View audit results offline (no API connection needed)
- Generate reports from historical audits
- Share audit results with security team (just send JSON file)
- Analyze audits from air-gapped environments

**Frontend Import Implementation Required:**
```typescript
function ImportButton({ onImportComplete }) {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      // Read file
      const text = await file.text();
      const auditData = JSON.parse(text);

      // Validate JSON structure
      if (!auditData.success || !auditData.audit) {
        throw new Error('Invalid audit file format');
      }

      // Verify version compatibility
      const version = auditData.audit.metadata.version;
      if (!version || parseFloat(version) < 2.5) {
        console.warn(`Old audit format detected: v${version}`);
      }

      // Pass imported data to parent component
      onImportComplete({
        ...auditData,
        isImported: true,  // Flag to show this is imported, not live
        importedAt: new Date().toISOString(),
        originalFilename: file.name
      });

    } catch (error) {
      alert(`Failed to import audit file: ${error.message}`);
    }
  };

  return (
    <>
      <input
        ref={fileInputRef}
        type="file"
        accept=".json"
        onChange={handleFileSelect}
        style={{ display: 'none' }}
      />
      <Button onClick={() => fileInputRef.current?.click()}>
        📥 Import Audit JSON
      </Button>
    </>
  );
}
```

**Display Imported Audit:**
```typescript
function AuditViewer({ auditData, isImported }) {
  return (
    <div>
      {isImported && (
        <Banner variant="info">
          📥 <strong>IMPORTED AUDIT</strong> - Viewing offline audit from {auditData.originalFilename}
          <br />
          Original audit date: {new Date(auditData.audit.metadata.timestamp).toLocaleString()}
        </Banner>
      )}

      {/* Display audit results normally */}
      <AuditSummary summary={auditData.audit.summary} />
      <VulnerabilityList findings={auditData.audit.findings} />
    </div>
  );
}
```

**Drag & Drop Support (Optional):**
```typescript
function ImportDropzone({ onImportComplete }) {
  const [isDragging, setIsDragging] = useState(false);

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    const file = e.dataTransfer.files[0];
    if (!file || !file.name.endsWith('.json')) {
      alert('Please drop a JSON file');
      return;
    }

    const text = await file.text();
    const auditData = JSON.parse(text);
    onImportComplete({ ...auditData, isImported: true });
  };

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      style={{
        border: isDragging ? '2px dashed blue' : '2px dashed gray',
        padding: '40px',
        textAlign: 'center'
      }}
    >
      📁 Drag & drop audit JSON file here
    </div>
  );
}
```

**JSON Structure to Expect:**
```json
{
  "success": true,
  "audit": {
    "metadata": {
      "timestamp": "2025-12-08T10:30:45.123Z",
      "duration": "45.23s",
      "includeDetails": true,
      "includeComputers": true,
      "version": "2.6.1"
    },
    "progress": [ /* 74 steps */ ],
    "summary": {
      "users": 1234,
      "groups": 89,
      "computers": 567,
      "vulnerabilities": {
        "critical": 23,
        "high": 45,
        "medium": 89,
        "low": 12,
        "total": 169,
        "score": 72
      }
    },
    "findings": {
      "critical": [ /* array of findings */ ],
      "high": [ /* array of findings */ ],
      "medium": [ /* array of findings */ ],
      "low": [ /* array of findings */ ]
    }
  }
}
```

---

#### 3.3 User Workflow Examples

**Workflow 1: Live Audit + Export**
1. User clicks "Run Audit" → Frontend calls `POST /api/audit/stream`
2. Progress bar shows 74/74 steps in real-time
3. When complete, user clicks "Export JSON" → Frontend calls `POST /api/audit/export`
4. JSON file downloads to user's machine
5. User can share this JSON with team or import later

**Workflow 2: Import Previous Audit**
1. User has JSON file from previous export
2. User clicks "Import Audit JSON" → Selects file
3. Frontend parses JSON and displays results
4. **No API connection needed** - all data is in the JSON
5. User can generate reports, view vulnerabilities, etc.

**Workflow 3: Air-Gapped Export**
1. Admin runs `docker exec ad-collector node export-audit.js` inside container
2. Copies JSON file to USB/shared drive
3. Transfers to analyst's machine
4. Analyst opens frontend and imports JSON
5. Views audit results without any network connection

---

## 📚 Detailed Documentation

**For complete vulnerability mappings and SSE step details, consult:**

🔗 **[VULNERABILITIES.md on GitHub](https://github.com/Fuskerrs/docker-ad-collector-n8n/blob/main/VULNERABILITIES.md)**

This table includes:
- All 87 vulnerabilities with descriptions
- SSE Step mapping for each vulnerability
- Severity levels
- Remediation guidance
- MITRE ATT&CK references

**For implementation examples and code samples:**

🔗 **[FRONTEND_CHANGELOG.md](https://github.com/Fuskerrs/docker-ad-collector-n8n/blob/main/FRONTEND_CHANGELOG.md)**

This guide includes:
- TypeScript interfaces for all new types
- React component examples
- SSE event handling updates
- Export/Import implementation code
- Migration checklist
- Testing scenarios

---

## 🎯 Implementation Priority

### Phase 1: Critical (Must Have)
1. ✅ Update progress bar: 58 → 74 steps
2. ✅ Add 16 new computer vulnerability types
3. ✅ Update severity counts (Critical: 16, High: 27, Medium: 38, Low: 6)

### Phase 2: Important (Should Have)
4. ⚠️ Add export button with `/api/audit/export` endpoint
5. ⚠️ Add import functionality for JSON files
6. ⚠️ Display computer-specific fields (dnsHostName, delegateTo, etc.)

### Phase 3: Enhancement (Nice to Have)
7. 💡 Parse metadata headers from export response
8. 💡 Add "IMPORTED AUDIT" visual indicator
9. 💡 Group computer vulns separately from user vulns

---

## ✅ Testing Checklist

- [ ] Progress bar reaches 100% (74/74 steps)
- [ ] All 16 computer vulnerability types display correctly
- [ ] Computer icon (🖥️) shows for computer findings
- [ ] Export button downloads JSON file
- [ ] Import button accepts and validates JSON
- [ ] Severity counts match: C:16, H:27, M:38, L:6
- [ ] Computer fields (dnsHostName, delegateTo) render properly
- [ ] Metadata headers display in export flow

---

## 🔄 API Compatibility

**Existing Endpoints (Unchanged):**
- ✅ `POST /api/audit` - Classic audit (still works)
- ✅ `POST /api/audit/stream` - SSE streaming (still works, now 74 steps)
- ✅ `POST /api/test-connection` - Connection test (still works)

**New Endpoint:**
- 🆕 `POST /api/audit/export` - Export as downloadable JSON (v2.6.1)

**Backward Compatibility:**
- All existing API calls work without changes
- Only progress step count changed (58 → 74)
- Audit response structure unchanged (only added fields)

---

## 📞 Questions?

If you need clarification on any of these changes:

1. Check [VULNERABILITIES.md](https://github.com/Fuskerrs/docker-ad-collector-n8n/blob/main/VULNERABILITIES.md) for vulnerability details
2. Check [FRONTEND_CHANGELOG.md](https://github.com/Fuskerrs/docker-ad-collector-n8n/blob/main/FRONTEND_CHANGELOG.md) for code examples
3. Check [API_GUIDE.md](https://github.com/Fuskerrs/docker-ad-collector-n8n/blob/main/API_GUIDE.md) for API documentation

**Backend Repository:** https://github.com/Fuskerrs/docker-ad-collector-n8n
**Current Version:** 2.6.1
**Last Updated:** December 8, 2025
