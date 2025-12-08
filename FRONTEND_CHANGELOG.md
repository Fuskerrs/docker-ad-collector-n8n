# Frontend Development Changelog - AD Collector v2.6.1

**Date:** December 8, 2025
**Target Audience:** Frontend developers working on n8n-nodes-ad-admin
**Current Backend Version:** 2.6.1

This document lists ALL backend changes that require frontend updates, including missing features from previous versions.

---

## 🚨 CRITICAL: Missing Features in Frontend

### 1. Computer Vulnerabilities (v2.5.0) ⚠️ **NOT IMPLEMENTED**

**Backend Status:** ✅ Implemented (16 new vulnerability types, 87 total)
**Frontend Status:** ❌ Missing

The backend now detects **16 new computer-specific vulnerabilities** but the frontend doesn't display them.

#### New Vulnerability Types to Add:

**CRITICAL (4):**
```typescript
type: 'COMPUTER_CONSTRAINED_DELEGATION'
type: 'COMPUTER_RBCD'
type: 'COMPUTER_IN_ADMIN_GROUP'
type: 'COMPUTER_DCSYNC_RIGHTS'
```

**HIGH (6):**
```typescript
type: 'COMPUTER_STALE_INACTIVE'
type: 'COMPUTER_PASSWORD_OLD'
type: 'COMPUTER_WITH_SPNS'
type: 'COMPUTER_NO_LAPS'
type: 'COMPUTER_ACL_ABUSE'
```

**MEDIUM (5):**
```typescript
type: 'COMPUTER_DISABLED_NOT_DELETED'
type: 'COMPUTER_WRONG_OU'
type: 'COMPUTER_WEAK_ENCRYPTION'
type: 'COMPUTER_DESCRIPTION_SENSITIVE'
type: 'COMPUTER_PRE_WINDOWS_2000'
```

**LOW (2):**
```typescript
type: 'COMPUTER_ADMIN_COUNT'
type: 'COMPUTER_SMB_SIGNING_DISABLED'
```

#### Finding Object Structure:

```typescript
interface ComputerVulnerability {
  type: string;
  samAccountName: string;      // Computer account name (e.g., "SERVER01$")
  dnsHostName?: string;         // DNS hostname (e.g., "server01.domain.com")
  dn: string;                   // Distinguished Name
  message: string;              // Human-readable description

  // Type-specific fields:
  delegateTo?: string;          // For COMPUTER_CONSTRAINED_DELEGATION
  daysInactive?: number;        // For COMPUTER_STALE_INACTIVE
  daysOld?: number;             // For COMPUTER_PASSWORD_OLD
  spns?: string[];              // For COMPUTER_WITH_SPNS
  operatingSystem?: string;     // For COMPUTER_PRE_WINDOWS_2000
}
```

#### Example Finding:

```json
{
  "type": "COMPUTER_CONSTRAINED_DELEGATION",
  "samAccountName": "SERVER01$",
  "dnsHostName": "server01.aza-me.cc",
  "delegateTo": "HTTP/webapp.aza-me.cc; CIFS/fileserver.aza-me.cc",
  "dn": "CN=SERVER01,OU=Servers,DC=aza-me,DC=cc",
  "message": "Computer has constrained delegation to 2 service(s)"
}
```

#### Frontend Requirements:

1. **Update Vulnerability Type Mapping**
   - Add all 16 new types to your vulnerability switch/case or mapping object
   - Add icons/colors for computer-specific vulnerabilities
   - Example: 🖥️ for computers vs 👤 for users

2. **Display Computer-Specific Fields**
   ```typescript
   // Example component
   function ComputerVulnerabilityCard({ finding }) {
     return (
       <Card severity={finding.type.severity}>
         <Icon>🖥️</Icon>
         <Title>{finding.type}</Title>
         <Field label="Computer">{finding.dnsHostName || finding.samAccountName}</Field>
         <Field label="DN">{finding.dn}</Field>
         {finding.delegateTo && (
           <Field label="Delegates To">{finding.delegateTo}</Field>
         )}
         {finding.daysInactive && (
           <Badge color="orange">{finding.daysInactive} days inactive</Badge>
         )}
         <Message>{finding.message}</Message>
       </Card>
     );
   }
   ```

3. **Update Statistics Display**
   ```typescript
   // Old: 71 vulnerabilities
   // New: 87 vulnerabilities
   const totalVulnerabilityTypes = 87; // Update this!

   // Update breakdown:
   const severityCounts = {
     critical: 16,  // was 12
     high: 27,      // was 22
     medium: 38,    // was 33
     low: 6         // was 4
   };
   ```

4. **Filter/Group by Object Type**
   ```typescript
   // Add computer filtering
   const filterOptions = [
     { label: 'All', value: 'all' },
     { label: 'Users', value: 'user' },
     { label: 'Groups', value: 'group' },
     { label: 'Computers', value: 'computer' }, // NEW
     { label: 'Domain', value: 'domain' },
     { label: 'ADCS', value: 'adcs' }
   ];

   function isComputerVuln(type: string) {
     return type.startsWith('COMPUTER_');
   }
   ```

---

### 2. SSE Progress Tracking (v2.2.0+) ⚠️ **PARTIALLY IMPLEMENTED**

**Backend Status:** ✅ 74 detailed audit steps (11 process + 63 detection)
**Frontend Status:** ⚠️ May be using old step format

#### New SSE Step Format:

The backend now sends **74 granular steps** instead of ~15. Update your SSE handling:

**Step Breakdown:**
- **11 Process Steps:** Infrastructure and enumeration (STEP_01_INIT, STEP_02_USER_ENUM, etc.)
- **63 Detection Steps:** Vulnerability detection steps (some detect multiple vulnerabilities)

**Old Steps (v1.x):**
```
STEP_01, STEP_02, ..., STEP_15
```

**New Steps (v2.2.0+):**
```
STEP_01_INIT                    // Process step
STEP_02_USER_ENUM               // Process step
STEP_03_PASSWORD_SEC            // Detection (4 vulnerabilities)
STEP_04_KERBEROS_SEC            // Detection (3 vulnerabilities)
STEP_09_SVC_SPN                 // Process step
STEP_10_SVC_NAME                // Process step
... (74 total steps)
STEP_32_1_COMP_CONSTR_DELEG     // Computer detection
STEP_32_2_COMP_RBCD             // Computer detection
... (16 computer steps)
STEP_57_RISK_SCORING            // Process step
STEP_58_COMPLETE                // Process step
```

#### Updated SSE Event Types:

```typescript
interface SSEProgressEvent {
  step: string;           // e.g., "STEP_32_1_COMP_CONSTR_DELEG"
  description: string;    // e.g., "Computer constrained delegation check"
  status: 'completed';
  count: number;          // Items processed
  duration: string;       // e.g., "0.52s"
  findings?: {            // Optional: vulnerability counts for this step
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}
```

#### Example SSE Stream:

```
event: progress
data: {"step":"STEP_01_CONNECT","description":"Connected to LDAP","status":"completed","count":1,"duration":"0.12s"}

event: progress
data: {"step":"STEP_02_USERS","description":"User enumeration","status":"completed","count":1234,"duration":"2.45s"}

event: progress
data: {"step":"STEP_32_1_COMP_CONSTR_DELEG","description":"Computer constrained delegation check","status":"completed","count":3,"duration":"0.52s","findings":{"critical":3,"high":0,"medium":0,"low":0}}

event: complete
data: {"success":true,"audit":{...}}
```

#### Frontend Requirements:

1. **Update Progress Bar**
   ```typescript
   const TOTAL_STEPS = 58; // was ~15

   function ProgressBar({ completedSteps }) {
     const progress = (completedSteps / TOTAL_STEPS) * 100;
     return <Progress value={progress} max={100} />;
   }
   ```

2. **Display Step Details**
   ```typescript
   function StepLog({ events }) {
     return (
       <div className="step-log">
         {events.map((event, idx) => (
           <StepItem key={idx}>
             <StepIcon status={event.status} />
             <StepName>{event.description}</StepName>
             <StepCount>{event.count} items</StepCount>
             <StepDuration>{event.duration}</StepDuration>
             {event.findings && (
               <StepFindings>
                 <Badge color="red">{event.findings.critical}</Badge>
                 <Badge color="orange">{event.findings.high}</Badge>
               </StepFindings>
             )}
           </StepItem>
         ))}
       </div>
     );
   }
   ```

3. **Handle New Step Names**
   ```typescript
   // Map step codes to human-readable phase names
   const stepPhases = {
     'STEP_01': 'Connection',
     'STEP_02': 'Enumeration',
     'STEP_03': 'Password Security',
     'STEP_04': 'Kerberos Security',
     // ... add all 74 steps
     'STEP_32_1': 'Computer Delegation (Critical)',
     'STEP_32_2': 'Computer RBCD (Critical)',
     // ... etc
     'STEP_58': 'Completion'
   };

   function getPhaseForStep(step: string): string {
     // Extract base step (e.g., "STEP_32_1" -> "STEP_32")
     const baseStep = step.split('_').slice(0, 2).join('_');
     return stepPhases[baseStep] || 'Processing';
   }
   ```

---

### 3. Export Feature (v2.6.0 & v2.6.1) ❌ **NOT IMPLEMENTED**

**Backend Status:** ✅ Two export methods available
**Frontend Status:** ❌ Missing

#### Export Method 1: CLI Script (v2.6.0)

Not directly usable in frontend, but document it for users:

```bash
docker exec ad-collector node export-audit.js \
  --output /tmp/audit.json \
  --include-details \
  --include-computers \
  --pretty
```

#### Export Method 2: API Endpoint (v2.6.1) 🎯 **IMPLEMENT THIS**

**NEW Endpoint:** `POST /api/audit/export`

This returns audit as a downloadable file. Perfect for frontend!

**Request:**
```typescript
interface ExportRequest {
  includeDetails?: boolean;   // Include full vulnerability details
  includeComputers?: boolean; // Include computer analysis
  filename?: string;          // Custom filename (default: audit-YYYY-MM-DD.json)
  pretty?: boolean;           // Pretty-print JSON
}
```

**Response Headers:**
```http
Content-Type: application/json
Content-Disposition: attachment; filename="audit-2025-12-08.json"
X-Audit-Duration: 45.23s
X-Audit-Users: 1234
X-Audit-Groups: 156
X-Audit-Computers: 89
X-Audit-Vulnerabilities-Total: 48
X-Audit-Vulnerabilities-Critical: 5
X-Audit-Vulnerabilities-High: 12
X-Audit-Security-Score: 72
```

#### Frontend Implementation:

**1. Add Export Button**
```typescript
function ExportButton({ collectorUrl, token, includeDetails, includeComputers }) {
  const [isExporting, setIsExporting] = useState(false);

  const handleExport = async () => {
    setIsExporting(true);
    try {
      const response = await fetch(`${collectorUrl}/api/audit/export`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          includeDetails,
          includeComputers,
          filename: `audit-${new Date().toISOString().split('T')[0]}.json`,
          pretty: true
        })
      });

      if (!response.ok) {
        throw new Error('Export failed');
      }

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

      // Show metadata from headers
      const metadata = {
        duration: response.headers.get('X-Audit-Duration'),
        users: response.headers.get('X-Audit-Users'),
        score: response.headers.get('X-Audit-Security-Score'),
        totalVulns: response.headers.get('X-Audit-Vulnerabilities-Total')
      };

      console.log('Export completed:', metadata);

    } catch (error) {
      console.error('Export error:', error);
      alert('Export failed: ' + error.message);
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <Button onClick={handleExport} disabled={isExporting}>
      {isExporting ? (
        <>
          <Spinner />
          Exporting...
        </>
      ) : (
        <>
          <DownloadIcon />
          Export JSON
        </>
      )}
    </Button>
  );
}
```

**2. Add Export Options Dialog**
```typescript
function ExportDialog({ isOpen, onClose, onExport }) {
  const [options, setOptions] = useState({
    includeDetails: true,
    includeComputers: true,
    pretty: true,
    filename: `audit-${new Date().toISOString().split('T')[0]}.json`
  });

  return (
    <Dialog open={isOpen} onClose={onClose}>
      <DialogTitle>Export Audit Report</DialogTitle>
      <DialogContent>
        <FormGroup>
          <FormControlLabel
            control={
              <Checkbox
                checked={options.includeDetails}
                onChange={(e) => setOptions({...options, includeDetails: e.target.checked})}
              />
            }
            label="Include full vulnerability details"
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={options.includeComputers}
                onChange={(e) => setOptions({...options, includeComputers: e.target.checked})}
              />
            }
            label="Include computer account analysis"
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={options.pretty}
                onChange={(e) => setOptions({...options, pretty: e.target.checked})}
              />
            }
            label="Pretty-print JSON (human-readable)"
          />
          <TextField
            label="Filename"
            value={options.filename}
            onChange={(e) => setOptions({...options, filename: e.target.value})}
            fullWidth
            margin="normal"
          />
        </FormGroup>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={() => onExport(options)} variant="contained">
          Export
        </Button>
      </DialogActions>
    </Dialog>
  );
}
```

---

### 4. JSON Import Feature ❌ **NOT IMPLEMENTED**

**Backend Status:** ❌ Not needed (frontend-only feature)
**Frontend Status:** ❌ Missing

This is a frontend-only feature. The user should be able to upload a previously exported JSON audit file to view the report without re-running the audit.

#### Frontend Implementation:

**1. Add Import Button**
```typescript
function ImportButton({ onImportComplete }) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isImporting, setIsImporting] = useState(false);

  const handleFileSelect = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsImporting(true);
    try {
      const text = await file.text();
      const auditData = JSON.parse(text);

      // Validate structure
      if (!auditData.success || !auditData.audit) {
        throw new Error('Invalid audit file format');
      }

      // Pass to parent component
      onImportComplete(auditData);

    } catch (error) {
      console.error('Import error:', error);
      alert('Failed to import audit file: ' + error.message);
    } finally {
      setIsImporting(false);
      // Reset input
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
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
      <Button
        onClick={() => fileInputRef.current?.click()}
        disabled={isImporting}
        variant="outlined"
      >
        {isImporting ? (
          <>
            <Spinner />
            Importing...
          </>
        ) : (
          <>
            <UploadIcon />
            Import JSON
          </>
        )}
      </Button>
    </>
  );
}
```

**2. Add Import/Export Toolbar**
```typescript
function AuditToolbar({ onExport, onImport, onRunAudit }) {
  return (
    <Toolbar>
      <ButtonGroup>
        <Button onClick={onRunAudit} variant="contained" color="primary">
          <PlayIcon />
          Run New Audit
        </Button>
        <Button onClick={onExport} variant="outlined">
          <DownloadIcon />
          Export
        </Button>
        <Button onClick={() => {/* trigger file input */}} variant="outlined">
          <UploadIcon />
          Import
        </Button>
      </ButtonGroup>
    </Toolbar>
  );
}
```

**3. Display Imported Audit with Banner**
```typescript
function AuditReport({ auditData, isImported }) {
  return (
    <div>
      {isImported && (
        <Alert severity="info" icon={<FolderOpenIcon />}>
          <AlertTitle>Imported Audit Report</AlertTitle>
          This report was imported from a saved file.
          Audit Date: {new Date(auditData.audit.metadata.timestamp).toLocaleString()}
          <Button size="small" onClick={clearImport}>Clear</Button>
        </Alert>
      )}

      {/* Regular audit display */}
      <AuditSummary data={auditData.audit.summary} />
      <VulnerabilityList findings={auditData.audit.findings} />
    </div>
  );
}
```

**4. Add Drag & Drop Support**
```typescript
function AuditDropZone({ onImport, children }) {
  const [isDragging, setIsDragging] = useState(false);

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    const file = e.dataTransfer.files[0];
    if (file && file.type === 'application/json') {
      const text = await file.text();
      const auditData = JSON.parse(text);
      onImport(auditData);
    }
  };

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      style={{
        border: isDragging ? '2px dashed #2196f3' : 'none',
        backgroundColor: isDragging ? 'rgba(33, 150, 243, 0.1)' : 'transparent'
      }}
    >
      {isDragging && (
        <div style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: 'rgba(33, 150, 243, 0.2)',
          zIndex: 1000
        }}>
          <Typography variant="h5">
            Drop audit JSON file here
          </Typography>
        </div>
      )}
      {children}
    </div>
  );
}
```

---

## 📊 Updated Audit Response Structure

### Full Response (v2.6.1):

```typescript
interface AuditResponse {
  success: boolean;
  audit: {
    metadata: {
      timestamp: string;        // ISO 8601
      duration: string;         // e.g., "45.23s"
      includeDetails: boolean;
      includeComputers: boolean;
      version: string;          // "2.6.1"
    };
    progress: ProgressStep[];   // 74 steps (11 process + 63 detection)
    summary: {
      users: number;
      groups: number;
      computers: number;
      vulnerabilities: {
        critical: number;       // Total critical findings
        high: number;
        medium: number;
        low: number;
        total: number;          // Sum of all severities
        score: number;          // 0-100 security score
      };
    };
    findings: {
      critical: Finding[];      // Array if includeDetails=true, number if false
      high: Finding[];
      medium: Finding[];
      low: Finding[];
    };
  };
}

interface ProgressStep {
  step: string;                 // e.g., "STEP_32_1_COMP_CONSTR_DELEG"
  description: string;          // Human-readable
  status: 'completed';
  count: number;
  duration: string;
  findings?: {                  // Optional
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

interface Finding {
  type: string;                 // Vulnerability type (see list above)
  samAccountName?: string;      // User or computer account
  dnsHostName?: string;         // Computer hostname
  dn: string;                   // Distinguished Name
  message: string;              // Human-readable description

  // Type-specific fields (varies by vulnerability):
  delegateTo?: string;
  daysInactive?: number;
  daysOld?: number;
  spns?: string[];
  // ... etc
}
```

---

## 🔄 Migration Checklist

### Phase 1: Critical Fixes (Required)
- [ ] Add support for 16 new computer vulnerability types
- [ ] Update total vulnerability count: 71 → 87
- [ ] Update severity counts (critical: 16, high: 27, medium: 38, low: 6)
- [ ] Add computer-specific fields display (dnsHostName, delegateTo, etc.)

### Phase 2: SSE Updates (Recommended)
- [ ] Update progress bar to handle 74 steps (11 process + 63 detection) instead of ~15
- [ ] Parse new step format (STEP_XX_YY_DESCRIPTION)
- [ ] Display step findings in real-time
- [ ] Add phase grouping for better UX

### Phase 3: Export/Import (High Value)
- [ ] Add "Export JSON" button using `/api/audit/export`
- [ ] Add export options dialog (includeDetails, includeComputers, pretty, filename)
- [ ] Implement file download with Content-Disposition
- [ ] Add "Import JSON" button with file picker
- [ ] Validate imported JSON structure
- [ ] Show "Imported Report" banner
- [ ] Add drag & drop support for JSON files
- [ ] Parse metadata from export headers (X-Audit-* headers)

### Phase 4: UI Enhancements (Optional)
- [ ] Add computer icon (🖥️) vs user icon (👤) in vulnerability cards
- [ ] Add filter by object type (All / Users / Groups / Computers / Domain / ADCS)
- [ ] Group findings by object type in UI
- [ ] Add "Download Report" action to individual findings
- [ ] Show audit metadata (timestamp, duration, version) prominently
- [ ] Add "Quick Stats" widget showing metadata from headers

---

## 🧪 Testing Scenarios

### Test 1: Computer Vulnerabilities Display
1. Run audit with `includeComputers: true`
2. Verify all 16 new computer vulnerability types appear
3. Check that computer-specific fields (dnsHostName, delegateTo) display correctly
4. Verify icons/colors distinguish computers from users

### Test 2: SSE Progress Tracking
1. Run audit using `/api/audit/stream`
2. Verify progress bar reaches 100% (74/74 steps)
3. Check that new step names display correctly
4. Verify step findings appear in real-time

### Test 3: Export JSON
1. Click "Export JSON" button
2. Verify options dialog appears
3. Select options (includeDetails, includeComputers, pretty)
4. Verify file downloads with correct filename
5. Check JSON is valid and pretty-printed if selected
6. Verify metadata headers are present

### Test 4: Import JSON
1. Export an audit to JSON
2. Click "Import JSON" button
3. Select the exported file
4. Verify report displays correctly
5. Check "Imported Report" banner appears
6. Verify all vulnerability types display (including computers)

### Test 5: Drag & Drop Import
1. Export an audit to JSON
2. Drag file over audit page
3. Verify drop zone highlights
4. Drop file
5. Verify report loads correctly

---

## 📖 Documentation Links

- **VULNERABILITIES.md**: Complete list of all 87 vulnerability types with descriptions
- **EXPORT.md**: Detailed guide on export features (CLI and API)
- **API_GUIDE.md**: Full API documentation including `/api/audit/export` endpoint

---

## 🆘 Need Help?

**Questions about implementation:**
- Check `VULNERABILITIES.md` for vulnerability type details
- Check `API_GUIDE.md` for API request/response formats
- Check `EXPORT.md` for export feature examples

**Backend Issues:**
- GitHub Issues: https://github.com/Fuskerrs/docker-ad-collector-n8n/issues

---

## 📝 Summary of Changes by Version

| Version | Changes | Frontend Impact |
|---------|---------|-----------------|
| **v2.5.0** | 16 computer vulnerabilities | ❌ Not implemented |
| **v2.2.0** | 74 SSE audit steps (11 process + 63 detection) | ⚠️ May need update |
| **v2.6.0** | CLI export script | ℹ️ Document for users |
| **v2.6.1** | API export endpoint | ❌ Not implemented |

---

**Last Updated:** December 8, 2025
**Backend Version:** 2.6.1
**Total Vulnerabilities:** 87
**SSE Steps:** 58
