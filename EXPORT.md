# AD Collector - Local Export Feature

## Overview

Starting with v2.6.0, AD Collector supports **local audit export** functionality. This allows enterprises to perform complete AD security audits without exposing the collector API publicly.

### Use Cases

- **Enterprise security requirements**: Companies that cannot expose internal services to external networks
- **Offline analysis**: Export audit data for analysis by external security teams
- **Compliance documentation**: Generate audit reports for regulatory compliance
- **Air-gapped environments**: Perform audits in isolated networks

## Features

- ✅ Complete AD security audit (all 87 vulnerability detections)
- ✅ Export to JSON format
- ✅ Support for `includeDetails` and `includeComputers` options
- ✅ Pretty-print option for human-readable output
- ✅ Runs entirely within Docker container (no network exposure required)
- ✅ Automatic timestamp-based filenames
- ✅ Progress tracking and detailed summary

## Quick Start

### Option 1: Run inside Docker container

```bash
# Basic audit export
docker exec ad-collector node export-audit.js

# Detailed audit with all options
docker exec ad-collector node export-audit.js \
  --output /tmp/audit.json \
  --include-details \
  --include-computers \
  --pretty

# Copy export to host
docker cp ad-collector:/tmp/audit.json ./audit-$(date +%Y-%m-%d).json
```

### Option 2: One-liner export to host

```bash
docker exec ad-collector node export-audit.js \
  --output /tmp/audit.json --include-details --include-computers --pretty \
  && docker cp ad-collector:/tmp/audit.json ./audit.json \
  && echo "✅ Audit exported to ./audit.json"
```

### Option 3: Run directly with Node.js (if not using Docker)

```bash
cd /opt/docker-ad-collector-n8n
node export-audit.js --output audit.json --include-details --pretty
```

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--output <file>` | Output file path | `audit-YYYY-MM-DD-HHmmss.json` |
| `--include-details` | Include full vulnerability details | `false` (summary only) |
| `--include-computers` | Include computer account analysis | `false` |
| `--pretty` | Pretty-print JSON output | `false` (minified) |
| `--help` | Show help message | - |

## Output Format

### Summary Mode (default)

```json
{
  "success": true,
  "audit": {
    "metadata": {
      "timestamp": "2025-12-08T12:34:56.789Z",
      "duration": "45.23s",
      "includeDetails": false,
      "includeComputers": false,
      "exportedBy": "export-audit.js",
      "version": "2.6.0"
    },
    "summary": {
      "users": 1234,
      "groups": 156,
      "computers": 0,
      "vulnerabilities": {
        "critical": 5,
        "high": 12,
        "medium": 23,
        "low": 8,
        "total": 48,
        "score": 72
      }
    },
    "findings": {
      "critical": 5,
      "high": 12,
      "medium": 23,
      "low": 8
    }
  }
}
```

### Detailed Mode (`--include-details`)

```json
{
  "success": true,
  "audit": {
    "metadata": { ... },
    "progress": [
      {
        "step": "STEP_01_CONNECT",
        "description": "Connected to LDAP",
        "timestamp": "2025-12-08T12:34:56.789Z"
      },
      ...
    ],
    "summary": { ... },
    "findings": {
      "critical": [
        {
          "type": "PASSWORD_NOT_REQUIRED",
          "samAccountName": "testuser",
          "dn": "CN=testuser,CN=Users,DC=example,DC=com",
          "message": "Account does not require a password"
        },
        ...
      ],
      "high": [...],
      "medium": [...],
      "low": [...]
    }
  }
}
```

## Example Workflows

### 1. Enterprise Security Audit

```bash
# 1. Perform comprehensive audit
docker exec ad-collector node export-audit.js \
  --output /tmp/security-audit.json \
  --include-details \
  --include-computers \
  --pretty

# 2. Copy to host
docker cp ad-collector:/tmp/security-audit.json ./security-audit.json

# 3. Review findings
cat security-audit.json | jq '.audit.summary.vulnerabilities'

# 4. Extract critical vulnerabilities
cat security-audit.json | jq '.audit.findings.critical'
```

### 2. Monthly Compliance Report

```bash
#!/bin/bash
# monthly-audit.sh

DATE=$(date +%Y-%m-%d)
OUTPUT="audit-${DATE}.json"

docker exec ad-collector node export-audit.js \
  --output /tmp/${OUTPUT} \
  --include-details \
  --include-computers \
  --pretty

docker cp ad-collector:/tmp/${OUTPUT} ./reports/${OUTPUT}

echo "Monthly audit saved to ./reports/${OUTPUT}"
```

### 3. Quick Security Check

```bash
# Fast summary audit (no details, no computers)
docker exec ad-collector node export-audit.js --output /tmp/quick-check.json
docker cp ad-collector:/tmp/quick-check.json ./quick-check.json

# View score
cat quick-check.json | jq '.audit.summary.vulnerabilities.score'
```

## Integration with External Tools

### Analyze with jq

```bash
# Get top 10 critical findings
cat audit.json | jq '.audit.findings.critical[:10]'

# Count vulnerabilities by type
cat audit.json | jq '.audit.findings | to_entries | map({severity: .key, count: (.value | length)})'

# Get all users with password not required
cat audit.json | jq '.audit.findings.critical[] | select(.type == "PASSWORD_NOT_REQUIRED") | .samAccountName'

# Calculate total findings
cat audit.json | jq '.audit.summary.vulnerabilities.total'
```

### Import into Python

```python
import json

with open('audit.json', 'r') as f:
    audit = json.load(f)

print(f"Security Score: {audit['audit']['summary']['vulnerabilities']['score']}/100")
print(f"Total Vulnerabilities: {audit['audit']['summary']['vulnerabilities']['total']}")

# Process critical findings
for finding in audit['audit']['findings']['critical']:
    print(f"[CRITICAL] {finding['type']}: {finding['samAccountName']}")
```

### Send to SIEM/Monitoring

```bash
# Send to Elastic/Splunk
curl -X POST https://siem.company.com/api/logs \
  -H "Content-Type: application/json" \
  -d @audit.json

# Send to Slack webhook
curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  -H "Content-Type: application/json" \
  -d "{\"text\": \"AD Audit completed. Score: $(cat audit.json | jq -r '.audit.summary.vulnerabilities.score')/100\"}"
```

## Security Considerations

### Authentication

The export script uses a **temporary JWT token** that:
- Is valid for only 5 minutes
- Is generated internally (not exposed)
- Expires immediately after use
- Cannot be intercepted (localhost-only communication)

### Network Isolation

The export script:
- Connects to `localhost` only (never exposed to network)
- Communicates via HTTP on loopback interface
- Does not require external network access
- Safe for air-gapped environments

### Data Protection

- Export files contain sensitive security data
- Store exports in secure locations with restricted permissions
- Consider encrypting exports for transmission:

```bash
# Encrypt export
gpg --encrypt --recipient security@company.com audit.json

# Or use openssl
openssl enc -aes-256-cbc -salt -in audit.json -out audit.json.enc
```

## Troubleshooting

### Error: "Failed to connect to AD Collector API"

**Cause**: Server not running or wrong port

**Solution**:
```bash
# Check if server is running
docker ps | grep ad-collector

# Check container logs
docker logs ad-collector

# Restart container
docker compose restart
```

### Error: "Audit request timed out"

**Cause**: Large AD environment or slow LDAP connection

**Solution**:
- Wait longer (timeout is 5 minutes)
- Check LDAP connectivity: `docker exec ad-collector node server.js` logs
- Reduce scan scope by removing `--include-computers`

### Error: "ENOENT: no such file or directory"

**Cause**: Invalid output path

**Solution**:
```bash
# Ensure directory exists
docker exec ad-collector mkdir -p /tmp

# Or use absolute path
docker exec ad-collector node export-audit.js --output /tmp/audit.json
```

### Permission Denied

**Cause**: Output directory not writable

**Solution**:
```bash
# Use /tmp directory (always writable)
docker exec ad-collector node export-audit.js --output /tmp/audit.json

# Or fix permissions
docker exec -u root ad-collector chmod 777 /path/to/output
```

## Performance

| AD Size | Users | Duration | Export Size (summary) | Export Size (detailed) |
|---------|-------|----------|-----------------------|------------------------|
| Small | 100 | ~5s | ~10 KB | ~50 KB |
| Medium | 1,000 | ~20s | ~20 KB | ~200 KB |
| Large | 10,000 | ~60s | ~50 KB | ~2 MB |
| Very Large | 50,000+ | ~180s | ~100 KB | ~10 MB |

*Times measured with `includeDetails` and `includeComputers` enabled*

## Automation Examples

### Cron Job (Daily Audit)

```bash
# Add to crontab: crontab -e
0 2 * * * /opt/scripts/daily-audit.sh >> /var/log/ad-audit.log 2>&1
```

```bash
#!/bin/bash
# /opt/scripts/daily-audit.sh

DATE=$(date +%Y-%m-%d)
OUTPUT="/var/audits/audit-${DATE}.json"

docker exec ad-collector node export-audit.js \
  --output /tmp/audit.json \
  --include-details \
  --pretty

docker cp ad-collector:/tmp/audit.json ${OUTPUT}

# Cleanup old audits (keep last 30 days)
find /var/audits -name "audit-*.json" -mtime +30 -delete

echo "Audit completed: ${OUTPUT}"
```

### Systemd Timer

```ini
# /etc/systemd/system/ad-audit.timer
[Unit]
Description=Daily AD Security Audit

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/ad-audit.service
[Unit]
Description=AD Security Audit Export

[Service]
Type=oneshot
ExecStart=/opt/scripts/daily-audit.sh
User=root
```

```bash
# Enable timer
systemctl enable ad-audit.timer
systemctl start ad-audit.timer
```

## Comparison: API vs Local Export

| Feature | API (`/api/audit`) | Local Export (`export-audit.js`) |
|---------|-------------------|----------------------------------|
| Network exposure | ❌ Requires API access | ✅ No network exposure |
| Authentication | ✅ JWT token required | ✅ Internal only |
| Full vulnerability data | ✅ Yes | ✅ Yes |
| SSE streaming | ✅ Yes | ❌ No (summary at end) |
| Real-time progress | ✅ Yes | ⚠️ Progress dots only |
| Use case | n8n integration | Enterprise/offline audit |

## FAQ

**Q: Can I run multiple exports simultaneously?**
A: No, the LDAP connection is shared. Run exports sequentially.

**Q: Does this work with ENDPOINT_MODE=no-audit?**
A: No, you must enable audit endpoints (`ENDPOINT_MODE=full` or `audit-only`).

**Q: Can I export to CSV?**
A: Currently only JSON is supported. Use `jq` to convert to CSV:
```bash
cat audit.json | jq -r '.audit.findings.critical[] | [.type, .samAccountName] | @csv'
```

**Q: How do I share exports with external consultants?**
A: Encrypt the file before sharing:
```bash
gpg --encrypt --recipient consultant@example.com audit.json
```

**Q: Does export count against TOKEN_MAX_USES quota?**
A: No, export uses a temporary internal token that bypasses quota limits.

## Version History

**v2.6.0** - Initial release
- Added `export-audit.js` script
- Support for JSON export with all audit features
- Command-line options for output, details, computers, and formatting

---

## Additional Resources

- [Full vulnerability list](VULNERABILITIES.md)
- [API documentation](README.md)
- [Docker setup guide](README.md#installation)

## Support

For issues or questions:
- GitHub Issues: https://github.com/Fuskerrs/docker-ad-collector-n8n/issues
- Documentation: https://github.com/Fuskerrs/docker-ad-collector-n8n
