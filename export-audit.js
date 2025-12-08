#!/usr/bin/env node

/**
 * AD Collector - Standalone Audit Export Script
 *
 * This script performs a complete AD security audit and exports results to a JSON file.
 * It can be run directly without exposing the collector API publicly.
 *
 * Usage:
 *   node export-audit.js [options]
 *
 * Options:
 *   --output <file>        Output file path (default: audit-YYYY-MM-DD-HHmmss.json)
 *   --include-details      Include full vulnerability details in export
 *   --include-computers    Include computer accounts in analysis
 *   --pretty               Pretty-print JSON output (human-readable)
 *   --help                 Show this help message
 *
 * Examples:
 *   # Basic audit export
 *   node export-audit.js
 *
 *   # Detailed audit with computers, pretty-printed
 *   node export-audit.js --output audit.json --include-details --include-computers --pretty
 *
 *   # From Docker container
 *   docker exec ad-collector node export-audit.js --output /tmp/audit.json --pretty
 *   docker cp ad-collector:/tmp/audit.json ./audit.json
 *
 * Environment Variables:
 *   Same as server.js (LDAP_URL, LDAP_BASE_DN, LDAP_BIND_DN, LDAP_BIND_PASSWORD, etc.)
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

// Parse command line arguments
const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
  console.log(fs.readFileSync(__filename, 'utf8').split('*/')[0].split('/**')[1]);
  process.exit(0);
}

const options = {
  output: null,
  includeDetails: args.includes('--include-details'),
  includeComputers: args.includes('--include-computers'),
  pretty: args.includes('--pretty')
};

// Get output file path
const outputIndex = args.indexOf('--output');
if (outputIndex !== -1 && args[outputIndex + 1]) {
  options.output = args[outputIndex + 1];
} else {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T');
  options.output = `audit-${timestamp[0]}-${timestamp[1].split('-')[0]}.json`;
}

console.log('╔════════════════════════════════════════════════════════════╗');
console.log('║   AD Collector - Standalone Audit Export v2.6.0           ║');
console.log('╚════════════════════════════════════════════════════════════╝');
console.log('');
console.log('Configuration:');
console.log(`  Output File: ${options.output}`);
console.log(`  Include Details: ${options.includeDetails}`);
console.log(`  Include Computers: ${options.includeComputers}`);
console.log(`  Pretty JSON: ${options.pretty}`);
console.log('');
console.log('📋 Starting AD security audit...\n');

// Generate a temporary token for internal API call
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

const tempToken = jwt.sign(
  {
    service: 'export-audit-cli',
    created: Date.now()
  },
  JWT_SECRET,
  {
    expiresIn: '5m',
    issuer: 'export-audit-cli'
  }
);

// Make request to local API
const postData = JSON.stringify({
  includeDetails: options.includeDetails,
  includeComputers: options.includeComputers
});

const requestOptions = {
  hostname: 'localhost',
  port: process.env.PORT || 8443,
  path: '/api/audit',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(postData),
    'Authorization': `Bearer ${tempToken}`
  },
  timeout: 300000 // 5 minutes timeout
};

const req = http.request(requestOptions, (res) => {
  let data = '';

  res.on('data', (chunk) => {
    data += chunk;
    // Show progress dots
    process.stdout.write('.');
  });

  res.on('end', () => {
    console.log('\n');

    try {
      const result = JSON.parse(data);

      if (!result.success) {
        console.error('❌ Audit failed:', result.error);
        process.exit(1);
      }

      // Write to file
      const output = options.pretty ? JSON.stringify(result, null, 2) : JSON.stringify(result);

      // Ensure output directory exists
      const outputDir = path.dirname(path.resolve(options.output));
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }

      fs.writeFileSync(options.output, output, 'utf8');

      // Display summary
      const summary = result.audit.summary;
      const vulns = summary.vulnerabilities;

      console.log('✅ Audit export completed successfully!\n');
      console.log('📄 Output Details:');
      console.log(`   File: ${path.resolve(options.output)}`);
      console.log(`   Size: ${(Buffer.byteLength(output) / 1024).toFixed(2)} KB`);
      console.log('');
      console.log('📊 Audit Summary:');
      console.log(`   Users: ${summary.users}`);
      console.log(`   Groups: ${summary.groups}`);
      console.log(`   Computers: ${summary.computers || 'N/A'}`);
      console.log(`   Duration: ${result.audit.metadata.duration}`);
      console.log('');
      console.log('🔍 Vulnerabilities Found:');
      console.log(`   🔴 Critical: ${vulns.critical}`);
      console.log(`   🟠 High: ${vulns.high}`);
      console.log(`   🟡 Medium: ${vulns.medium}`);
      console.log(`   🔵 Low: ${vulns.low}`);
      console.log(`   📊 Total: ${vulns.total}`);
      console.log('');
      console.log('🛡️  Security Score:');
      console.log(`   ${vulns.score}/100 ${getScoreEmoji(vulns.score)}`);
      console.log(`   ${getScoreDescription(vulns.score)}`);
      console.log('');

      if (!options.includeDetails) {
        console.log('💡 Tip: Use --include-details to export full vulnerability data');
      }
      if (!options.includeComputers) {
        console.log('💡 Tip: Use --include-computers to analyze computer accounts');
      }
      if (!options.pretty) {
        console.log('💡 Tip: Use --pretty for human-readable JSON output');
      }

      process.exit(0);

    } catch (error) {
      console.error('❌ Failed to parse audit response:', error.message);
      console.error('Raw response:', data.substring(0, 500));
      process.exit(1);
    }
  });
});

req.on('error', (error) => {
  console.error('\n❌ Failed to connect to AD Collector API:');
  console.error(error.message);
  console.error('');
  console.error('Troubleshooting:');
  console.error('  1. Ensure AD Collector server is running (node server.js)');
  console.error('  2. Check PORT environment variable (default: 8443)');
  console.error('  3. Verify LDAP configuration in .env file');
  process.exit(1);
});

req.on('timeout', () => {
  console.error('\n❌ Audit request timed out (>5 minutes)');
  console.error('This may indicate:');
  console.error('  - Large AD environment requiring more time');
  console.error('  - LDAP connectivity issues');
  console.error('  - Server performance problems');
  req.abort();
  process.exit(1);
});

req.write(postData);
req.end();

function getScoreEmoji(score) {
  if (score >= 90) return '🟢 Excellent';
  if (score >= 70) return '🟡 Good';
  if (score >= 50) return '🟠 Fair';
  if (score >= 30) return '🔴 Poor';
  return '⛔ Critical';
}

function getScoreDescription(score) {
  if (score >= 90) return 'Strong security posture with minimal vulnerabilities';
  if (score >= 70) return 'Good security with some issues to address';
  if (score >= 50) return 'Multiple vulnerabilities requiring attention';
  if (score >= 30) return 'Significant security gaps - urgent remediation needed';
  return 'Severe security risk - immediate action required';
}
