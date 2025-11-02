#!/bin/sh

# AD Collector for n8n - Entrypoint Script
# Version 1.0.0

echo "========================================="
echo "AD Collector for n8n - Starting..."
echo "========================================="

# Check required environment variables
if [ -z "$LDAP_URL" ]; then
  echo "⚠️  WARNING: LDAP_URL not set, using default: ldaps://localhost:636"
fi

if [ -z "$LDAP_BASE_DN" ]; then
  echo "⚠️  WARNING: LDAP_BASE_DN not set, using default: DC=example,DC=com"
fi

if [ -z "$LDAP_BIND_DN" ]; then
  echo "⚠️  WARNING: LDAP_BIND_DN not set, using default: CN=admin,CN=Users,DC=example,DC=com"
fi

if [ -z "$LDAP_BIND_PASSWORD" ]; then
  echo "❌ ERROR: LDAP_BIND_PASSWORD is required!"
  echo "Please set the LDAP_BIND_PASSWORD environment variable."
  exit 1
fi

echo "✅ Configuration validated"
echo "========================================="

# Start the application
exec node server.js
