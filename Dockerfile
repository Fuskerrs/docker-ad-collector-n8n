FROM node:18-alpine

# Metadata
LABEL maintainer="AD Collector for n8n"
LABEL version="1.0.0"
LABEL description="Active Directory Collector API for n8n-nodes-ad-admin"

# Set working directory
WORKDIR /app

# Install dependencies first (better caching)
COPY package.json ./
RUN npm install --production

# Copy application files
COPY server.js ./
COPY entrypoint.sh ./

# Make entrypoint executable
RUN chmod +x entrypoint.sh

# Expose port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8443/health', (r) => { process.exit(r.statusCode === 200 ? 0 : 1); }).on('error', () => process.exit(1));"

# Use entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["node", "server.js"]
