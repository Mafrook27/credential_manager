// util/reqLogger.js
console.log('--------------reqlogger ------------------');

const morgan = require('morgan');
const logger = require('./Logger'); // Import Winston logger

// Configuration flags
const ENABLE_BODY_LOGGING = true;
const ENABLE_HEADER_LOGGING = false;
const ENABLE_QUERY_LOGGING = false;
const ENABLE_IP_LOGGING = true;
const ENABLE_TIMESTAMP = true;
const ENABLE_REQUEST_ID = true; // NEW: Enable request ID tracking

// Custom token: Request ID (NEW)
if (ENABLE_REQUEST_ID) {
  morgan.token('request-id', (req) => req.requestId || 'N/A');
}

// Custom token: Body logging with sanitization
if (ENABLE_BODY_LOGGING) {
  morgan.token('body', (req) => {
    if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
      // Sanitize sensitive fields
      const sanitized = { ...req.body };
      const sensitiveFields = ['password', 'token', 'secret', 'newPassword', 'oldPassword', 'confirmPassword'];
      
      sensitiveFields.forEach(field => {
        if (sanitized[field]) {
          sanitized[field] = '[REDACTED]';
        }
      });
      
      return JSON.stringify(sanitized);
    }
    return '';
  });
}

// Custom token: Headers
if (ENABLE_HEADER_LOGGING) {
  morgan.token('headers', (req) => JSON.stringify(req.headers));
}

// Custom token: Query params
if (ENABLE_QUERY_LOGGING) {
  morgan.token('query', (req) => {
    if (req.query && Object.keys(req.query).length > 0) {
      return JSON.stringify(req.query);
    }
    return '';
  });
}

// Custom token: IP address
if (ENABLE_IP_LOGGING) {
  morgan.token('ip', (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0].trim() || 
           req.socket.remoteAddress || 
           req.ip;
  });
}

// Custom token: Timestamp
if (ENABLE_TIMESTAMP) {
  morgan.token('timestamp', () => new Date().toISOString());
}

// Build format string
function buildFormat() {
  let format = '[REQ] :method :url :status - :response-time ms';

  if (ENABLE_REQUEST_ID) format = '[:request-id] ' + format; 
  if (ENABLE_TIMESTAMP) format = ':timestamp ' + format;
  if (ENABLE_IP_LOGGING) format += ' :ip';
  if (ENABLE_QUERY_LOGGING) format += ' :query';
  if (ENABLE_BODY_LOGGING) format += ' :body';
  if (ENABLE_HEADER_LOGGING) format += ' :headers';

  return format;
}

const format = buildFormat();


const requestLogger = morgan(format, {

  stream: {
    write: (message) => {
      logger.http(message.trim());
    }
  },
  

  skip: (req) => {

    // return req.url === '/api/health' || 
       return    req.url === '/favicon.ico' ||
           req.url.startsWith('/api-docs') ||
           req.url.startsWith('/swagger');
  }
});

module.exports = requestLogger;
