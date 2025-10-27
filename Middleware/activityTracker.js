const { v4: uuidv4 } = require('uuid');
const geoip = require('geoip-lite');
const ActivityLog = require('../Models/activity');
const logger = require('../util/Logger');
const User = require('../Models/CRED_User');
const { getClientIP } = require('../util/clientIp');  

const config = {
  ENABLE_TRACKING: true,
  SLOW_THRESHOLD_MS: 200,
  LOG_SLOW_ONLY: false,
  LOG_TO_DB: true,
  LOG_TO_CONSOLE: false,
  ENABLE_GEOLOCATION: true,
  EXCLUDE_PATHS: [
    '/api/health',
    '/api-docs',
    '/swagger.json',
    '/favicon.ico',
    '/api/admin/activity-logs'
  ]
};

const attachRequestId = (req, res, next) => {
  req.requestId = uuidv4();
  req.startTime = Date.now();
  res.setHeader('X-Request-ID', req.requestId);
  next();
};

const activityTrackerMiddleware = (req, res, next) => {
  if (!config.ENABLE_TRACKING) return next();
  if (config.EXCLUDE_PATHS.some(path => req.url.startsWith(path))) return next();
  
  res.on('finish', async () => {
    try {
      const responseTime = Date.now() - req.startTime;
      const isSlowResponse = responseTime > config.SLOW_THRESHOLD_MS;
      
      if (config.LOG_SLOW_ONLY && !isSlowResponse) return;
      
      
      const ipInfo = getClientIP(req);
      
    
      let geolocation = null;
      if (config.ENABLE_GEOLOCATION) {
        const geo = geoip.lookup(ipInfo.address); 
        if (geo) {
          geolocation = {
            country: geo.country,
            region: geo.region || '',
            city: geo.city || '',
            timezone: geo.timezone,
            latitude: geo.ll?.[0] || 0,
            longitude: geo.ll?.[1] || 0
          };
        }
      }

      const userId = req.payload?.id || req.loginUserId || null;
      const isAuthenticated = !!userId;

      let userEmail = 'anonymous';
      let userName = null;
      let userRole = 'N/A';

      if (userId) {
        try {
          const user = await User.findById(userId).select('email name role').lean();
          if (user) {
            userEmail = user.email;
            userName = user.name;
            userRole = user.role;
          }
        } catch (dbError) {
          logger.warn('Failed to fetch user details', {
            userId,
            error: dbError.message
          });
        }
      } else if (req.body?.email) {
        userEmail = req.body.email;
        try {
          const user = await User.findOne({ email: req.body.email }).select('name role').lean();
          if (user) {
            userName = user.name;
            userRole = user.role;
          }
        } catch (dbError) {
          // Silent fail
        }
      }

      const operation = req.activityMeta?.operation || 'UNKNOWN_OPERATION';
      const resourceId = req.params?.id || req.params?.userId || req.params?.credentialId || null;
      
      const hasError = res.statusCode >= 400;
      
      const activityEntry = {
        requestId: req.requestId,
        timestamp: new Date(),
        method: req.method,
        url: req.originalUrl || req.url,
        route: req.route?.path,
        userId,
        userEmail,
        userName,
        userRole,
        isAuthenticated,
        operation,
        resourceId,
        statusCode: res.statusCode,
        responseTime,
        isSlowResponse,
        slowThreshold: config.SLOW_THRESHOLD_MS,
        ipAddress: ipInfo.address, 
        userAgent: req.get('user-agent'),
        geolocation,
        hasError,
        errorMessage: hasError ? (res.locals.error?.message || 'Unknown Error') : null,
        errorStack: hasError ? (res.locals.error?.stack || null) : null
      };
      
      if (config.LOG_TO_CONSOLE) {
        const indicator = hasError ? '[ERROR]' : isSlowResponse ? '[SLOW]' : '[OK]';
        const logLevel = hasError ? 'error' : isSlowResponse ? 'warn' : 'info';
        
        logger[logLevel](`${indicator} ${operation}`, {
          requestId: req.requestId,
          method: req.method,
          url: req.url,
          statusCode: res.statusCode,
          responseTime: `${responseTime}ms`,
          userId: userId || null,
          userEmail: userEmail || 'anonymous',
          userName: userName || null,
          userRole: userRole || 'N/A',
          resourceId,
          ip: `${ipInfo.address} (${ipInfo.version})`,  
          location: geolocation 
            ? `${geolocation.city || geolocation.region || geolocation.country}` 
            : 'unknown'
        });
      }
      
      if (config.LOG_TO_DB) {
        await ActivityLog.create(activityEntry);
      }
      
    } catch (error) {
      logger.error('Activity tracking failed', {
        error: error.message,
        requestId: req.requestId
      });
    }
  });
  
  next();
};

module.exports = { activityTrackerMiddleware, attachRequestId, config };
