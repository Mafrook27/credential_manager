// util/Logger.js
const winston = require('winston');
const { combine, timestamp, printf, errors, colorize, json } = winston.format;

// Custom log levels with 'activity' level
const customLevels = {
  levels: {
    error: 0,
    warn: 1,
    info: 2,
    http: 3,
    activity: 4,
    debug: 5
  },
  colors: {
    error: 'red',
    warn: 'yellow',
    info: 'green',
    http: 'magenta',
    activity: 'cyan',
    debug: 'blue'
  }
};

winston.addColors(customLevels.colors);

const filterStackTrace = winston.format((info) => {
  if (info.stack) {
    const stackLines = info.stack.split('\n');
    
    const filteredStack = stackLines.filter((line, index) => {
      if (index === 0) return true;
      
      return !line.includes('node_modules') && 
             !line.includes('Layer.handle') &&
             !line.includes('router/index.js');
    });
    
    info.stack = filteredStack.slice(0, 4).join('\n');
  }
  return info;
});

// Console format (colored, readable)
const consoleFormat = combine(
  colorize({ all: true }),
  timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  filterStackTrace(), 
  errors({ stack: true }),
  // ✅ FIX: Add 'stack' to the destructuring parameters
  printf(({ timestamp, level, message, stack, ...metadata }) => {
    let msg = `${timestamp} [${level}]: ${message}`;
    
    if (stack) {
      msg += `\n${stack}`;
    }
    
    if (Object.keys(metadata).length > 0) {
      msg += `\n${JSON.stringify(metadata, null, 2)}`;
    }
    
    return msg;
  })
);

// File format (JSON for parsing)
const fileFormat = combine(
  timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  filterStackTrace(),  // ✅ ADD: Apply filter to file logs too
  errors({ stack: true }),
  json()
);

// Create logger instance
const logger = winston.createLogger({
  levels: customLevels.levels,
  level: process.env.LOG_LEVEL || 'activity',
  format: fileFormat,
  transports: [
    new winston.transports.Console({ format: consoleFormat }),
    
    new winston.transports.File({ 
      filename: 'logs/combined.log',
      maxsize: 5242880,
      maxFiles: 5
    }),
    
    new winston.transports.File({ 
      filename: 'logs/error.log',
      level: 'error',
      maxsize: 5242880,
      maxFiles: 5
    }),
    
    new winston.transports.File({ 
      filename: 'logs/activity.log',
      level: 'activity',
      maxsize: 10485760,
      maxFiles: 10
    })
  ],
  exitOnError: false
});

logger.activity = function(message, metadata) {
  this.log('activity', message, metadata);
};

module.exports = logger;
