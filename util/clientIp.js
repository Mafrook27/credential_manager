// util/ipHelper.js

/**
 * Detect IP version (IPv4 or IPv6)
 * @param {string} ip - IP address
 * @returns {string} 'IPv4' or 'IPv6'
 */
function getIPVersion(ip) {
  return ip.includes(':') ? 'IPv6' : 'IPv4';
}

/**
 * Extract and clean client IP address
 * Handles proxy headers and IPv6 conversion
 * @param {Object} req - Express request object
 * @returns {Object} { address: string, version: string }
 */
function getClientIP(req) {
  let ip = req.headers['x-forwarded-for']?.split(',')[0].trim() ||
           req.headers['x-real-ip'] ||
           req.socket.remoteAddress ||
           req.ip;
  
  // Clean IPv6-mapped IPv4 (::ffff:192.168.1.1 → 192.168.1.1)
  ip = ip.replace(/^::ffff:/, '');
  
  // Localhost handling
  if (ip === '::1') ip = '127.0.0.1';
  
  return {
    address: ip,
    version: getIPVersion(ip)
  };
}

module.exports = { getClientIP, getIPVersion };
