const { verifyAccessToken } = require("../util/jwtUtil");
const logger = require("../util/Logger");

/**
 * Middleware to authenticate JWT access tokens from cookie
 * @module middleware/authMiddleware
 * @function authenticateToken
 * @param {Object} req - Express request object
 * @param {Object} req.cookies - Request cookies
 * @param {string} [req.cookies.accessToken] - Access token stored in HttpOnly cookie
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {void}
 * @throws {JSON} 401 - No token provided or token expired
 * @throws {JSON} 403 - Invalid token
 */
function authenticateToken(req, res, next) {
  try {
    // Get access token from cookie
    const token = req.cookies?.accessToken;

    if (!token) {
      logger.warn("❌ No access token found in cookies");
      const error = new Error("Session expired. Please login again.");
      error.statusCode = 401;
      error.code = 'NO_TOKEN';
      throw error;
    }

    // Verify access token
    const decoded = verifyAccessToken(token);
    req.payload = decoded.payload;
    
    logger.info("✅ Token authenticated for user:", decoded.payload.id);
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      logger.warn("⏰ Access token expired");
      const err = new Error("Access token expired");
      err.statusCode = 401;
      err.code = 'TOKEN_EXPIRED';
      return next(err);
    }
    
    if (error.name === 'JsonWebTokenError') {
      logger.error("❌ Invalid token");
      const err = new Error("Invalid session. Please login again.");
      err.statusCode = 401;
      err.code = 'INVALID_TOKEN';
      return next(err);
    }

    logger.error("❌ Authentication error:", error.message);
    next(error);
  }
}

module.exports = { authenticateToken };
