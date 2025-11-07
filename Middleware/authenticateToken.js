const { verifyAccessToken } = require("../util/jwtUtil");
const Session = require("../models/Session");
const logger = require("../util/Logger");

/**
 * Middleware to authenticate JWT access tokens from cookie
 * Also validates that the session is still active
 * @module middleware/authMiddleware
 * @function authenticateToken
 * @param {Object} req - Express request object
 * @param {Object} req.cookies - Request cookies
 * @param {string} [req.cookies.accessToken] - Access token stored in HttpOnly cookie
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {void}
 * @throws {JSON} 401 - No token provided or token expired or session inactive
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

    // ✅ Validate session is ACTIVE in database
    const validateActiveSession = async () => {
      const session = await Session.findOne({
        userId: decoded.payload.id,
        active: true  // ✅ Check if active
      });

      if (!session) {
        logger.warn(`❌ No active session found for user ${decoded.payload.id}`);
        const error = new Error("Session ended. You logged in from another device.");
        error.statusCode = 401;
        error.code = 'SESSION_INACTIVE';
        throw error;
      }

      logger.info(`✅ Active session validated for user ${decoded.payload.id}`);
    };

    // Execute async validation and then call next()
    validateActiveSession()
      .then(() => {
        next();
      })
      .catch(error => {
        next(error);
      });

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      logger.warn("⏰ Access token expired");
      const err = new Error("Access token expired. Please refresh.");
      err.statusCode = 401;
      err.code = 'TOKEN_EXPIRED';
      return next(err);
    }

    if (error.name === 'JsonWebTokenError') {
      logger.error("❌ Invalid token signature");
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
