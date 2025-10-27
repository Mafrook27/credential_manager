const jwt = require("jsonwebtoken");
const logger = require("../util/Logger");

/**
 * Middleware to authenticate JWT tokens from cookie OR Authorization header
 * @module middleware/authMiddleware
 * @function authenticateToken
 * @param {Object} req - Express request object
 * @param {Object} req.cookies - Request cookies (NEW)
 * @param {string} [req.cookies.token] - JWT token stored in HttpOnly cookie (NEW)
 * @param {Object} req.headers - Request headers
 * @param {string} [req.headers.authorization] - Authorization header in format "Bearer <token>" (OLD - kept for compatibility)
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {void}
 * @throws {JSON} 401 - No token provided
 * @throws {JSON} 403 - Invalid or expired token
 * @example
 * // Apply to route
 * app.get('/protected-route', authenticateToken, (req, res) => {
 *   // Access authenticated user ID via req.userId
 *   res.json({ userId: req.userId });
 * });
 */

function authenticateToken(req, res, next) {
  try {
    //  Token from HttpOnly cookie
    console.log("Cookies:", req.cookies);
    let token = req.cookies?.token;
console.log("Cookie token:", req.cookies?.token);
    //  OLD M
 // Authorization header
    /*
    if (!token) {
      token = req.headers.authorization?.split(" ")[1];
    }
    */

    if (!token) {
      const error = new Error("No token provided");
      error.statusCode = 401;
      throw error;
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        const error = new Error("Invalid or expired token");
        error.statusCode = 403;
        throw error;
      }

      req.payload = decoded.payload;
      logger.info("Token payload:", decoded);
      next();
    });
  } catch (error) {
    logger.error("Authentication error", { message: error.message, stack: error.stack });
    next(error);
  }
}

module.exports = { authenticateToken };
