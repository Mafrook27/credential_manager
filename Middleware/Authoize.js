const User = require('../Models/CRED_User');

const authorize = (allowedRoles = []) => {
  return async (req, res, next) => {
    try {
      const currentUserId = req.payload?.id;

      if (!currentUserId) {
        const error = new Error("Unauthorized: No user ID found");
        error.statusCode = 401;
        throw error;
      }

      const user = await User.findById(currentUserId);
      if (!user) {
        const error = new Error("User not found");
        error.statusCode = 404;
        throw error;
      }

      if (allowedRoles.length > 0 && !allowedRoles.includes(user.role)) {
        const error = new Error("Access denied: Insufficient permissions");
        error.statusCode = 403;
        throw error;
      }

      req.user = user;
      next();
    } catch (error) {
      next(error);
    }
  };
};

const requireAdmin = authorize(['admin']);
const requireUser = authorize(['admin','user']);

module.exports = {
  authorize,
  requireAdmin,
  requireUser
};