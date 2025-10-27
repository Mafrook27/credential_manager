

/**
 * Simple helper to track route operations
 * Usage: router.post('/login', track('USER_LOGIN', 'auth'), controller.login)
 */
const track = (operation) => {
  return (req, res, next) => {
    req.activityMeta = { operation };
    next();
  };
};

module.exports = { track };
