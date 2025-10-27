const User = require('../Models/CRED_User');
const bcrypt = require("bcryptjs");
const logger = require('../util/Logger');

const commonController = {
  // GET /api/users/list
  getUserList: async (req, res, next) => {
    try {
      const requesterId = req.payload.id;
      const { page = 1, limit = 10 } = req.query;

      // Validate current user
      const currentUser = await User.findById(requesterId).lean();
      if (!currentUser) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }

 

      // 🔄 Pagination setup
      const parsedLimit = Math.max(parseInt(limit), 1);
      const parsedPage = Math.max(parseInt(page), 1);
      const skip = (parsedPage - 1) * parsedLimit;

      // 🔍 Fetch paginated users (id + name only)
      const [users, total] = await Promise.all([
        User.find({}, '_id name')
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parsedLimit)
          .lean(),
        User.countDocuments()
      ]);

      // ✅ Response
      res.json({
        success: true,
        count: users.length,
        total,
        page: parsedPage,
        limit: parsedLimit,
        totalPages: Math.ceil(total / parsedLimit),
        data: { users }
      });

    } catch (error) {
      logger.error('getUserList', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // POST /api/user/change-password 
  changePassword: async (req, res, next) => {
    try {
      const currentUserId = req.payload.id;
      const { oldPassword, newPassword } = req.body;

      const user = await User.findById(currentUserId);
      if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }

      const isMatch = await bcrypt.compare(oldPassword, user.password);
      if (!isMatch) {
        const error = new Error('Incorrect current password');
        error.statusCode = 401;
        throw error;
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      await user.save();

      res.json({
        success: true,
        message: 'Password changed successfully'
      });
    } catch (error) {
      logger.error('changePassword', { message: error.message, stack: error.stack });
      next(error);
    }
  }
};

module.exports = commonController;