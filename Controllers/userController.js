const User = require('../models/CRED_User');
const Credential = require('../models/Credential');
const Audit = require('../models/Audit');
const logger = require('../util/Logger');

const userController = {
  // GET /api/user/:id - User profile
  getProfile: async (req, res, next) => {
    try {
      const { id } = req.params;
      const currentUserId = req.payload.id;


      if (currentUserId !== id) {
        const error = new Error('Access denied');
        error.statusCode = 403;
        throw error;
      }

      const user = await User.findById(id).select('-password');
      if (!user || user.isDeleted) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }

      res.json({
        success: true,
        data: { user }
      });
    } catch (error) {
      logger.error('getProfile', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // PUT /api/user/:id - Update user profile (owner only)
  updateProfile: async (req, res, next) => {
    try {
      const { id } = req.params;
      const currentUserId = req.payload.id;
      const { name, email } = req.body;


      if (currentUserId !== id) {
        const error = new Error('Access denied');
        error.statusCode = 403;
        throw error;
      }

      const user = await User.findById(id);
      if (!user || user.isDeleted) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }


      if (email && email !== user.email) {
        const emailExists = await User.findOne({
          email,
          _id: { $ne: id }
        });
        if (emailExists) {
          const error = new Error('Email already exists');
          error.statusCode = 409;
          throw error;
        }
        user.email = email;
      }

      if (name !== undefined) user.name = name;

      await user.save();

      const updatedUser = await User.findById(id).select('-password');

      res.json({
        success: true,
        data: { user: updatedUser },
        message: 'Profile updated successfully'
      });
    } catch (error) {
      logger.error('updateProfile', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // DELETE /api/user/:id - Delete user (owner only) - Soft Delete
  deleteUser: async (req, res, next) => {
    try {
      const { id } = req.params;
      const currentUserId = req.payload.id;

      // Users can only delete themselves (admin logic removed)
      if (currentUserId !== id) {
        const error = new Error('Access denied');
        error.statusCode = 403;
        throw error;
      }

      const user = await User.findById(id);
      if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }

      if (user.isDeleted) {
        const error = new Error('User is already deleted');
        error.statusCode = 400;
        throw error;
      }

      // Soft delete: mark as deleted instead of removing from database
      user.isDeleted = true;
      user.deletedAt = new Date();
      user.deletedBy = currentUserId;

      await user.save();

      res.json({
        success: true,
        message: 'Account deleted successfully'
      });

      logger.info('deletedProfile', { userId: id, performedBy: currentUserId });
    } catch (error) {
      logger.error('deleteUser', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // GET /api/user/:id/stats - User personal stats only
  getStats: async (req, res, next) => {
    try {
      const { id } = req.params;
      const currentUserId = req.payload.id;


      if (currentUserId !== id) {
        const error = new Error('Access denied');
        error.statusCode = 403;
        throw error;
      }

      const stats = {
        totalCredentials: await Credential.countDocuments({
          createdBy: id,
          isDeleted: { $ne: true }
        }),
        sharedWithMe: await Credential.countDocuments({
          sharedWith: id,
          createdBy: { $ne: id },
          isDeleted: { $ne: true }
        }),
        recentActivities: await Audit.countDocuments({
          user: id,
          timestamp: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
        })

      };

      res.json({
        success: true,
        data: { stats }
      });

      logger.info('fetchedStats', { userId: currentUserId, targetUserId: id });
    } catch (error) {
      logger.error('getStats', { message: error.message, stack: error.stack });
      next(error);
    }
  }
};

module.exports = userController;