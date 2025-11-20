const User = require('../models/CRED_User');
const Credential = require('../models/Credential');
const SubInstance = require('../models/Sub_ins');
const Audit = require('../models/Audit');
const Session = require('../models/Session');
const bcrypt = require("bcryptjs");
const logger = require('../util/Logger');
const mongoose = require('mongoose');

const adminController = {



  //POST /api/admin/adduser
  createUser: async (req, res, next) => {
    try {
      const { name, email, password, role } = req.body;

      // Validation
      if (!name || !email || !password) {
        const error = new Error('Missing required fields: name, email, password');
        error.statusCode = 400;
        throw error;
      }

      // Check if user already exists
      const exists = await User.findOne({ email });
      if (exists) {
        const error = new Error('Email already exists');
        error.statusCode = 409;
        throw error;
      }

      // Hash password
      const hashed = await bcrypt.hash(password, 10);

      // Create user
      const user = await User.create({
        name,
        email,
        password: hashed,
        role: role || 'user',
        isVerified: true
      });

      // Response
      res.status(201).json({
        success: true,
        message: 'User created successfully',
        data: {
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            isVerified: user.isVerified,
            createdAt: user.createdAt
          }
        }
      });

      logger.info(`Admin created user: ${user.email} with role: ${user.role}`);
    } catch (error) {
      next(error);
    }
  },


  // GET /api/admin/users 
  getAllUsers: async (req, res, next) => {
    try {
      const { page = 1, limit = 10 } = req.query;

      const parsedLimit = Math.max(parseInt(limit), 1);
      const parsedPage = Math.max(parseInt(page), 1);
      const skip = (parsedPage - 1) * parsedLimit;

      const [users, total] = await Promise.all([
        User.find({ isDeleted: { $ne: true } })
          .select('-password')
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parsedLimit)
          .lean(),
        User.countDocuments({ isDeleted: { $ne: true } })
      ]);

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
      logger.error('getAllUsers', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // GET /api/admin/users/:id 
  getUserProfile: async (req, res, next) => {
    try {
      const { id } = req.params;

      const user = await User.findById(id).select('-password');
      if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }

      res.json({
        success: true,
        data: { user }
      });
    } catch (error) {
      logger.error('adminGetUserProfile', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // PUT /api/admin/users/:id
  updateUser: async (req, res, next) => {
    try {
      const { id } = req.params;
      const { name, email } = req.body;

      const user = await User.findById(id);
      if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }

      // Check if email exists (if changing email)
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
        message: 'User updated successfully'
      });
    } catch (error) {
      logger.error('adminUpdateUser', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // DELETE /api/admin/users/:id - Delete any user 
  deleteUser: async (req, res, next) => {
    try {
      const { id } = req.params;

      // Find user and check if already deleted
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

      // Prevent deleting admin users
      if (user.role === 'admin') {
        const error = new Error('Cannot delete admin users');
        error.statusCode = 403;
        throw error;
      }

      // Soft delete: mark as deleted instead of removing from database
      user.isDeleted = true;
      user.deletedAt = new Date();
      user.deletedBy = req.user._id;

      await user.save();

      // Invalidate all user sessions
      await Session.deleteMany({ userId: id });
      logger.info('userSessionsInvalidated', { userId: id, reason: 'deleted', performedBy: req.user._id });

      res.json({
        success: true,
        message: 'User disabled successfully'
      });

      logger.info('adminDeletedUser', { userId: id, performedBy: req.user._id });
    } catch (error) {
      logger.error('adminDeleteUser', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // PUT /api/admin/users/:id/role - Change user role 
  changeUserRole: async (req, res, next) => {
    try {
      const { id } = req.params;
      const { role } = req.body;

      const user = await User.findByIdAndUpdate(
        id,
        { role },
        { new: true, runValidators: true }
      ).select('-password');

      if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }

      res.json({
        success: true,
        data: { user },
        message: 'User role updated successfully'
      });
    } catch (error) {
      logger.error('changeUserRole', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // GET /api/admin/users/:id/stats - Get user stats 
  getUserStats: async (req, res, next) => {
    try {
      const { id } = req.params;

      // Check if user exists
      const user = await User.findById(id);
      if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }

      const stats = {
        totalUsers: await User.countDocuments(),
        totalCredentials: await Credential.countDocuments({ isDeleted: { $ne: true } }),
        activeUsers: await User.countDocuments({
          lastLogin: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        }),
        recentActivities: await Audit.countDocuments({
          timestamp: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
        })
      };

      res.json({
        success: true,
        data: { stats }
      });

      logger.info('adminFetchedStats', { targetUserId: id, performedBy: req.user._id });
    } catch (error) {
      logger.error('adminGetUserStats', { message: error.message, stack: error.stack });
      next(error);
    }
  },



  getStats: async (req, res, next) => {
    try {
      const { userId } = req.query;

      // ===== USER-SPECIFIC STATS =====
      if (userId) {
        // Check if user exists
        const user = await User.findById(userId);
        if (!user) {
          const error = new Error('User not found');
          error.statusCode = 404;
          throw error;
        }

        const stats = {
          // User credentials owned (exclude deleted)
          totalCredentials: await Credential.countDocuments({
            ownerId: userId,
            isDeleted: { $ne: true }
          }),

          // User's last login
          lastLogin: user.lastLogin,

          // User's recent activities (last 7 days)
          recentActivities: await Audit.countDocuments({
            userId: userId,
            timestamp: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
          }),

          // User info
          userName: user.name,
          userEmail: user.email,
          userRole: user.role,
          isVerified: user.isVerified,
          accountCreated: user.createdAt
        };

        return res.json({
          success: true,
          data: { stats }
        });
      }

      // ===== SYSTEM-WIDE STATS (Admin Dashboard) =====
      const stats = {
        // Total users in system (exclude deleted and admins)
        totalUsers: await User.countDocuments({
          isDeleted: { $ne: true },
          role: { $ne: 'admin' }
        }),

        // Total credentials in system (exclude deleted and those with deleted subInstances)
        totalCredentials: await Credential.countDocuments({
          isDeleted: { $ne: true },
          subInstance: { $in: await SubInstance.find({ isDeleted: false }).distinct('_id') }
        }),

        // Active users (exclude deleted, only verified and active, exclude admins)
        activeUsers: await User.countDocuments({
          isDeleted: { $ne: true },
          isVerified: true,
          isActive: true,
          role: { $ne: 'admin' }
        }),

        // Unverified users (exclude deleted and admins)
        unverifiedUsers: await User.countDocuments({
          isVerified: false,
          isDeleted: { $ne: true },
          role: { $ne: 'admin' }
        }),

        // Admin users
        adminUsers: await User.countDocuments({ role: 'admin' }),

        // Recent activities (last 7 days)
        recentActivities: await Audit.countDocuments({
          timestamp: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
        })
      };

      res.json({
        success: true,
        data: { stats }
      });

      logger.info('adminFetchedStats', {
        userId: userId || 'system',
        performedBy: req.user._id
      });

    } catch (error) {
      logger.error('adminGetStats', {
        message: error.message,
        stack: error.stack,
        userId: req.query.userId
      });
      next(error);
    }
  },



  // POST /api/admin/users/:id/change-password 
  changeUserPassword: async (req, res, next) => {
    try {
      const { id } = req.params;
      const { newPassword } = req.body;

      const user = await User.findById(id);
      if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      await user.save();

      res.json({
        success: true,
        message: 'User password changed successfully'
      });

      logger.info('adminChangedUserPassword', { targetUserId: id, performedBy: req.user._id });
    } catch (error) {
      logger.error('adminChangeUserPassword', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // Set User Verification Status
  approveUser: async (req, res, next) => {
    try {
      const { id } = req.params;
      const { isVerified } = req.body;

      // Validate request body
      if (typeof isVerified !== 'boolean') {
        const error = new Error('isVerified must be a boolean value');
        error.statusCode = 400;
        throw error;
      }

      const user = await User.findById(id);
      if (!user) {
        const error = new Error("User not found");
        error.statusCode = 404;
        throw error;
      }

      // Prevent modifying admin users
      if (user.role === 'admin') {
        const error = new Error('Cannot modify admin users');
        error.statusCode = 403;
        throw error;
      }

      // Check if already deleted
      if (user.isDeleted) {
        const error = new Error('Cannot modify deleted users');
        error.statusCode = 400;
        throw error;
      }

      // Set isVerified to explicit value
      user.isVerified = isVerified;

      // Clear rejection fields when approving
      if (isVerified) {
        user.rejectedAt = null;
        user.rejectedBy = null;
      }

      await user.save();

      // If rejecting user, invalidate all their sessions
      if (!isVerified) {
        await Session.deleteMany({ userId: id });
        logger.info('userSessionsInvalidated', { userId: id, reason: 'rejected', performedBy: req.user._id });
      }

      const action = isVerified ? 'approved' : 'rejected';
      res.status(200).json({
        success: true,
        message: `User ${user.email} ${action} successfully.`,
      });

      logger.info(`adminUser${action}`, { userId: id, performedBy: req.user._id });
    } catch (error) {
      logger.error('approveUser', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // Reject User (Mark as rejected without deleting)
  rejectUser: async (req, res, next) => {
    try {
      const { id } = req.params;

      const user = await User.findById(id);
      if (!user) {
        const error = new Error("User not found");
        error.statusCode = 404;
        throw error;
      }

      // Prevent modifying admin users
      if (user.role === 'admin') {
        const error = new Error('Cannot modify admin users');
        error.statusCode = 403;
        throw error;
      }

      // Check if already deleted
      if (user.isDeleted) {
        const error = new Error('Cannot modify deleted users');
        error.statusCode = 400;
        throw error;
      }

      // Mark as rejected
      user.rejectedAt = new Date();
      user.rejectedBy = req.user._id;
      user.isVerified = false;
      await user.save();

      // Invalidate all their sessions
      await Session.deleteMany({ userId: id });
      logger.info('userSessionsInvalidated', { userId: id, reason: 'rejected', performedBy: req.user._id });

      res.status(200).json({
        success: true,
        message: `User ${user.email} rejected successfully.`,
      });

      logger.info('adminUserRejected', { userId: id, performedBy: req.user._id });
    } catch (error) {
      logger.error('rejectUser', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // Undo User Rejection
  undoRejection: async (req, res, next) => {
    try {
      const { id } = req.params;

      const user = await User.findById(id);
      if (!user) {
        const error = new Error("User not found");
        error.statusCode = 404;
        throw error;
      }

      // Prevent modifying admin users
      if (user.role === 'admin') {
        const error = new Error('Cannot modify admin users');
        error.statusCode = 403;
        throw error;
      }

      // Check if already deleted
      if (user.isDeleted) {
        const error = new Error('Cannot modify deleted users');
        error.statusCode = 400;
        throw error;
      }

      // Clear rejection
      user.rejectedAt = null;
      user.rejectedBy = null;
      // Keep isVerified as false (still pending)
      await user.save();

      res.status(200).json({
        success: true,
        message: `Rejection undone for ${user.email}.`,
      });

      logger.info('adminUndoRejection', { userId: id, performedBy: req.user._id });
    } catch (error) {
      logger.error('undoRejection', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // Set User Active Status (Block/Unblock)
  blockUser: async (req, res, next) => {
    try {
      const { id } = req.params;
      const { isActive } = req.body;

      // Validate request body
      if (typeof isActive !== 'boolean') {
        const error = new Error('isActive must be a boolean value');
        error.statusCode = 400;
        throw error;
      }

      const user = await User.findById(id);
      if (!user) {
        const error = new Error("User not found");
        error.statusCode = 404;
        throw error;
      }

      // Prevent modifying admin users
      if (user.role === 'admin') {
        const error = new Error('Cannot modify admin users');
        error.statusCode = 403;
        throw error;
      }

      // Check if already deleted
      if (user.isDeleted) {
        const error = new Error('Cannot modify deleted users');
        error.statusCode = 400;
        throw error;
      }

      // Set isActive to explicit value
      user.isActive = isActive;
      await user.save();

      // If blocking user, invalidate all their sessions
      if (!isActive) {
        await Session.deleteMany({ userId: id });
        logger.info('userSessionsInvalidated', { userId: id, reason: 'blocked', performedBy: req.user._id });
      }

      const action = isActive ? 'unblocked' : 'blocked';
      res.status(200).json({
        success: true,
        message: `User ${user.email} ${action} successfully.`,
      });

      logger.info(`adminUser${action}`, { userId: id, performedBy: req.user._id });
    } catch (error) {
      logger.error('blockUser', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // GET /api/admin/access
  // Query params:
  //   search: string (matches user name/email/role)
  //   rootName: string (matches rootInstance.serviceName)
  //   subName: string (matches subInstance.name)
  //   accessGivenToMe: 'true' | 'false'
  //   accessGivenByMe: 'true' | 'false'
  //   page: number
  //   limit: number
  getUserAccess: async (req, res, next) => {
    try {
      const {
        search,
        rootName,
        subName,
        accessGivenToMe,
        accessGivenByMe,
        page = 1,
        limit = 10
      } = req.query;

      const parsedLimit = Math.max(parseInt(limit, 10) || 10, 1);
      const parsedPage = Math.max(parseInt(page, 10) || 1, 1);
      const skip = (parsedPage - 1) * parsedLimit;

      const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      const searchRegex = search
        ? new RegExp(escapeRegex(search.trim()), 'i')
        : null;
      const rootRegex = rootName
        ? new RegExp(escapeRegex(rootName.trim()), 'i')
        : null;
      const subRegex = subName
        ? new RegExp(escapeRegex(subName.trim()), 'i')
        : null;

      const isAccessGivenToMe = accessGivenToMe === 'true';
      const isAccessGivenByMe = accessGivenByMe === 'true';

      // 1) Base user match (cheap, no lookups yet)
      const userMatch = {};
      if (searchRegex) {
        userMatch.$or = [
          { name: { $regex: searchRegex } },
          { email: { $regex: searchRegex } },
          { role: { $regex: searchRegex } }
        ];
      }

      const pipeline = [
        { $match: userMatch },
        { $sort: { name: 1 } },

        // 2) Use facet so we only run heavy lookups for paginated users
        {
          $facet: {
            metadata: [
              { $count: 'total' },
              { $addFields: { page: parsedPage, limit: parsedLimit } }
            ],
            data: [
              { $skip: skip },
              { $limit: parsedLimit },

              // --- Roots & subs created by this user ---
              {
                $lookup: {
                  from: 'rootinstances',
                  let: { userId: '$_id' },
                  pipeline: [
                    {
                      $match: {
                        $expr: { $eq: ['$createdBy', '$$userId'] }
                      }
                    },
                    ...(rootRegex
                      ? [{ $match: { serviceName: { $regex: rootRegex } } }]
                      : []),
                    {
                      $lookup: {
                        from: 'subinstances',
                        let: { rootId: '$_id' },
                        pipeline: [
                          {
                            $match: {
                              $expr: { $eq: ['$rootInstance', '$$rootId'] }
                            }
                          },
                          ...(subRegex
                            ? [{ $match: { name: { $regex: subRegex } } }]
                            : []),
                          {
                            $project: {
                              subId: '$_id',
                              subName: '$name',
                              createdAt: 1
                            }
                          }
                        ],
                        as: 'subInstances'
                      }
                    },
                    {
                      $project: {
                        rootId: '$_id',
                        rootName: '$serviceName',
                        type: '$type',
                        createdAt: 1,
                        subInstances: 1,
                        subsCount: { $size: '$subInstances' }
                      }
                    }
                  ],
                  as: 'myInstances'
                }
              },

              // --- Credentials owned by this user ---
              {
                $lookup: {
                  from: 'credentials',
                  let: { userId: '$_id' },
                  pipeline: [
                    {
                      $match: {
                        $expr: {
                          $and: [
                            { $eq: ['$createdBy', '$$userId'] },
                            { $ne: ['$isDeleted', true] }
                          ]
                        }
                      }
                    },
                    {
                      $lookup: {
                        from: 'rootinstances',
                        localField: 'rootInstance',
                        foreignField: '_id',
                        as: 'rootData'
                      }
                    },
                    {
                      $lookup: {
                        from: 'subinstances',
                        localField: 'subInstance',
                        foreignField: '_id',
                        as: 'subData'
                      }
                    },
                    {
                      $lookup: {
                        from: 'c_users',
                        localField: 'sharedWith',
                        foreignField: '_id',
                        as: 'sharedWithUsers'
                      }
                    },
                    {
                      $addFields: {
                        rootName: { $arrayElemAt: ['$rootData.serviceName', 0] },
                        subName: { $arrayElemAt: ['$subData.name', 0] },
                        sharedWithCount: { $size: { $ifNull: ['$sharedWith', []] } }
                      }
                    },
                    ...(rootRegex
                      ? [{ $match: { rootName: { $regex: rootRegex } } }]
                      : []),
                    ...(subRegex
                      ? [{ $match: { subName: { $regex: subRegex } } }]
                      : []),
                    {
                      $project: {
                        credentialId: '$_id',
                        rootInstance: {
                          rootId: { $arrayElemAt: ['$rootData._id', 0] },
                          rootName: { $arrayElemAt: ['$rootData.serviceName', 0] }
                        },
                        subInstance: {
                          subId: { $arrayElemAt: ['$subData._id', 0] },
                          subName: { $arrayElemAt: ['$subData.name', 0] }
                        },
                        fields: '$fields',
                        notes: '$notes',
                        createdAt: 1,
                        sharedWithCount: 1,
                        sharedWith: {
                          $map: {
                            input: '$sharedWithUsers',
                            as: 'user',
                            in: {
                              userId: '$$user._id',
                              name: '$$user.name',
                              email: '$$user.email',
                              sharedAt: '$createdAt'
                            }
                          }
                        }
                      }
                    }
                  ],
                  as: 'myCredentials'
                }
              },

              // --- Credentials shared WITH this user ---
              {
                $lookup: {
                  from: 'credentials',
                  let: { userId: '$_id' },
                  pipeline: [
                    {
                      $match: {
                        $expr: {
                          $and: [
                            { $in: ['$$userId', '$sharedWith'] },
                            { $ne: ['$isDeleted', true] }
                          ]
                        }
                      }
                    },
                    {
                      $lookup: {
                        from: 'rootinstances',
                        localField: 'rootInstance',
                        foreignField: '_id',
                        as: 'rootData'
                      }
                    },
                    {
                      $lookup: {
                        from: 'subinstances',
                        localField: 'subInstance',
                        foreignField: '_id',
                        as: 'subData'
                      }
                    },
                    {
                      $lookup: {
                        from: 'c_users',
                        localField: 'createdBy',
                        foreignField: '_id',
                        as: 'ownerData'
                      }
                    },
                    {
                      $addFields: {
                        rootName: { $arrayElemAt: ['$rootData.serviceName', 0] },
                        subName: { $arrayElemAt: ['$subData.name', 0] }
                      }
                    },
                    ...(rootRegex
                      ? [{ $match: { rootName: { $regex: rootRegex } } }]
                      : []),
                    ...(subRegex
                      ? [{ $match: { subName: { $regex: subRegex } } }]
                      : []),
                    {
                      $project: {
                        credentialId: '$_id',
                        rootInstance: {
                          rootId: { $arrayElemAt: ['$rootData._id', 0] },
                          rootName: { $arrayElemAt: ['$rootData.serviceName', 0] },
                          type: { $arrayElemAt: ['$rootData.type', 0] }
                        },
                        subInstance: {
                          subId: { $arrayElemAt: ['$subData._id', 0] },
                          subName: { $arrayElemAt: ['$subData.name', 0] }
                        },
                        credentialData: {
                          fields: '$fields',
                          notes: '$notes'
                        },
                        sharedBy: {
                          userId: { $arrayElemAt: ['$ownerData._id', 0] },
                          name: { $arrayElemAt: ['$ownerData.name', 0] },
                          email: { $arrayElemAt: ['$ownerData.email', 0] }
                        },
                        sharedAt: '$createdAt'
                      }
                    }
                  ],
                  as: 'sharedAccess'
                }
              },

              // --- Build summary counts ---
              {
                $addFields: {
                  summary: {
                    rootsCreated: { $size: '$myInstances' },
                    subsCreated: {
                      $sum: {
                        $map: {
                          input: '$myInstances',
                          as: 'root',
                          in: { $ifNull: ['$$root.subsCount', 0] }
                        }
                      }
                    },
                    credentialsOwned: { $size: '$myCredentials' },
                    credentialsSharedWithMe: { $size: '$sharedAccess' },
                    credentialsIShared: {
                      $sum: {
                        $map: {
                          input: '$myCredentials',
                          as: 'cred',
                          in: { $ifNull: ['$$cred.sharedWithCount', 0] }
                        }
                      }
                    }
                  }
                }
              },

              // --- Filter by root/sub if requested ---
              ...(rootRegex || subRegex
                ? [
                  {
                    $addFields: {
                      hasMatchingAccess: {
                        $or: [
                          { $gt: [{ $size: '$myInstances' }, 0] },
                          { $gt: [{ $size: '$myCredentials' }, 0] },
                          { $gt: [{ $size: '$sharedAccess' }, 0] }
                        ]
                      }
                    }
                  },
                  { $match: { hasMatchingAccess: true } }
                ]
                : []),

              // --- Filter by accessGivenToMe / accessGivenByMe ---
              ...(isAccessGivenToMe
                ? [
                  {
                    $match: {
                      'summary.credentialsSharedWithMe': { $gt: 0 }
                    }
                  }
                ]
                : []),
              ...(isAccessGivenByMe
                ? [
                  {
                    $match: {
                      'summary.credentialsIShared': { $gt: 0 }
                    }
                  }
                ]
                : []),

              // --- Final shape for each user row ---
              {
                $project: {
                  userId: '$_id',
                  name: 1,
                  email: 1,
                  role: 1,
                  lastLogin: 1,
                  summary: 1,
                  myInstances: 1,
                  myCredentials: 1,
                  sharedAccess: 1
                }
              }
            ]
          }
        }
      ];

      const result = await User.aggregate(pipeline);

      const meta = result[0].metadata[0] || {
        total: 0,
        page: parsedPage,
        limit: parsedLimit
      };
      const rawUsers = result[0].data || [];

      const users = rawUsers.map((u) => ({
        userId: u.userId,
        userDetails: {
          name: u.name,
          email: u.email,
          role: u.role,
          lastLogin: u.lastLogin
        },
        summary: u.summary,
        myInstances: u.myInstances || [],
        myCredentials: u.myCredentials || [],
        sharedAccess: u.sharedAccess || []
      }));

      res.json({
        success: true,
        message: 'User access summary retrieved successfully',
        pagination: {
          page: meta.page,
          limit: meta.limit,
          totalUsers: meta.total,
          totalPages: Math.ceil((meta.total || 0) / meta.limit)
        },
        data: { users }
      });
    } catch (err) {
      console.error('getUserAccess error:', err);
      next(err);
    }
  },
}


module.exports = adminController;
