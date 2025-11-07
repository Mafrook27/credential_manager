const User = require('../Models/CRED_User');
const Credential = require('../Models/Credential');
const Audit = require('../Models/Audit');
const bcrypt = require("bcryptjs");
const logger = require('../util/Logger');
const mongoose = require('mongoose');

const adminController ={



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
        User.find()
          .select('-password')
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parsedLimit)
          .lean(),
        User.countDocuments()
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

      const user = await User.findByIdAndDelete(id);
      if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }

      res.json({
        success: true,
        message: 'User deleted successfully'
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



getStats :async (req, res, next) => {
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
      // Total users in system
      totalUsers: await User.countDocuments(),
      
      // Verified users
      verifiedUsers: await User.countDocuments({ isVerified: true }),
      
      // Unverified users
      unverifiedUsers: await User.countDocuments({ isVerified: false }),
      
      // Total credentials in system (exclude deleted)
      totalCredentials: await Credential.countDocuments({ isDeleted: { $ne: true } }),
      
      // Active users (logged in last 30 days)
      activeUsers: await User.countDocuments({ 
        lastLogin: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } 
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

 approveUser: async (req, res, next) => {
  try {
    const { id } = req.params;

    const user = await User.findById(id);
    console.log("User to approve:", user); // Debugging line
    if (!user) {
      const error = new Error("User not found");
      error.statusCode = 404;
      throw error;
    }

    user.isVerified = true;
    await user.save();

    res.status(200).json({
      success: true,
      message: `User ${user.email} approved successfully.`,
    });

  } catch (error) {
    logger.error('addUseraccess ', { message: error.message, stack: error.stack });
    next(error);
  }
},

blockUser: async (req, res, next) => {
  try {
    const { id } = req.params;

    const user = await User.findById(id);
    if (!user) {
      const error = new Error("User not found");
      error.statusCode = 404;
      throw error;
    }

    user.isActive = false;
    await user.save();

    res.status(200).json({
      success: true,
      message: `User ${user.email} blocked successfully.`,
    });

    logger.info('blockUser', { userId: id, performedBy: req.user._id });
  } catch (error) {
    logger.error('blockUser', { message: error.message, stack: error.stack });
    next(error);
  }
},

unblockUser: async (req, res, next) => {
  try {
    const { id } = req.params;

    const user = await User.findById(id);
    if (!user) {
      const error = new Error("User not found");
      error.statusCode = 404;
      throw error;
    }

    user.isActive = true;
    await user.save();

    res.status(200).json({
      success: true,
      message: `User ${user.email} unblocked successfully.`,
    });

    logger.info('unblockUser', { userId: id, performedBy: req.user._id });
  } catch (error) {
    logger.error('unblockUser', { message: error.message, stack: error.stack });
    next(error);
  }
},

  // GET /api/admin/access
  // GET /api/admin/access?userName=<name>&rootName=<root>&subName=<sub>&type=<type>&search=<term>&accessGivenToMe=<true/false>&accessGivenByMe=<true/false>&page=<page>&limit=<limit>
getUserAccess: async (req, res, next) => {
  try {
    const {
      userName,
      rootName,
      subName,
      search,
      accessGivenToMe,
      accessGivenByMe,
      page = 1,
      limit = 10
    } = req.query;
    // CHANGED: Removed type parameter

    const parsedLimit = Math.max(parseInt(limit), 1);
    const parsedPage = Math.max(parseInt(page), 1);
    const skip = (parsedPage - 1) * parsedLimit;

    const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    const showMyInstances = accessGivenToMe !== 'true';
    const showSharedAccess = accessGivenByMe !== 'true';
    const isAccessGivenToMe = accessGivenToMe === 'true';
    const isAccessGivenByMe = accessGivenByMe === 'true';

    const userMatch = {};
    if (userName) {
      userMatch.name = { 
        $regex: escapeRegex(userName.trim()), 
        $options: 'i' 
      };
    }

    // CHANGED: Removed type from root conditions
    const rootMatchConditions = [];
    if (rootName) {
      rootMatchConditions.push({ 
        serviceName: { $regex: escapeRegex(rootName.trim()), $options: 'i' } 
      });
    }

    const subMatchConditions = [];
    if (subName) {
      subMatchConditions.push({ 
        name: { $regex: escapeRegex(subName.trim()), $options: 'i' } 
      });
    }

    const pipeline = [
      ...(Object.keys(userMatch).length > 0 ? [{ $match: userMatch }] : []),
      
      ...(showMyInstances ? [{
        $lookup: {
          from: 'rootinstances',
          let: { userId: '$_id' },
          pipeline: [
            { $match: { $expr: { $eq: ['$createdBy', '$$userId'] } } },
            ...(rootMatchConditions.length > 0 ? [{ $match: { $and: rootMatchConditions } }] : []),
            {
              $lookup: {
                from: 'subinstances',
                let: { rootId: '$_id' },
                pipeline: [
                  { $match: { $expr: { $eq: ['$rootInstance', '$$rootId'] } } },
                  { $match: { isDeleted: false } },  // ADDED: Filter soft-deleted subinstances
                  ...(subMatchConditions.length > 0 ? [{ $match: { $or: subMatchConditions } }] : []),
                  {
                    $lookup: {
                      from: 'credentials',
                      let: { subId: '$_id', userId: '$$userId' },
                      pipeline: [
                        {
                          $match: {
                            $expr: {
                              $and: [
                                { $eq: ['$subInstance', '$$subId'] },
                                { $eq: ['$createdBy', '$$userId'] },
                                { $ne: ['$isDeleted', true] }  // ADDED: Filter soft-deleted credentials
                              ]
                            }
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
                          $project: {
                            credentialId: '$_id',
                            username: '$username',
                            url: '$url',
                            notes: '$notes',
                            createdAt: 1,
                            sharedWithCount: { $size: '$sharedWithUsers' },
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
                      as: 'credentials'
                    }
                  },
                  {
                    $project: {
                      subId: '$_id',
                      subName: '$name',
                      createdAt: 1,
                      credentialsCount: { $size: '$credentials' },
                      credentials: 1
                    }
                  }
                ],
                as: 'subs'
              }
            },
            {
              $project: {
                rootId: '$_id',
                rootName: '$serviceName',
                createdAt: 1,
                subInstances: '$subs'
              }
            }
          ],
          as: 'myInstances'
        }
      }] : []),
      
      ...(showSharedAccess ? [{
        $lookup: {
          from: 'credentials',
          let: { userId: '$_id' },
          pipeline: [
            {
              $match: {
                $expr: {
                  $and: [
                    { $in: ['$$userId', '$sharedWith'] },
                    { $ne: ['$isDeleted', true] }  // ADDED: Filter soft-deleted credentials
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
                let: { subId: '$subInstance' },
                pipeline: [
                  { $match: { $expr: { $eq: ['$_id', '$$subId'] } } },
                  { $match: { isDeleted: false } }  // ADDED: Filter soft-deleted subinstances
                ],
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
            ...(rootMatchConditions.length > 0 ? [{
              $match: {
                $and: rootMatchConditions.map(cond => {
                  const key = Object.keys(cond)[0];
                  return { [`rootData.${key}`]: cond[key] };
                })
              }
            }] : []),
            ...(subMatchConditions.length > 0 ? [{
              $match: {
                $or: subMatchConditions.map(cond => {
                  const key = Object.keys(cond)[0];
                  return { [`subData.${key}`]: cond[key] };
                })
              }
            }] : []),
            {
              $project: {
                credentialId: '$_id',
                rootInstance: {
                  rootId: { $arrayElemAt: ['$rootData._id', 0] },
                  rootName: { $arrayElemAt: ['$rootData.serviceName', 0] }
                  // CHANGED: Removed type field
                },
                subInstance: {
                  subId: { $arrayElemAt: ['$subData._id', 0] },
                  subName: { $arrayElemAt: ['$subData.name', 0] }
                },
                credentialData: {
                  username: '$username',
                  url: '$url',
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
      }] : []),
      
      {
        $addFields: {
          summary: {
            rootsCreated: { $size: { $ifNull: ['$myInstances', []] } },
            subsCreated: {
              $sum: {
                $map: {
                  input: { $ifNull: ['$myInstances', []] },
                  as: 'root',
                  in: { $size: { $ifNull: ['$$root.subInstances', []] } }
                }
              }
            },
            credentialsOwned: {
              $sum: {
                $map: {
                  input: { $ifNull: ['$myInstances', []] },
                  as: 'root',
                  in: {
                    $sum: {
                      $map: {
                        input: { $ifNull: ['$$root.subInstances', []] },
                        as: 'sub',
                        in: { $size: { $ifNull: ['$$sub.credentials', []] } }
                      }
                    }
                  }
                }
              }
            },
            credentialsSharedWithMe: { $size: { $ifNull: ['$sharedAccess', []] } },
            credentialsIShared: {
              $sum: {
                $map: {
                  input: { $ifNull: ['$myInstances', []] },
                  as: 'root',
                  in: {
                    $sum: {
                      $map: {
                        input: { $ifNull: ['$$root.subInstances', []] },
                        as: 'sub',
                        in: {
                          $sum: {
                            $map: {
                              input: { $ifNull: ['$$sub.credentials', []] },
                              as: 'cred',
                              in: { $ifNull: ['$$cred.sharedWithCount', 0] }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      },
      
      {
        $project: {
          userId: '$_id',
          name: 1,
          email: 1,
          role: 1,
          summary: 1,
          myInstances: { $ifNull: ['$myInstances', []] },
          sharedAccess: { $ifNull: ['$sharedAccess', []] }
        }
      },

      ...(search ? [{
        $match: {
          $or: [
            { name: { $regex: escapeRegex(search.trim()), $options: 'i' } },
            { email: { $regex: escapeRegex(search.trim()), $options: 'i' } },
            { 'myInstances.rootName': { $regex: escapeRegex(search.trim()), $options: 'i' } },
            { 'myInstances.subInstances.subName': { $regex: escapeRegex(search.trim()), $options: 'i' } },
            { 'sharedAccess.rootInstance.rootName': { $regex: escapeRegex(search.trim()), $options: 'i' } },
            { 'sharedAccess.subInstance.subName': { $regex: escapeRegex(search.trim()), $options: 'i' } }
          ]
        }
      }] : []),

      { $sort: { name: 1 } },
      {
        $facet: {
          metadata: [
            { $count: 'total' },
            { $addFields: { page: parsedPage, limit: parsedLimit } }
          ],
          data: [
            { $skip: skip },
            { $limit: parsedLimit }
          ]
        }
      }
    ];

    const result = await User.aggregate(pipeline);

    const total = result[0].metadata[0]?.total || 0;
    const rawUsers = result[0].data || [];

    const users = rawUsers.map(user => ({
      userId: user.userId,
      userDetails: {
        name: user.name,
        email: user.email,
        role: user.role
      },
      summary: user.summary,
      ...(showMyInstances && { myInstances: user.myInstances }),
      ...(showSharedAccess && { sharedAccess: user.sharedAccess })
    }));

    let message = 'User access details retrieved successfully';
    let queryContext = {};

    if (isAccessGivenToMe && userName) {
      message = `Showing credentials shared WITH ${userName}`;
      queryContext = {
        filter: 'accessGivenToMe',
        description: `Credentials that other users have shared with ${userName}`,
        focusArea: 'sharedAccess'
      };
    } else if (isAccessGivenToMe) {
      message = 'Showing credentials shared WITH users';
      queryContext = {
        filter: 'accessGivenToMe',
        description: 'Credentials that other users have shared with these users',
        focusArea: 'sharedAccess'
      };
    } else if (isAccessGivenByMe && userName) {
      message = `Showing credentials shared BY ${userName}`;
      queryContext = {
        filter: 'accessGivenByMe',
        description: `Credentials that ${userName} has shared with other users`,
        focusArea: 'myInstances.credentials.sharedWith'
      };
    } else if (isAccessGivenByMe) {
      message = 'Showing credentials shared BY users';
      queryContext = {
        filter: 'accessGivenByMe',
        description: 'Credentials that these users have shared with others',
        focusArea: 'myInstances.credentials.sharedWith'
      };
    } else if (userName) {
      message = `Showing complete access details for ${userName}`;
      queryContext = {
        filter: 'none',
        description: `All instances, credentials, and shared access for ${userName}`,
        focusArea: 'all'
      };
    }

    res.json({
      success: true,
      message: message,
      queryContext: queryContext,
      pagination: {
        page: parsedPage,
        limit: parsedLimit,
        totalUsers: total,
        totalPages: Math.ceil(total / parsedLimit)
      },
      data: { users }
    });

  } catch (error) {
    logger.error('adminGetUserAccess', { message: error.message, stack: error.stack });
    next(error);
  }
}

}



module.exports = adminController;