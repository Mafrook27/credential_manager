const Credential = require('../Models/Credential');
const RootInstance = require('../Models/Root_Ins');
const SubInstance = require('../Models/Sub_ins');
const Audit = require('../Models/Audit');
const User = require('../Models/CRED_User');
const logger = require('../util/Logger');
const { encrypt,decrypt,getDisplayCredential,getDecryptedCredential } = require('../util/cryptography');
const { getClientIP } = require('../util/clientIp');


const userCredentialController = {
  // GET /api/users/credentials
  // GET /api/users/credentials?search=<searchTerm>&type=<type>&page=<page>&limit=<limit>
  getCredentials: async (req, res, next) => {
    try {
      const userId = req.payload.id;
      const { search: rawSearch, type: rawType, page = 1, limit = 5 } = req.query;

      const search = Array.isArray(rawSearch) ? rawSearch[0] : rawSearch?.trim();
      const type = Array.isArray(rawType) ? rawType[0] : rawType?.trim();

      const currentUser = await User.findById(userId).lean();
      if (!currentUser) throw Object.assign(new Error('User not found'), { statusCode: 404 });

      const baseAccessFilter = {
        $or: [
          { createdBy: userId },
          { sharedWith: userId }
        ]
      };

      // ----- Dynamic Search Filters -----
      const orFilters = [];
      let rootQuery = {}; 

      if (search && type) {
        rootQuery.$and = [
          { serviceName: { $regex: search, $options: 'i' } },
          { type }
        ];
      } else if (search) {
        rootQuery.serviceName = { $regex: search, $options: 'i' };
      } else if (type) {
        rootQuery.type = type;
      }

      const subQuery = search
        ? { name: { $regex: search, $options: 'i' } }
        : null;

      const [rootInstances, subInstances] = await Promise.all([
        RootInstance.find(rootQuery).select('_id'),
        subQuery ? SubInstance.find(subQuery).select('_id') : []
      ]);

      const rootIds = rootInstances.map(r => r._id);
      const subIds = subInstances.map(s => s._id);

      if (rootIds.length > 0) orFilters.push({ rootInstance: { $in: rootIds } });
      if (subIds.length > 0) orFilters.push({ subInstance: { $in: subIds } });

      // ----- Final Filter -----
      const finalFilter = orFilters.length > 0
        ? { $and: [baseAccessFilter, { $or: orFilters }] }
        : baseAccessFilter;

      // ----- Pagination Setup -----
      const parsedLimit = Math.max(parseInt(limit), 1);
      const parsedPage = Math.max(parseInt(page), 1);
      const skip = (parsedPage - 1) * parsedLimit;

      // ----- Fetch Matching Credentials -----
      const [credentials, total] = await Promise.all([
        Credential.find(finalFilter)
          .populate('rootInstance', 'serviceName type')
          .populate('subInstance', 'name')
          .populate('createdBy', 'name email')
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parsedLimit)
          .lean(),

        Credential.countDocuments(finalFilter)
      ]);

      const displayCredentials = credentials.map(cred => getDisplayCredential(cred));

      // ----- Response -----
      res.json({
        success: true,
        count: credentials.length,
        total,
        page: parsedPage,
        limit: parsedLimit,
        totalPages: Math.ceil(total / parsedLimit),
        data: { credentials: displayCredentials }
      });

    } catch (error) {
      logger.error('getCredentials', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // GET /api/users/credentials/:id
  getCredential: async (req, res, next) => {
    try {
      const credentialId = req.params.id;
      const userId = req.payload.id;
      if (!userId ) {
             throw new Error('User ID is required');
            }
             if (!credentialId ) {
           throw new Error('Credential ID is required');
            }

         const credential = await Credential.findById(credentialId)
        .populate('rootInstance', 'serviceName type')
        .populate('subInstance', 'name')
        .populate('createdBy', 'name email')
        .populate('sharedWith', 'name email');

      if (!credential) {
        const error = new Error('Credential not found');
        error.statusCode = 404;
        throw error;
      }

      // Check access - user can only access if owner or shared with
      const isOwner = credential.createdBy._id.toString() === userId;
      const isShared = credential.sharedWith.some(user => user._id.toString() === userId);

      if (!isOwner && !isShared) {
        const error = new Error('Access denied');
        error.statusCode = 403;
        throw error;
      }

      // Log view if shared user (not owner)
      if (isShared && !isOwner) {
        await Audit.create({
          user: userId,
          credential: credentialId,
          credentialOwner: credential.createdBy._id,
          serviceName: credential.rootInstance.serviceName, 
          action: 'view',
          ipAddress: getClientIP(req).address,
          userAgent: req.get('User-Agent')
        });
      }

      const displaycred = getDisplayCredential(credential);
      res.json({
        success: true,
        data: { displaycred },
      });

    } catch (error) {
      logger.error('getCredential without filter', { message: error.message, stack: error.stack });
      next(error);
    }
  },




  // POST /api/users/credentials?rootId=<rootId>&subId=<subId>
  createCredential: async (req, res, next) => {
    try {
      const userId = req.payload.id;
      const { rootId, subId } = req.query;
      const { username, password, url, notes } = req.body; 

      const rootInstance = await RootInstance.findById(rootId);
      if (!rootInstance) {
        const error = new Error('Root instance not found');
        error.statusCode = 404;
        throw error;
      }

      const subInstance = await SubInstance.findOne({
        _id: subId,
        rootInstance: rootId
      });

      if (!subInstance) {
        const error = new Error('Sub-instance not found');
        error.statusCode = 404;
        throw error;
      }

       const existingCredential = await Credential.findOne({
      subInstance: subId,
      createdBy: userId 
    });

    if (existingCredential) {
      const error = new Error(
        `You already have a credential in "${rootInstance.serviceName} → ${subInstance.name}". ` +
        `Only one credential per subInstance folder is allowed. Please update your existing credential instead.`
      );
      error.statusCode = 409;
      error.existingCredentialId = existingCredential._id;
      throw error;
    }

      const credential = await Credential.create({
        rootInstance: rootId,
        subInstance: subId,
        createdBy: userId,
        username: encrypt(username),
        password: encrypt(password),
        url: url || '',
        notes: notes || ''
      });

      await SubInstance.findByIdAndUpdate(subId, {
        $push: { credentials: credential._id }
      });

      const populatedCredential = await Credential.findById(credential._id)
        .populate('rootInstance', 'serviceName type')
        .populate('subInstance', 'name')
        .populate('createdBy', 'name email');

      const displayCredential = getDisplayCredential(populatedCredential);

      await Audit.create({
        user: userId,
        credential: credential._id,
        credentialOwner: userId,
        serviceName: rootInstance.serviceName,
        action: 'create',
        ipAddress: getClientIP(req).address,
        userAgent: req.get('User-Agent')
      });

      res.status(201).json({
        success: true,
        data: { credential: displayCredential },
        message: 'Credential created successfully'
      });

    } catch (error) {
      logger.error('createCredential', { message: error.message, stack: error.stack });
      next(error);
    }
  },



  // PUT /api/users/credentials/:credId
  updateCredential: async (req, res, next) => {
    try {
      const userId = req.payload.id;
      const credId = req.params.credId;
      const { username, password, url, notes } = req.body;  

      const credential = await Credential.findById(credId).populate('rootInstance', 'serviceName type');

      if (!credential) {
        const error = new Error('Credential not found');
        error.statusCode = 404;
        throw error;
      }

  
      const isOwner = credential.createdBy.toString() === userId;
      if (!isOwner) {
        const error = new Error('Access denied');
        error.statusCode = 403;
        throw error;
      }

    
      if (username) credential.username = encrypt(username);
      if (password) credential.password = encrypt(password);
      if (url !== undefined) credential.url = url;
      if (notes !== undefined) credential.notes = notes;

      await credential.save();

      await Audit.create({
        user: userId,
        credential: credId,
        credentialOwner: credential.createdBy,
        serviceName: credential.rootInstance.serviceName,
        action: 'update',
        ipAddress: getClientIP(req).address,
        userAgent: req.get('User-Agent')
      });

      const updatedCredential = await Credential.findById(credId)
        .populate('rootInstance', 'serviceName type')
        .populate('subInstance', 'name')
        .populate('createdBy', 'name email')
        .populate('sharedWith', 'name email');

      const displayCredential = getDisplayCredential(updatedCredential);

      res.json({
        success: true,
        data: { credential: displayCredential },
        message: 'Credential updated successfully'
      });

    } catch (error) {
      logger.error('updateCredential', { message: error.message, stack: error.stack });
      next(error);
    }
  },
















  
  // DELETE /api/users/credentials/:id
  deleteCredential: async (req, res, next) => {
    try {
      const credentialId = req.params.id;
      const userId = req.payload.id;

      const credential = await Credential.findById(credentialId)
        .populate('rootInstance', 'serviceName type');

      if (!credential) {
        const error = new Error('Credential not found');
        error.statusCode = 404;
        throw error;
      }

      // Only owner can delete (admin logic removed)
      const isOwner = credential.createdBy.toString() === userId;
      if (!isOwner) {
        const error = new Error('Access denied');
        error.statusCode = 403;
        throw error;
      }

      await SubInstance.findByIdAndUpdate(
        credential.subInstance,
        { $pull: { credentials: credentialId } }
      );

      await Credential.findByIdAndDelete(credentialId);

      const subInstanceCreds = await Credential.countDocuments({ 
        subInstance: credential.subInstance 
      });
      
      if (subInstanceCreds === 0) {
        await SubInstance.findByIdAndDelete(credential.subInstance);
        
        const rootInstanceSubs = await SubInstance.countDocuments({ 
          rootInstance: credential.rootInstance._id 
        });
        
        if (rootInstanceSubs === 0) {
          await RootInstance.findByIdAndDelete(credential.rootInstance._id);
        }
      }

      await Audit.create({
        user: userId,
        credential: credentialId,
        credentialOwner: credential.createdBy,
        serviceName: credential.rootInstance.serviceName, 
        action: 'delete',
        ipAddress:getClientIP(req).address,
        userAgent: req.get('User-Agent')
      });

      res.json({
        success: true,
        message: 'Credential deleted successfully'
      });

    } catch (error) {
      next(error);
    }
  },

  // POST /api/users/credentials/:id/share
   
shareCredential: async (req, res, next) => {
  try {
    const credentialId = req.params.id;
    const userId = req.payload.id;
    const { userId: targetUserId } = req.body;
    const userRole = req.user?.role; // From authorize middleware

    const credential = await Credential.findById(credentialId)
      .populate('rootInstance', 'serviceName type');

    if (!credential) {
      const error = new Error('Credential not found');
      error.statusCode = 404;
      throw error;
    }

    // Owner can share, or admin can share any credential
    const isOwner = credential.createdBy.toString() === userId;
    const isAdmin = userRole === 'admin';
    
    if (!isOwner && !isAdmin) {
      const error = new Error('Access denied');
      error.statusCode = 403;
      throw error;
    }

    // Rest of your existing code remains the same...
    const targetUser = await User.findById(targetUserId);
    if (!targetUser) {
      const error = new Error('User not found');
      error.statusCode = 404;
      throw error;
    }

    if (targetUserId === userId) {
      const error = new Error('Cannot share with yourself');
      error.statusCode = 400;
      throw error;
    }

    if (credential.sharedWith.includes(targetUserId)) {
      const error = new Error('Already shared with this user');
      error.statusCode = 409;
      throw error;
    }

    credential.sharedWith.push(targetUserId);
    await credential.save();

    await Audit.create({
      user: userId,
      credential: credentialId,
      credentialOwner: credential.createdBy,
      serviceName: credential.rootInstance.serviceName, 
      action: 'share',
      targetUser: targetUserId,
      ipAddress: getClientIP(req).address,
      userAgent: req.get('User-Agent')
    });

    const updatedCredential = await Credential.findById(credentialId)
      .populate('sharedWith', 'name email');

    res.json({
      success: true,
      data: { credential: updatedCredential },
      message: 'Credential shared successfully'
    });

  } catch (error) {
    next(error);
  }
},


  // DELETE /api/users/credentials/:id/share/:userId

revokeAccess: async (req, res, next) => {
  try {
    const credentialId = req.params.id;
    const targetUserId = req.params.userId;
    const userId = req.payload.id;
    const userRole = req.user?.role; // From authorize middleware

    const credential = await Credential.findById(credentialId)
      .populate('rootInstance', 'serviceName type');

    if (!credential) {
      const error = new Error('Credential not found');
      error.statusCode = 404;
      throw error;
    }

    // Owner can revoke, or admin can revoke from any credential
    const isOwner = credential.createdBy.toString() === userId;
    const isAdmin = userRole === 'admin';
    
    if (!isOwner && !isAdmin) {
      const error = new Error('Access denied');
      error.statusCode = 403;
      throw error;
    }

    if (!credential.sharedWith.includes(targetUserId)) {
      const error = new Error('Not shared with this user');
      error.statusCode = 404;
      throw error;
    }

    credential.sharedWith = credential.sharedWith.filter(
      id => id.toString() !== targetUserId
    );
    await credential.save();

    await Audit.create({
      user: userId,
      credential: credentialId,
      credentialOwner: credential.createdBy,
      serviceName: credential.rootInstance.serviceName,
      action: 'revoke',
      targetUser: targetUserId,
      ipAddress: getClientIP(req).address,
      userAgent: req.get('User-Agent')
    });

    res.json({
      success: true,      message: 'Access revoked successfully'
    });

  } catch (error) {
    next(error);
  }
},


  // GET /api/users/credentials/:id/audit-logs
  getAuditLogs: async (req, res, next) => {
    try {
      const credentialId = req.params.id;
      const userId = req.payload.id;
      const { page = 1, limit = 5 } = req.query;

      const credential = await Credential.findById(credentialId);
      if (!credential) {
        const error = new Error('Credential not found');
        error.statusCode = 404;
        throw error;
      }

      // Only owner can view audit logs (admin logic removed)
      const isOwner = credential.createdBy.toString() === userId;
      if (!isOwner) {
        const error = new Error('Access denied');
        error.statusCode = 403;
        throw error;
      }

      const parsedLimit = Math.max(parseInt(limit), 1);
      const parsedPage = Math.max(parseInt(page), 1);
      const skip = (parsedPage - 1) * parsedLimit;

      const [auditLogs, total] = await Promise.all([
        Audit.find({ credential: credentialId })
          .populate('user', 'name email')
          .populate('targetUser', 'name email')
          .sort({ timestamp: -1 })
          .skip(skip)
          .limit(parsedLimit),

        Audit.countDocuments({ credential: credentialId })
      ]);

      res.json({
        success: true,
        count: auditLogs.length,
        total,
        page: parsedPage,
        limit: parsedLimit,
        totalPages: Math.ceil(total / parsedLimit),
        data: { auditLogs }
      });

    } catch (error) {
      next(error);
    }
  },

  // GET /api/users/credentials/:id/decrypt
  getCredentialDecrypted: async (req, res, next) => {
    try {
      const credentialId = req.params.id;
      const userId = req.payload.id;

      const credential = await Credential.findById(credentialId);
      if (!credential) {
        const error = new Error('Credential not found');
        error.statusCode = 404;
        throw error;
      }

      const isOwner = credential.createdBy.toString() === userId;
      const isSharedWith = credential.sharedWith?.map(id => id.toString()).includes(userId);

      if (!isOwner && !isSharedWith) {
        const error = new Error('Access denied');
        error.statusCode = 403;
        throw error;
      }

      const decryptedUsername = decrypt(credential.username);
      const decryptedPassword = decrypt(credential.password);

      const populatedCredential = await Credential.findById(credentialId)
        .populate('rootInstance', 'serviceName type')
        .populate('subInstance', 'name')
        .populate('createdBy', 'name email');

      const credentialObj = populatedCredential.toObject();
      const decryptedCredential = {
        ...credentialObj,
        username: decryptedUsername,
        password: decryptedPassword
      };

      await Audit.create({
        user: userId,
        credential: credentialId,
        credentialOwner: credential.createdBy,
        serviceName: credential.rootInstance?.serviceName || 'Unknown',
        action: 'decrypt',
        ipAddress:getClientIP(req).address,
        userAgent: req.get('User-Agent')
      });

      res.json({
        success: true,
        data: { credential: decryptedCredential }
      });

    } catch (error) {
      logger.error('getCredentialDecrypted', { message: error.message, stack: error.stack });
      next(error);
    }
  }
};

module.exports = userCredentialController;