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
// user.credentialController.js

  getCredentials: async (req, res, next) => {
    try {
      const userId = req.payload.id;
      const { search: rawSearch, page = 1, limit = 5 } = req.query;

      const search = Array.isArray(rawSearch) ? rawSearch[0] : rawSearch?.trim();
      // CHANGED: Removed type extraction

      const currentUser = await User.findById(userId).lean();
      if (!currentUser) throw Object.assign(new Error('User not found'), { statusCode: 404 });

      const baseAccessFilter = {
        $or: [
          { createdBy: userId },
          { sharedWith: userId }
        ],
        isDeleted: false  
      };

      const orFilters = [];
      let rootQuery = {};
      // CHANGED: Removed type filter logic

      if (search) {
        rootQuery.serviceName = { $regex: search, $options: 'i' };
      }

      const subQuery = search
        ? { name: { $regex: search, $options: 'i' }, isDeleted: false }  
        : { isDeleted: false }; 
    const [rootInstances, subInstances] = await Promise.all([
      RootInstance.find(rootQuery).select('_id'),
      subQuery ? SubInstance.find(subQuery).select('_id') : []
    ]);

    const rootIds = rootInstances.map(r => r._id);
    const subIds = subInstances.map(s => s._id);

    if (rootIds.length > 0) orFilters.push({ rootInstance: { $in: rootIds } });
    if (subIds.length > 0) orFilters.push({ subInstance: { $in: subIds } });

      const isSearchActive = search; 

      let finalFilter;
      if (isSearchActive && orFilters.length === 0) {
        finalFilter = { _id: null };
      } else if (orFilters.length > 0) {
        finalFilter = { $and: [baseAccessFilter, { $or: orFilters }] };
      } else {
        finalFilter = baseAccessFilter;
      }

      const parsedLimit = Math.max(parseInt(limit), 1);
      const parsedPage = Math.max(parseInt(page), 1);
      const skip = (parsedPage - 1) * parsedLimit;

      const [credentials, total] = await Promise.all([
        Credential.find(finalFilter)
          .populate('rootInstance', 'serviceName') 
          .populate({  
            path: 'subInstance',
            select: 'name isDeleted',
            match: { isDeleted: false } 
          })
          .populate('createdBy', 'name email')
          .populate('sharedWith', 'name email')
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parsedLimit)
          .lean(),

        Credential.countDocuments(finalFilter)
      ]);

      const activeCredentials = credentials.filter(cred => cred.subInstance !== null);  // ADDED: Filter soft-deleted

      const displayCredentials = activeCredentials.map(cred => {
        const isOwner = cred.createdBy._id.toString() === userId;

        return {
          ...getDisplayCredential(cred),
          isOwner
        };
      });

      res.json({
        success: true,
        count: activeCredentials.length,  // CHANGED: Use activeCredentials count
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

      if (!userId) {
        throw new Error('User ID is required');
      }
      if (!credentialId) {
        throw new Error('Credential ID is required');
      }

      const credential = await Credential.findById(credentialId)
        .populate('rootInstance', 'serviceName') 
        .populate('subInstance', 'name isDeleted') 
        .populate('createdBy', 'name email')
        .populate('sharedWith', 'name email');

      if (!credential) {
        const error = new Error('Credential not found');
        error.statusCode = 404;
        throw error;
      }

      // ADDED: Check if credential is soft-deleted
      if (credential.isDeleted) {
        const error = new Error('Cannot access deleted credential');
        error.statusCode = 403;
        throw error;
      }

      // ADDED: Check if subinstance is soft-deleted
      if (credential.subInstance && credential.subInstance.isDeleted) {
        const error = new Error('Cannot access credential in deleted subinstance');
        error.statusCode = 403;
        throw error;
      }

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
          subInstanceName: credential.subInstance?.name || 'N/A',
          action: 'view',
          ipAddress: getClientIP(req).address,
          userAgent: req.get('User-Agent'),
          timestamp: new Date()  // ADDED: timestamp field
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

      // ADDED: Validation checks
      if (!rootId || !subId) {
        const error = new Error('rootId and subId are required');
        error.statusCode = 400;
        throw error;
      }

      if (!username || !password) {
        const error = new Error('username and password are required');
        error.statusCode = 400;
        throw error;
      }

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


      if (subInstance.isDeleted) {
        const error = new Error('Cannot create credential in deleted subinstance');
        error.statusCode = 403;
        throw error;
      }

      const existingCredential = await Credential.findOne({
        subInstance: subId,
        createdBy: userId,
        isDeleted: false  // ADDED: Filter active credentials only
      });

    if (existingCredential) {
      const error = new Error(
        `You already have a credential in "${rootInstance.serviceName} → ${subInstance.name}". ` +
        `Only one credential per subinstance is allowed. Please update your existing credential instead.`
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
        .populate('rootInstance', 'serviceName')  // CHANGED: Removed type
        .populate('subInstance', 'name')
        .populate('createdBy', 'name email');

      const displayCredential = getDisplayCredential(populatedCredential);

      await Audit.create({
        user: userId,
        credential: credential._id,
        credentialOwner: userId,
        serviceName: rootInstance.serviceName,
        subInstanceName: subInstance.name,
        action: 'create',
        ipAddress: getClientIP(req).address,
        userAgent: req.get('User-Agent'),
        timestamp: new Date()  // ADDED: timestamp field
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

      const credential = await Credential.findById(credId)
        .populate('rootInstance', 'serviceName')  // CHANGED: Removed type
        .populate('subInstance', 'name isDeleted');  // CHANGED: Added isDeleted

      if (!credential) {
        const error = new Error('Credential not found');
        error.statusCode = 404;
        throw error;
      }

      // ADDED: Check if credential is soft-deleted
      if (credential.isDeleted) {
        const error = new Error('Cannot update deleted credential');
        error.statusCode = 403;
        throw error;
      }

      // ADDED: Check if subinstance is soft-deleted
      if (credential.subInstance && credential.subInstance.isDeleted) {
        const error = new Error('Cannot update credential in deleted subinstance');
        error.statusCode = 403;
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
        subInstanceName: credential.subInstance?.name || 'N/A',
        action: 'update',
        ipAddress: getClientIP(req).address,
        userAgent: req.get('User-Agent'),
        timestamp: new Date()  // ADDED: timestamp field
      });

      const updatedCredential = await Credential.findById(credId)
        .populate('rootInstance', 'serviceName')  // CHANGED: Removed type
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
        .populate('rootInstance', 'serviceName')  // CHANGED: Removed type
        .populate('subInstance', 'name');

      if (!credential) {
        const error = new Error('Credential not found');
        error.statusCode = 404;
        throw error;
      }

      // ADDED: Check if already soft-deleted
      if (credential.isDeleted) {
        const error = new Error('Credential is already deleted');
        error.statusCode = 400;
        throw error;
      }

      const isOwner = credential.createdBy.toString() === userId;
      if (!isOwner) {
        const error = new Error('Access denied');
        error.statusCode = 403;
        throw error;
      }

      // CHANGED: Soft delete instead of hard delete
      const now = new Date();
      await Credential.findByIdAndUpdate(credentialId, {
        isDeleted: true,
        deletedAt: now,
        deletedBy: userId
      });

      await Audit.create({
        user: userId,
        credential: credentialId,
        credentialOwner: credential.createdBy,
        serviceName: credential.rootInstance.serviceName,
        subInstanceName: credential.subInstance?.name || 'N/A',
        action: 'delete',
        ipAddress: getClientIP(req).address,
        userAgent: req.get('User-Agent'),
        timestamp: now 
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
      .populate('rootInstance', 'serviceName')
      .populate('subInstance', 'name');

    if (!credential) {
      const error = new Error('Credential not found');
      error.statusCode = 404;
      throw error;
    }

     if (credential.isDeleted) {
        const error = new Error('Cannot share deleted credential');
        error.statusCode = 403;
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
        subInstanceName: credential.subInstance?.name || 'N/A',
        action: 'share',
        targetUser: targetUserId,
        ipAddress: getClientIP(req).address,
        userAgent: req.get('User-Agent'),
        timestamp: new Date()  // ADDED: timestamp field
      });

    const updatedCredential = await Credential.findById(credentialId)
      .populate('sharedWith', 'name email');

      res.json({
        success: true,
        data: { credential: updatedCredential },
        message: 'Credential shared successfully'
      });

    } catch (error) {
      logger.error('shareCredential', { message: error.message, stack: error.stack });
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
        .populate('rootInstance', 'serviceName')  // CHANGED: Removed type
        .populate('subInstance', 'name');

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
      subInstanceName: credential.subInstance?.name || 'N/A',
      action: 'revoke',
      targetUser: targetUserId,
      ipAddress: getClientIP(req).address,
      userAgent: req.get('User-Agent'),
      timestamp : new Date(),
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
      logger.info('getAuditLogs', { message: error.message, stack: error.stack });
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

  
      if (credential.isDeleted) {
        const error = new Error('Cannot access deleted credential');
        error.statusCode = 403;
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
        .populate('rootInstance', 'serviceName')   // CHANGED: Removed type
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
        serviceName: populatedCredential.rootInstance?.serviceName || 'Unknown',
        subInstanceName: populatedCredential.subInstance?.name || 'N/A',
        action: 'decrypt',
        ipAddress: getClientIP(req).address,
        userAgent: req.get('User-Agent'),
        timestamp: new Date()  // ADDED: timestamp field
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