const Credential = require('../Models/Credential');
const RootInstance = require('../Models/Root_Ins');
const SubInstance = require('../Models/Sub_ins');
const Audit = require('../Models/Audit');
const User = require('../Models/CRED_User');
const logger = require('../util/Logger');
const { encrypt,decrypt,getDisplayCredential,getDecryptedCredential } = require('../util/cryptography');
const { getClientIP } = require('../util/clientIp');
const adminCredentialController = {
  // GET /api/admin/credentials
  // GET /api/admin/credentials?search=<searchTerm>&type=<type>&page=<page>&limit=<limit>
  getAllCredentials: async (req, res, next) => {
    try {
      const { search: rawSearch, type: rawType, page = 1, limit = 5 } = req.query;
  
      // Sanitize query parameters
      const search = Array.isArray(rawSearch) ? rawSearch[0]?.trim() : rawSearch?.trim();
      const type = Array.isArray(rawType) ? rawType[0]?.trim() : rawType?.trim();
  
      console.log('🔍 Search params:', { search, type, page, limit });
  
      // ✅ Admin can see all credentials (empty object = no restrictions)
      const baseAccessFilter = {};
  
      // ----- Dynamic Search Filters -----
      let rootQuery = {};
  
      // Build root instance query
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
  
      // Build sub instance query
      const subQuery = search
        ? { name: { $regex: search, $options: 'i' } }
        : null;
  
      // Fetch matching root and sub instances
      const [rootInstances, subInstances] = await Promise.all([
        RootInstance.find(rootQuery).select('_id'),
        subQuery ? SubInstance.find(subQuery).select('_id') : []
      ]);
  
      const rootIds = rootInstances.map(r => r._id);
      const subIds = subInstances.map(s => s._id);
  
      console.log('📊 Matching IDs:', { 
        rootIds: rootIds.length, 
        subIds: subIds.length 
      });
  
      // ✅ Build OR filters
      const orFilters = [];
      if (rootIds.length > 0) orFilters.push({ rootInstance: { $in: rootIds } });
      if (subIds.length > 0) orFilters.push({ subInstance: { $in: subIds } });
  
      // ✅ CRITICAL FIX: Handle case when search yields no results
      let finalFilter;
      
      if (search || type) {
        // If user is searching/filtering but nothing matches
        if (orFilters.length === 0 && search) {
          // ✅ Return NOTHING - use impossible condition
          finalFilter = { _id: null }; // MongoDB won't find any documents
        } else if (orFilters.length === 0 && type) {
          // Type filter with no matches
          finalFilter = { _id: null };
        } else {
          // Normal case: search/filter found matches
          finalFilter = { $and: [baseAccessFilter, { $or: orFilters }] };
        }
      } else {
        // No search/filter - return all credentials
        finalFilter = baseAccessFilter;
      }
  
      console.log('🎯 Final filter:', JSON.stringify(finalFilter, null, 2));
  
      // ----- Pagination Setup -----
      const parsedLimit = Math.max(parseInt(limit) || 5, 1);
      const parsedPage = Math.max(parseInt(page) || 1, 1);
      const skip = (parsedPage - 1) * parsedLimit;
  
      // ----- Fetch Matching Credentials -----
      const [credentials, total] = await Promise.all([
        Credential.find(finalFilter)
          .populate('rootInstance', 'serviceName type')
          .populate('subInstance', 'name')
          .populate('createdBy', 'name email')
          .populate('sharedWith', 'name email')
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parsedLimit)
          .lean(),
  
        Credential.countDocuments(finalFilter)
      ]);
  
      console.log('✅ Found credentials:', credentials.length);
  
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
      console.error('❌ getAllCredentials error:', error);
      logger.error('adminGetAllCredentials', { 
        message: error.message, 
        stack: error.stack 
      });
      next(error);
    }
  },
  

  // GET /api/admin/credentials/:id
  getCredential: async (req, res, next) => {
    try {
      const credentialId = req.params.id;

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

      // Admin can access any credential without access check
      const displaycred = getDisplayCredential(credential);
      res.json({
        success: true,
        data: { displaycred },
      });

    } catch (error) {
      logger.error('adminGetCredential', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // POST /api/admin/credentials?rootId=<rootId>&subId=<subId>
  createCredential: async (req, res, next) => {
  try {
    const userId = req.payload.id;
    const { rootId, subId } = req.query
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
    logger.error('adminCreateCredential', { message: error.message, stack: error.stack });
    next(error);
  }
},

  // PUT /api/admin/credentials/:credId
  updateCredential: async (req, res, next) => {
  try {
    const userId = req.payload.id;
    const {credId } = req.params; 
    const { username, password, url, notes } = req.body; 

  const credential = await Credential.findById(credId).populate('rootInstance', 'serviceName type');
    if (!credential) {
      const error = new Error('Credential not found');
      error.statusCode = 404;
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
    logger.error('adminUpdateCredential', { message: error.message, stack: error.stack });
    next(error);
  }
},
  

  // DELETE /api/admin/credentials/:id
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

      // Admin can delete any credential without ownership check
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

  // GET /api/admin/credentials/:id/decrypt
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

      // Admin can decrypt any credential without access check
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
      logger.error('adminGetCredentialDecrypted', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // GET /api/admin/credentials/:id/audit-logs
  getAuditLogs: async (req, res, next) => {
    try {
      const credentialId = req.params.id;
      const { page = 1, limit = 5 } = req.query;

      const credential = await Credential.findById(credentialId);
      if (!credential) {
        const error = new Error('Credential not found');
        error.statusCode = 404;
        throw error;
      }

      // Admin can view any credential's audit logs
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

  // GET /api/admin/audit-logs
  getAllAuditLogs: async (req, res, next) => {
    try {
      const { page = 1, limit = 20, userId: queryUserId, credentialId, credentialOwner } = req.query;

      const skip = (parseInt(page) - 1) * parseInt(limit);

      // ----- Dynamic Filter -----
      const filter = {};
      if (queryUserId) filter.user = queryUserId;
      if (credentialId) filter.credential = credentialId;
      if (credentialOwner) filter.credentialOwner = credentialOwner;

      // ----- Fetch Logs -----
      const [auditLogs, totalCount] = await Promise.all([
        Audit.find(filter)
          .sort({ timestamp: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .populate('credential', 'serviceName type')
          .populate('user', 'name email')
          .populate('targetUser', 'name email')
          .lean(),

        Audit.countDocuments(filter)
      ]);

      res.json({
        success: true,
        data: { auditLogs },
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: totalCount,
          totalPages: Math.ceil(totalCount / limit)
        }
      });

    } catch (error) {
      logger.error('getAllAuditLogs', { message: error.message, stack: error.stack });
      next(error);
    }
  }
};

module.exports = adminCredentialController;