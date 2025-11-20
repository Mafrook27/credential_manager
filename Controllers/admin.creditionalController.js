const Credential = require('../models/Credential');
const RootInstance = require('../models/Root_Ins');
const SubInstance = require('../models/Sub_ins');
const Audit = require('../models/Audit');
const User = require('../models/CRED_User');
const logger = require('../util/Logger');
const { encrypt, decrypt, getDisplayCredential, getDecryptedCredential } = require('../util/cryptography');
const { getClientIP } = require('../util/clientIp');
const adminCredentialController = {
  // GET /api/admin/credentials
  // GET /api/admin/credentials?search=<searchTerm>&type=<type>&page=<page>&limit=<limit>
  getAllCredentials: async (req, res, next) => {
    try {
      const { search: rawSearch, page = 1, limit = 5 } = req.query;
      // CHANGED: Removed type parameter

      const search = Array.isArray(rawSearch) ? rawSearch[0]?.trim() : rawSearch?.trim();
      // CHANGED: Removed type extraction

      // Escape special regex characters to prevent regex errors
      const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      const baseAccessFilter = {
        isDeleted: false  // ADDED: Admin filter to exclude soft-deleted
      };

      const orFilters = [];
      let rootQuery = {};

      if (search) {
        const escapedSearch = escapeRegex(search);
        rootQuery.serviceName = { $regex: escapedSearch, $options: 'i' };
      }

      const subQuery = search
        ? { name: { $regex: escapeRegex(search), $options: 'i' }, isDeleted: false }  // CHANGED: Added isDeleted filter and escape regex
        : null;

      const [rootInstances, subInstances] = await Promise.all([
        RootInstance.find(rootQuery).select('_id'),
        subQuery ? SubInstance.find(subQuery).select('_id') : []
      ]);

      const rootIds = rootInstances.map(r => r._id);
      const subIds = subInstances.map(s => s._id);

      if (rootIds.length > 0) orFilters.push({ rootInstance: { $in: rootIds } });
      if (subIds.length > 0) orFilters.push({ subInstance: { $in: subIds } });

      let finalFilter;

      if (search && orFilters.length === 0) {
        finalFilter = { _id: null };
      } else if (orFilters.length > 0) {
        finalFilter = { $and: [baseAccessFilter, { $or: orFilters }] };
      } else {
        finalFilter = baseAccessFilter;
      }

      const parsedLimit = Math.max(parseInt(limit) || 5, 1);
      const parsedPage = Math.max(parseInt(page) || 1, 1);
      const skip = (parsedPage - 1) * parsedLimit;

      // ----- Fetch Matching Credentials -----
      const [credentials, total] = await Promise.all([
        Credential.find(finalFilter)
          .populate('rootInstance', 'serviceName')  // CHANGED: Removed type
          .populate({  // CHANGED: Changed from direct populate
            path: 'subInstance',
            select: 'name isDeleted',
            match: { isDeleted: false }  // ADDED: Filter active subinstances
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

      const displayCredentials = activeCredentials.map(cred => getDisplayCredential(cred));

      // Count only active credentials (excluding those with deleted subInstances)
      const activeTotal = await Credential.countDocuments({
        ...finalFilter,
        subInstance: { $in: await SubInstance.find({ isDeleted: false }).distinct('_id') }
      });

      res.json({
        success: true,
        count: activeCredentials.length,  // CHANGED: Use activeCredentials count
        total: activeTotal,  // CHANGED: Use active total count
        page: parsedPage,
        limit: parsedLimit,
        totalPages: Math.ceil(activeTotal / parsedLimit),  // CHANGED: Use active total
        data: { credentials: displayCredentials }
      });

    } catch (error) {
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
        .populate('rootInstance', 'serviceName')  // CHANGED: Removed type
        .populate('subInstance', 'name isDeleted')  // CHANGED: Added isDeleted
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
      const { fields, url, notes } = req.body;

      // ADDED: Validation
      if (!rootId || !subId) {
        const error = new Error('rootId and subId are required');
        error.statusCode = 400;
        throw error;
      }

      if (!fields || !Array.isArray(fields) || fields.length === 0) {
        const error = new Error('At least one credential field is required');
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

      // Encrypt all field values
      const encryptedFields = fields.map(field => ({
        key: field.key,
        value: encrypt(field.value)
      }));

      const credential = await Credential.create({
        rootInstance: rootId,
        subInstance: subId,
        createdBy: userId,
        fields: encryptedFields,
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
        subInstanceName: subInstance?.name || 'N/A',
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
      logger.error('adminCreateCredential', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  updateCredential: async (req, res, next) => {
    try {
      const userId = req.payload.id;
      const { credId } = req.params;
      const { fields, url, notes } = req.body;

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

      if (fields && Array.isArray(fields) && fields.length > 0) {
        credential.fields = fields.map(field => ({
          key: field.key,
          value: encrypt(field.value)
        }));
      }
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
      logger.error('adminUpdateCredential', { message: error.message, stack: error.stack });
      next(error);
    }
  },

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
      logger.error('adminDeleteCredential', { message: error.message, stack: error.stack });
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

      // ADDED: Check if credential is soft-deleted
      if (credential.isDeleted) {
        const error = new Error('Cannot access deleted credential');
        error.statusCode = 403;
        throw error;
      }

      // Decrypt all fields
      const decryptedFields = credential.fields.map(field => ({
        key: field.key,
        value: decrypt(field.value)
      }));

      const populatedCredential = await Credential.findById(credentialId)
        .populate('rootInstance', 'serviceName')  // CHANGED: Removed type
        .populate('subInstance', 'name')
        .populate('createdBy', 'name email');

      const credentialObj = populatedCredential.toObject();
      const decryptedCredential = {
        ...credentialObj,
        fields: decryptedFields
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
      logger.error('adminGetAuditLogs', { message: error.message, stack: error.stack });
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
          .populate({
            path: 'credential',
            populate: [
              {
                path: 'subInstance',
                select: 'name _id'
              },
              {
                path: 'rootInstance',
                select: 'serviceName _id'  // CHANGED: Removed type
              }
            ]
          })
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
      logger.error('adminGetAllAuditLogs', { message: error.message, stack: error.stack });
      next(error);
    }
  }
};

module.exports = adminCredentialController;