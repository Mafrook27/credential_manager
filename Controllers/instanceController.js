const Credential = require('../models/Credential');
const RootInstance = require('../models/Root_Ins');
const SubInstance = require('../models/Sub_ins');
const Audit = require('../models/Audit');
const User = require('../models/CRED_User');
const mongoose = require('mongoose');
const logger = require('../util/Logger');
const { getClientIP } = require('../util/clientIp');

const instanceController = {

  // POST /api/instances
  createInstance: async (req, res, next) => {
    try {
      const userId = req.payload.id;
      const { serviceName } = req.body;

      const existingInstance = await RootInstance.findOne({
        serviceName: { $regex: `^${serviceName.trim()}$`, $options: 'i' }

      });

      if (existingInstance) {
        return res.status(200).json({
          success: true,
          data: {
            id: existingInstance._id,
            serviceName: existingInstance.serviceName,
            subInstancesCount: existingInstance.subInstances.length,
            createdAt: existingInstance.createdAt,
            isNew: false
          },
          message: 'Using existing service from list'
        });
      }

      const rootInstance = await RootInstance.create({
        serviceName: serviceName.trim(),
        createdBy: userId,
        subInstances: []
      });

      res.status(201).json({
        success: true,
        data: {
          id: rootInstance._id,
          serviceName: rootInstance.serviceName,
          subInstancesCount: 0,
          createdAt: rootInstance.createdAt,
          isNew: true
        },
        message: 'Service added to list successfully'
      });

    } catch (error) {
      logger.error('createInstance error', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // GET /api/instances
  // GET /api/instances?rootId=<instanceId>
  // GET /api/instances?rootName=<serviceName>
  // GET /api/instances?search=<searchTerm>
  listInstances: async (req, res, next) => {
    try {
      const { rootId, rootName, search } = req.query;

      // ===== CASE 1: Get by ID =====
      if (rootId) {
        if (!mongoose.Types.ObjectId.isValid(rootId)) {
          const error = new Error('Invalid root instance ID format');
          error.statusCode = 400;
          throw error;
        }

        const instance = await RootInstance.findById(rootId)
          .populate({
            path: 'subInstances',
            select: 'name createdAt isDeleted',
            match: { isDeleted: false }
          })
          .select('serviceName subInstances createdAt')
          .lean();

        if (!instance) {
          const error = new Error('Root instance not found');
          error.statusCode = 404;
          throw error;
        }

        return res.json({
          success: true,
          data: {
            rootInstanceId: instance._id,
            serviceName: instance.serviceName,
            subInstances: instance.subInstances.map(sub => ({
              subInstanceId: sub._id,
              name: sub.name,
              createdAt: sub.createdAt
            })),
            createdAt: instance.createdAt
          }
        });
      }

      if (rootName) {
        const instances = await RootInstance.find({
          serviceName: { $regex: rootName.trim(), $options: 'i' }
        })
          .populate({
            path: 'subInstances',
            select: 'name createdAt'
          })
          .select('serviceName subInstances createdAt')
          .sort({ serviceName: 1 })
          .lean();

        const formattedInstances = instances.map(instance => {
          // ✨ FILTER: Remove soft-deleted subinstances
          const activeSubInstances = instance.subInstances.filter(sub => !sub.isDeleted);

          return {
            rootInstanceId: instance._id,
            serviceName: instance.serviceName,
            subInstances: activeSubInstances.map(sub => ({
              subInstanceId: sub._id,
              name: sub.name,
              createdAt: sub.createdAt
            })),
            createdAt: instance.createdAt
          };
        });

        return res.json({
          success: true,
          data: formattedInstances,
          count: formattedInstances.length
        });
      }

      if (search) {
        const searchTerm = search.trim();

        // Search root instances
        const matchingRoots = await RootInstance.find({
          serviceName: { $regex: searchTerm, $options: 'i' }
        })
          .select('serviceName createdAt')
          .sort({ serviceName: 1 })
          .lean();

        // Search sub-instances
        const matchingSubs = await SubInstance.find({
          name: { $regex: searchTerm, $options: 'i' },
          isDeleted: false  // ✨ ADDED: exclude soft-deleted
        })
          .populate('rootInstance', 'serviceName')
          .select('name rootInstance createdAt')
          .sort({ name: 1 })
          .lean();

        const results = [];

        matchingRoots.forEach(root => {
          results.push({
            type: 'root',
            rootInstanceId: root._id,
            serviceName: root.serviceName,
            createdAt: root.createdAt
          });
        });

        matchingSubs.forEach(sub => {
          results.push({
            type: 'sub',
            subInstanceId: sub._id,
            subInstanceName: sub.name,
            rootInstanceId: sub.rootInstance._id,
            rootInstanceName: sub.rootInstance.serviceName,
            createdAt: sub.createdAt
          });
        });

        return res.json({
          success: true,
          data: results,
          count: results.length
        });
      }

      const instances = await RootInstance.find({})
        .select('serviceName createdAt')
        .sort({ serviceName: 1 })
        .lean();

      const formattedInstances = instances.map(instance => ({
        rootInstanceId: instance._id,
        serviceName: instance.serviceName,
        createdAt: instance.createdAt
      }));

      res.json({
        success: true,
        data: formattedInstances,
        count: formattedInstances.length
      });

    } catch (error) {
      logger.error('listInstances error', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // PUT /api/instances/:instanceId
  updateInstance: async (req, res, next) => {
    try {
      const userId = req.payload.id;
      const { instanceId } = req.params;
      const { serviceName } = req.body;

      const user = await User.findById(userId).select('role');
      const isAdmin = user.role === 'admin';
      if (!mongoose.Types.ObjectId.isValid(instanceId)) {
        const error = new Error('Invalid instance ID format');
        error.statusCode = 400;
        throw error;
      }

      if (!isAdmin) {
        const error = new Error('You don\'t have permission to edit services');
        error.statusCode = 403;
        throw error;
      }

      const instance = await RootInstance.findById(instanceId);

      if (!instance) {
        const error = new Error('Root instance not found');
        error.statusCode = 404;
        throw error;
      }

      if (serviceName && serviceName !== instance.serviceName) {
        const duplicate = await RootInstance.findOne({
          serviceName: { $regex: `^${serviceName.trim()}$`, $options: 'i' },
          _id: { $ne: instanceId }
        });

        if (duplicate) {
          const error = new Error('A service with this name already exists in list');
          error.statusCode = 400;
          throw error;
        }
      }

      if (serviceName) instance.serviceName = serviceName.trim();
      // ✨ REMOVED: type assignment

      await instance.save();

      res.json({
        success: true,
        data: {
          id: instance._id,
          serviceName: instance.serviceName,
          createdAt: instance.createdAt
        },
        message: 'Service updated successfully'
      });

    } catch (error) {
      logger.error('updateInstance error', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // DELETE /api/instances/:instanceId
  deleteInstance: async (req, res, next) => {
    try {
      const userId = req.payload.id;
      const { instanceId } = req.params;

      const user = await User.findById(userId).select('role');
      const isAdmin = user.role === 'admin';
      console.info("seeeeeeeee", isAdmin);
      if (!mongoose.Types.ObjectId.isValid(instanceId)) {
        const error = new Error('Invalid instance ID format');
        error.statusCode = 400;
        throw error;
      }

      // ✨ NEW: Regular users CANNOT delete
      if (!isAdmin) {
        const error = new Error('You don\'t have permission to delete services');
        error.statusCode = 403;
        throw error;
      }

      const instance = await RootInstance.findById(instanceId)
        .populate('subInstances');

      if (!instance) {
        const error = new Error('Root instance not found');
        error.statusCode = 404;
        throw error;
      }

      // ✨ NEW: Check for active sub-instances
      const activeSubInstances = instance.subInstances.filter(sub => !sub.isDeleted);

      if (activeSubInstances.length > 0) {
        const error = new Error(
          `Cannot delete service with ${activeSubInstances.length} active subinstance(s). Delete subinstance first.`
        );
        error.statusCode = 400;
        throw error;
      }

      const session = await mongoose.startSession();
      session.startTransaction();

      try {
        const credentials = await Credential.find({ rootInstance: instanceId }).session(session);

        const auditLogs = credentials.map(cred => ({
          user: userId,
          credential: cred._id,
          credentialOwner: cred.createdBy,
          serviceName: instance.serviceName,
          action: 'delete',
          ipAddress: getClientIP(req).address,
          userAgent: req.get('User-Agent'),
          timestamp: new Date()
        }));

        if (auditLogs.length > 0) {
          await Audit.insertMany(auditLogs, { session });
        }

        await Credential.deleteMany({ rootInstance: instanceId }).session(session);
        await SubInstance.deleteMany({ rootInstance: instanceId }).session(session);
        await RootInstance.findByIdAndDelete(instanceId).session(session);

        await session.commitTransaction();

        res.json({
          success: true,
          message: 'Service and all related data deleted successfully',
          deleted: {
            rootInstance: 1,
            subInstances: instance.subInstances.length,
            credentials: credentials.length
          }
        });

      } catch (error) {
        await session.abortTransaction();
        throw error;
      } finally {
        session.endSession();
      }

    } catch (error) {
      logger.error('deleteInstance error', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // POST /api/instances/:instanceId/sub-instances
  createSubInstance: async (req, res, next) => {
    try {
      const userId = req.payload.id;
      const { instanceId } = req.params;
      const { name } = req.body;

      if (!mongoose.Types.ObjectId.isValid(instanceId)) {
        const error = new Error('Invalid instance ID format');
        error.statusCode = 400;
        throw error;
      }

      const rootInstance = await RootInstance.findById(instanceId);

      if (!rootInstance) {
        const error = new Error('Root instance not found');
        error.statusCode = 404;
        throw error;
      }


      if (name.trim().toLowerCase() === rootInstance.serviceName.toLowerCase()) {
        const error = new Error(
          `Sub-instance name cannot be the same as service name "${rootInstance.serviceName}"`
        );
        error.statusCode = 400;
        throw error;
      }

      const existingSubInstance = await SubInstance.findOne({
        name: { $regex: `^${name.trim()}$`, $options: 'i' },
        rootInstance: instanceId,
        isDeleted: false  // ✨ Only check active subinstances
      });

      if (existingSubInstance) {
        return res.status(200).json({
          success: true,
          data: {
            id: existingSubInstance._id,
            name: existingSubInstance.name,
            rootInstanceId: instanceId,
            credentialsCount: existingSubInstance.credentials.length,
            createdAt: existingSubInstance.createdAt,
            isNew: false
          },
          message: 'Using existing subinstance from list'
        });
      }

      const subInstance = await SubInstance.create({
        name: name.trim(),
        rootInstance: instanceId,
        createdBy: userId,
        credentials: [],
        isDeleted: false
      });

      await RootInstance.findByIdAndUpdate(instanceId, {
        $push: { subInstances: subInstance._id }
      });

      res.status(201).json({
        success: true,
        data: {
          id: subInstance._id,
          name: subInstance.name,
          rootInstanceId: instanceId,
          credentialsCount: 0,
          createdAt: subInstance.createdAt,
          isNew: true
        },
        message: 'subinstance added to list successfully'
      });

    } catch (error) {
      logger.error('createSubInstance error', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // GET /api/instances/:instanceId/sub-instances
  listSubInstances: async (req, res, next) => {
    try {
      const { instanceId } = req.params;

      if (!mongoose.Types.ObjectId.isValid(instanceId)) {
        const error = new Error('Invalid instance ID format');
        error.statusCode = 400;
        throw error;
      }

      const rootInstance = await RootInstance.findById(instanceId)
        .select('serviceName createdBy')
        .populate('createdBy', 'name email')
        .lean();

      if (!rootInstance) {
        const error = new Error('Root instance not found');
        error.statusCode = 404;
        throw error;
      }

      // ✨ UPDATED: Filter out soft-deleted subinstances
      const subInstances = await SubInstance.find({
        rootInstance: instanceId,
        isDeleted: false  // ✨ Only get active subinstances
      })
        .populate('createdBy', 'name email')
        .sort({ name: 1 })
        .lean();

      const formattedSubInstances = subInstances.map(sub => ({
        id: sub._id,
        name: sub.name,
        credentialsCount: sub.credentials.length,
        createdBy: {
          id: sub.createdBy._id,
          name: sub.createdBy.name,
          email: sub.createdBy.email
        },
        createdAt: sub.createdAt
      }));

      res.json({
        success: true,
        rootInstance: {
          id: rootInstance._id,
          serviceName: rootInstance.serviceName,
          createdBy: {
            id: rootInstance.createdBy._id,
            name: rootInstance.createdBy.name,
            email: rootInstance.createdBy.email
          }
        },
        data: formattedSubInstances,
        count: formattedSubInstances.length
      });

    } catch (error) {
      logger.error('listSubInstances error', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // PUT /api/instances/:instanceId/sub-instances/:subId
  updateSubInstance: async (req, res, next) => {
    try {
      const userId = req.payload.id;
      const { instanceId, subId } = req.params;
      const { name } = req.body;

      const user = await User.findById(userId).select('role');
      const isAdmin = user.role === 'admin';

      if (!mongoose.Types.ObjectId.isValid(instanceId) || !mongoose.Types.ObjectId.isValid(subId)) {
        const error = new Error('Invalid instance or sub-instance ID format');
        error.statusCode = 400;
        throw error;
      }


      if (!isAdmin) {
        const error = new Error('You don\'t have permission to edit subinstances');
        error.statusCode = 403;
        throw error;
      }

      const rootInstance = await RootInstance.findById(instanceId);

      if (!rootInstance) {
        const error = new Error('Root instance not found');
        error.statusCode = 404;
        throw error;
      }

      const subInstance = await SubInstance.findOne({
        _id: subId,
        rootInstance: instanceId
      });

      if (!subInstance) {
        const error = new Error('Sub-instance not found');
        error.statusCode = 404;
        throw error;
      }


      if (subInstance.isDeleted) {
        const error = new Error('Cannot update deleted subinstance');
        error.statusCode = 400;
        throw error;
      }

      if (name && name.trim().toLowerCase() === rootInstance.serviceName.toLowerCase()) {
        const error = new Error(
          `Sub-instance name cannot be the same as service name "${rootInstance.serviceName}"`
        );
        error.statusCode = 400;
        throw error;
      }

      // Check for duplicates (excluding soft-deleted)
      if (name && name !== subInstance.name) {
        const duplicate = await SubInstance.findOne({
          name: { $regex: `^${name.trim()}$`, $options: 'i' },
          rootInstance: instanceId,
          _id: { $ne: subId }
        });

        if (duplicate) {
          const error = new Error('A subinstance with this name already exists in this service');
          error.statusCode = 400;
          throw error;
        }
      }

      subInstance.name = name.trim();
      await subInstance.save();

      res.json({
        success: true,
        data: {
          id: subInstance._id,
          name: subInstance.name,
          rootInstanceId: instanceId,
          createdAt: subInstance.createdAt
        },
        message: 'Subinstance updated successfully'
      });

    } catch (error) {
      logger.error('updateSubInstance error', { message: error.message, stack: error.stack });
      next(error);
    }
  },

  // DELETE /api/instances/:instanceId/sub-instances/:subId
  deleteSubInstance: async (req, res, next) => {
    try {
      const userId = req.payload.id;
      const { instanceId, subId } = req.params;
      const user = await User.findById(userId).select('role');
      const isAdmin = user.role === 'admin';
      if (!mongoose.Types.ObjectId.isValid(instanceId) || !mongoose.Types.ObjectId.isValid(subId)) {
        const error = new Error('Invalid instance or sub-instance ID format');
        error.statusCode = 400;
        throw error;
      }

      // ✨ NEW: Regular users CANNOT delete
      if (!isAdmin) {
        const error = new Error('You don\'t have permission to delete subinstance');
        error.statusCode = 403;
        throw error;
      }

      const subInstance = await SubInstance.findOne({
        _id: subId,
        rootInstance: instanceId
      });

      if (!subInstance) {
        const error = new Error('Sub-instance not found');
        error.statusCode = 404;
        throw error;
      }

      // ✨ NEW: Check if already soft-deleted
      if (subInstance.isDeleted) {
        const error = new Error('subinstance is already deleted');
        error.statusCode = 400;
        throw error;
      }

      const session = await mongoose.startSession();
      session.startTransaction();

      try {
        const rootInstance = await RootInstance.findById(instanceId).session(session);

        // ✨ NEW: SOFT DELETE instead of hard delete
        await SubInstance.findByIdAndUpdate(
          subId,
          {
            isDeleted: true,
            deletedAt: new Date(),
            deletedBy: userId
          },
          { session }
        );

        // ✨ Audit: Log soft delete (keep it minimal - no extra fields)
        await Audit.create([{
          user: userId,
          credential: null,  // No specific credential
          credentialOwner: userId,
          serviceName: rootInstance.serviceName,
          subInstanceName: subInstance.name,
          action: 'delete',  // Reuse credential delete action
          ipAddress: getClientIP(req).address,
          userAgent: req.get('User-Agent'),
          timestamp: new Date()
        }], { session });

        await session.commitTransaction();

        res.json({
          success: true,
          message: 'subinstance disabled successfully (soft delete triggered)',
          deleted: {
            subInstance: 1,
            isDeleted: true,
            frontendAction: 'Hide from UI, disable all operations'
          }
        });

      } catch (error) {
        await session.abortTransaction();
        throw error;
      } finally {
        session.endSession();
      }

    } catch (error) {
      logger.error('deleteSubInstance error', { message: error.message, stack: error.stack });
      next(error);
    }
  }

};

module.exports = instanceController;
