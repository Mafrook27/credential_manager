const Credential = require('../Models/Credential');
const RootInstance = require('../Models/Root_Ins');
const SubInstance = require('../Models/Sub_ins');
const Audit = require('../Models/Audit');
const User = require('../Models/CRED_User');
const mongoose = require('mongoose');
const logger = require('../util/Logger');
const { getClientIP } = require('../util/clientIp');

const instanceController = {

  // POST /api/instances
  createInstance: async (req, res, next) => {
    try {
      const userId = req.payload.id;
      const { serviceName, type } = req.body;

      const existingInstance = await RootInstance.findOne({
        serviceName: { $regex: `^${serviceName.trim()}$`, $options: 'i' },
        type: type || 'other'
      });

      if (existingInstance) {
        return res.status(200).json({
          success: true,
          data: {
            id: existingInstance._id,
            serviceName: existingInstance.serviceName,
            type: existingInstance.type,
            subInstancesCount: existingInstance.subInstances.length,
            createdAt: existingInstance.createdAt,
            isNew: false
          },
          message: 'Using existing service from list'
        });
      }

      const rootInstance = await RootInstance.create({
        serviceName: serviceName.trim(),
        type: type || 'other',
        createdBy: userId,
        subInstances: []
      });

      res.status(201).json({
        success: true,
        data: {
          id: rootInstance._id,
          serviceName: rootInstance.serviceName,
          type: rootInstance.type,
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
          select: 'name createdAt'
        })
        .select('serviceName type subInstances createdAt')
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
          type: instance.type,
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
        .select('serviceName type subInstances createdAt')
        .sort({ serviceName: 1 })
        .lean();

      const formattedInstances = instances.map(instance => ({
        rootInstanceId: instance._id,
        serviceName: instance.serviceName,
        type: instance.type,
        subInstances: instance.subInstances.map(sub => ({
          subInstanceId: sub._id,
          name: sub.name,
          createdAt: sub.createdAt
        })),
        createdAt: instance.createdAt
      }));

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
        .select('serviceName type createdAt')
        .sort({ serviceName: 1 })
        .lean();

      // Search sub-instances
      const matchingSubs = await SubInstance.find({
        name: { $regex: searchTerm, $options: 'i' }
      })
        .populate('rootInstance', 'serviceName type')
        .select('name rootInstance createdAt')
        .sort({ name: 1 })
        .lean();

     
      const results = [];

      
      matchingRoots.forEach(root => {
        results.push({
          type: 'root',
          rootInstanceId: root._id,
          serviceName: root.serviceName,
          rootType: root.type,
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
          rootType: sub.rootInstance.type,
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
      .select('serviceName type createdAt')
      .sort({ serviceName: 1 })
      .lean();

    const formattedInstances = instances.map(instance => ({
      rootInstanceId: instance._id,
      serviceName: instance.serviceName,
      type: instance.type,
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
      const { serviceName, type } = req.body;

      if (!mongoose.Types.ObjectId.isValid(instanceId)) {
        const error = new Error('Invalid instance ID format');
        error.statusCode = 400;
        throw error;
      }

      const user = await User.findById(userId).select('role');
      
      if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }

      const instance = await RootInstance.findById(instanceId);

      if (!instance) {
        const error = new Error('Root instance not found');
        error.statusCode = 404;
        throw error;
      }

        //find total count 
      const usersUsingThis = await Credential.distinct('createdBy', {
        rootInstance: instanceId
      });
      console.log(usersUsingThis);

      const otherUsersCount = usersUsingThis.filter(
        id => id.toString() !== userId
      ).length;
console.log(otherUsersCount);
console.log(user.role);

      if (user.role !== 'admin' && otherUsersCount > 0) {
        const error = new Error(
          `Cannot update: ${otherUsersCount} other user(s) are using this service. ` +
          `Changes would affect their other user credentials.`
        );
        error.statusCode = 403;
        throw error;
      }

  
      if (serviceName && serviceName !== instance.serviceName) {
        const duplicate = await RootInstance.findOne({
          serviceName: { $regex: `^${serviceName.trim()}$`, $options: 'i' },
          type: type || instance.type,
          _id: { $ne: instanceId }
        });

        if (duplicate) {
          const error = new Error('A service with this name and type already exists in list');
          error.statusCode = 400;
          throw error;
        }
      }

      if (serviceName) instance.serviceName = serviceName.trim();
      if (type) instance.type = type;

      await instance.save();

      res.json({
        success: true,
        data: {
          id: instance._id,
          serviceName: instance.serviceName,
          type: instance.type,
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

      if (!mongoose.Types.ObjectId.isValid(instanceId)) {
        const error = new Error('Invalid instance ID format');
        error.statusCode = 400;
        throw error;
      }

      const user = await User.findById(userId).select('role');
      if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }

      const instance = await RootInstance.findById(instanceId);

      if (!instance) {
        const error = new Error('Root instance not found');
        error.statusCode = 404;
        throw error;
      }

   
      const usersUsingThis = await Credential.distinct('createdBy', {
        rootInstance: instanceId
      });

      const otherUsersCount = usersUsingThis.filter(
        id => id.toString() !== userId
      ).length;

      // Block if others using it (unless admin)
      if (user.role !== 'admin' && otherUsersCount > 0) {
        const error = new Error(
          `Cannot delete: ${otherUsersCount} other user(s) have credentials in this service. ` +
          `Only admin can delete services in use by others.`
        );
        error.statusCode = 403;
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
        rootInstance: instanceId
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
        credentials: []
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
        message: 'Folder added to list successfully'
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
        .select('serviceName type createdBy')
        .populate('createdBy', 'name email')
        .lean();

      if (!rootInstance) {
        const error = new Error('Root instance not found');
        error.statusCode = 404;
        throw error;
      }

      const subInstances = await SubInstance.find({ rootInstance: instanceId })
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
          type: rootInstance.type,
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

      if (!mongoose.Types.ObjectId.isValid(instanceId) || !mongoose.Types.ObjectId.isValid(subId)) {
        const error = new Error('Invalid instance or sub-instance ID format');
        error.statusCode = 400;
        throw error;
      }

      const user = await User.findById(userId).select('role');
      if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
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

 
      if (name && name.trim().toLowerCase() === rootInstance.serviceName.toLowerCase()) {
        const error = new Error(
          `Sub-instance name cannot be the same as service name "${rootInstance.serviceName}"`
        );
        error.statusCode = 400;
        throw error;
      }

     
      const usersUsingThis = await Credential.distinct('createdBy', {
        subInstance: subId
      });

      const otherUsersCount = usersUsingThis.filter(
        id => id.toString() !== userId
      ).length;

  
      if (user.role !== 'admin' && otherUsersCount > 0) {
        const error = new Error(
          `Cannot update: ${otherUsersCount} other user(s) are using this subinstance. ` +
          `Changes would affect their other user credentials.`
        );
        error.statusCode = 403;
        throw error;
      }

      // Check for duplicates
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
        message: 'Folder updated successfully'
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

      if (!mongoose.Types.ObjectId.isValid(instanceId) || !mongoose.Types.ObjectId.isValid(subId)) {
        const error = new Error('Invalid instance or sub-instance ID format');
        error.statusCode = 400;
        throw error;
      }

      const user = await User.findById(userId).select('role');
      if (!user) {
        const error = new Error('User not found');
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

      // Check if others are using this list item
      const usersUsingThis = await Credential.distinct('createdBy', {
        subInstance: subId
      });

      const otherUsersCount = usersUsingThis.filter(
        id => id.toString() !== userId
      ).length;

      // Block if others using it (unless admin)
      if (user.role !== 'admin' && otherUsersCount > 0) {
        const error = new Error(
          `Cannot delete: ${otherUsersCount} other user(s) have credentials in this subinstance. ` +
          `Only admin can delete subinstances in use by others.`
        );
        error.statusCode = 403;
        throw error;
      }

      const session = await mongoose.startSession();
      session.startTransaction();

      try {
        const rootInstance = await RootInstance.findById(instanceId).session(session);

        const credentials = await Credential.find({ subInstance: subId }).session(session);

        const auditLogs = credentials.map(cred => ({
          user: userId,
          credential: cred._id,
          credentialOwner: cred.createdBy,
          serviceName: rootInstance.serviceName,
          action: 'delete',
          ipAddress: getClientIP(req).address,
          userAgent: req.get('User-Agent'),
          timestamp: new Date()
        }));

        if (auditLogs.length > 0) {
          await Audit.insertMany(auditLogs, { session });
        }

        await Credential.deleteMany({ subInstance: subId }).session(session);
        await RootInstance.findByIdAndUpdate(instanceId, { $pull: { subInstances: subId } }).session(session);
        await SubInstance.findByIdAndDelete(subId).session(session);

        await session.commitTransaction();

        res.json({
          success: true,
          message: 'Folder and all related credentials deleted successfully',
          deleted: {
            subInstance: 1,
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
      logger.error('deleteSubInstance error', { message: error.message, stack: error.stack });
      next(error);
    }
  }

};

module.exports = instanceController;
