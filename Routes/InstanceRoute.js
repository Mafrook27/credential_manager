const express = require('express');
const router = express.Router();
const instanceController = require('../Controllers/instanceController');
const { authenticateToken } = require('../Middleware/authenticateToken');
const { CheckAccess } = require('../Middleware/CheckAccess');
const { requireUser } = require('../Middleware/Authoize');
const { validate } = require('../Middleware/validate');
const { 
  createInstanceSchema, 
  updateInstanceSchema,
  createSubInstanceSchema,
  updateSubInstanceSchema 
} = require('../validations/InstanceVal');
const { track } = require('../util/track');


router.use(authenticateToken, requireUser, CheckAccess);


//  root instance
router.post('/',track('CREATE_INSTANCE'), validate(createInstanceSchema), instanceController.createInstance);


router.get('/', track('READ_ALL_INSTANCES'), instanceController.listInstances);


router.put('/:instanceId',track('UPDATE_INSTANCE'), validate(updateInstanceSchema), instanceController.updateInstance);


router.delete('/:instanceId',  track('DELETE_INSTANCE'),  instanceController.deleteInstance);




// SUB-INSTANCE

// Create
router.post('/:instanceId/sub-instances', track('CREATE_SUB_INSTANCE'), validate(createSubInstanceSchema), instanceController.createSubInstance);

// List 
router.get( '/:instanceId/sub-instances', track('READ_SUB_INSTANCES'), instanceController.listSubInstances);

// Update 
router.put('/:instanceId/sub-instances/:subId', track('UPDATE_SUB_INSTANCE'),  validate(updateSubInstanceSchema), instanceController.updateSubInstance);

// Delete 
router.delete('/:instanceId/sub-instances/:subId', track('DELETE_SUB_INSTANCE'), instanceController.deleteSubInstance);



module.exports = router;



// ==================== SWAGGER DOCUMENTATION FOR INSTANCE ROUTES ====================

/**
 * @swagger
 * tags:
 *   name: Instance
 *   description: Root Instance and Sub-Instance management APIs
 */

/**
 * @swagger
 * /api/instances:
 *   post:
 *     summary: Create a new root instance (service)
 *     tags: [Instance]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - serviceName
 *             properties:
 *               serviceName:
 *                 type: string
 *                 description: Name of the service
 *                 example: "AWS"
 *               type:
 *                 type: string
 *                 description: Type of service
 *                 example: "cloud"
 *                 default: "other"
 *     responses:
 *       201:
 *         description: Service created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       example: "507f1f77bcf86cd799439011"
 *                     serviceName:
 *                       type: string
 *                       example: "AWS"
 *                     type:
 *                       type: string
 *                       example: "cloud"
 *                     subInstancesCount:
 *                       type: number
 *                       example: 0
 *                     createdAt:
 *                       type: string
 *                       format: date-time
 *                       example: "2025-10-17T12:00:00.000Z"
 *                     isNew:
 *                       type: boolean
 *                       example: true
 *                 message:
 *                   type: string
 *                   example: "Service added to list successfully"
 *       200:
 *         description: Using existing service from list
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       example: "507f1f77bcf86cd799439011"
 *                     serviceName:
 *                       type: string
 *                       example: "AWS"
 *                     type:
 *                       type: string
 *                       example: "cloud"
 *                     subInstancesCount:
 *                       type: number
 *                       example: 3
 *                     createdAt:
 *                       type: string
 *                       format: date-time
 *                       example: "2025-10-17T12:00:00.000Z"
 *                     isNew:
 *                       type: boolean
 *                       example: false
 *                 message:
 *                   type: string
 *                   example: "Using existing service from list"
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *       403:
 *         description: Forbidden - Insufficient permissions
 */

/**
 * @swagger
 * /api/instances:
 *   get:
 *     summary: List all root instances or search/filter instances
 *     tags: [Instance]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: rootId
 *         schema:
 *           type: string
 *         description: Get specific root instance by ID
 *         example: "507f1f77bcf86cd799439011"
 *       - in: query
 *         name: rootName
 *         schema:
 *           type: string
 *         description: Filter by service name (case-insensitive partial match)
 *         example: "AWS"
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search across root instances and sub-instances
 *         example: "production"
 *     responses:
 *       200:
 *         description: List of instances retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       rootInstanceId:
 *                         type: string
 *                         example: "507f1f77bcf86cd799439011"
 *                       serviceName:
 *                         type: string
 *                         example: "AWS"
 *                       type:
 *                         type: string
 *                         example: "cloud"
 *                       createdAt:
 *                         type: string
 *                         format: date-time
 *                         example: "2025-10-17T12:00:00.000Z"
 *                 count:
 *                   type: number
 *                   example: 5
 *       400:
 *         description: Invalid request parameters
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *       404:
 *         description: Root instance not found (when using rootId)
 */

/**
 * @swagger
 * /api/instances/{instanceId}:
 *   put:
 *     summary: Update a root instance
 *     tags: [Instance]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: instanceId
 *         required: true
 *         schema:
 *           type: string
 *         description: Root instance ID
 *         example: "507f1f77bcf86cd799439011"
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               serviceName:
 *                 type: string
 *                 description: Updated service name
 *                 example: "AWS Cloud"
 *               type:
 *                 type: string
 *                 description: Updated service type
 *                 example: "cloud"
 *     responses:
 *       200:
 *         description: Service updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       example: "507f1f77bcf86cd799439011"
 *                     serviceName:
 *                       type: string
 *                       example: "AWS Cloud"
 *                     type:
 *                       type: string
 *                       example: "cloud"
 *                     createdAt:
 *                       type: string
 *                       format: date-time
 *                       example: "2025-10-17T12:00:00.000Z"
 *                 message:
 *                   type: string
 *                   example: "Service updated successfully"
 *       400:
 *         description: Validation error or duplicate service name
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *       403:
 *         description: Forbidden - Cannot update service in use by other users (non-admin)
 *       404:
 *         description: Root instance not found
 */

/**
 * @swagger
 * /api/instances/{instanceId}:
 *   delete:
 *     summary: Delete a root instance and all related data
 *     tags: [Instance]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: instanceId
 *         required: true
 *         schema:
 *           type: string
 *         description: Root instance ID
 *         example: "507f1f77bcf86cd799439011"
 *     responses:
 *       200:
 *         description: Service and all related data deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Service and all related data deleted successfully"
 *                 deleted:
 *                   type: object
 *                   properties:
 *                     rootInstance:
 *                       type: number
 *                       example: 1
 *                     subInstances:
 *                       type: number
 *                       example: 3
 *                     credentials:
 *                       type: number
 *                       example: 10
 *       400:
 *         description: Invalid instance ID format
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *       403:
 *         description: Forbidden - Cannot delete service in use by other users (non-admin)
 *       404:
 *         description: Root instance not found
 */

/**
 * @swagger
 * /api/instances/{instanceId}/sub-instances:
 *   post:
 *     summary: Create a new sub-instance (folder) under a root instance
 *     tags: [Instance]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: instanceId
 *         required: true
 *         schema:
 *           type: string
 *         description: Root instance ID
 *         example: "507f1f77bcf86cd799439011"
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *             properties:
 *               name:
 *                 type: string
 *                 description: Name of the sub-instance (folder)
 *                 example: "Production Environment"
 *     responses:
 *       201:
 *         description: Folder created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       example: "507f1f77bcf86cd799439022"
 *                     name:
 *                       type: string
 *                       example: "Production Environment"
 *                     rootInstanceId:
 *                       type: string
 *                       example: "507f1f77bcf86cd799439011"
 *                     credentialsCount:
 *                       type: number
 *                       example: 0
 *                     createdAt:
 *                       type: string
 *                       format: date-time
 *                       example: "2025-10-17T12:00:00.000Z"
 *                     isNew:
 *                       type: boolean
 *                       example: true
 *                 message:
 *                   type: string
 *                   example: "Folder added to list successfully"
 *       200:
 *         description: Using existing subinstance from list
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       example: "507f1f77bcf86cd799439022"
 *                     name:
 *                       type: string
 *                       example: "Production Environment"
 *                     rootInstanceId:
 *                       type: string
 *                       example: "507f1f77bcf86cd799439011"
 *                     credentialsCount:
 *                       type: number
 *                       example: 5
 *                     createdAt:
 *                       type: string
 *                       format: date-time
 *                       example: "2025-10-17T12:00:00.000Z"
 *                     isNew:
 *                       type: boolean
 *                       example: false
 *                 message:
 *                   type: string
 *                   example: "Using existing subinstance from list"
 *       400:
 *         description: Validation error or sub-instance name same as service name
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *       404:
 *         description: Root instance not found
 */

/**
 * @swagger
 * /api/instances/{instanceId}/sub-instances:
 *   get:
 *     summary: List all sub-instances under a root instance
 *     tags: [Instance]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: instanceId
 *         required: true
 *         schema:
 *           type: string
 *         description: Root instance ID
 *         example: "507f1f77bcf86cd799439011"
 *     responses:
 *       200:
 *         description: List of sub-instances retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 rootInstance:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       example: "507f1f77bcf86cd799439011"
 *                     serviceName:
 *                       type: string
 *                       example: "AWS"
 *                     type:
 *                       type: string
 *                       example: "cloud"
 *                     createdBy:
 *                       type: object
 *                       properties:
 *                         id:
 *                           type: string
 *                           example: "507f1f77bcf86cd799439001"
 *                         name:
 *                           type: string
 *                           example: "John Doe"
 *                         email:
 *                           type: string
 *                           example: "john@example.com"
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                         example: "507f1f77bcf86cd799439022"
 *                       name:
 *                         type: string
 *                         example: "Production Environment"
 *                       credentialsCount:
 *                         type: number
 *                         example: 5
 *                       createdBy:
 *                         type: object
 *                         properties:
 *                           id:
 *                             type: string
 *                             example: "507f1f77bcf86cd799439001"
 *                           name:
 *                             type: string
 *                             example: "John Doe"
 *                           email:
 *                             type: string
 *                             example: "john@example.com"
 *                       createdAt:
 *                         type: string
 *                         format: date-time
 *                         example: "2025-10-17T12:00:00.000Z"
 *                 count:
 *                   type: number
 *                   example: 3
 *       400:
 *         description: Invalid instance ID format
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *       404:
 *         description: Root instance not found
 */

/**
 * @swagger
 * /api/instances/{instanceId}/sub-instances/{subId}:
 *   put:
 *     summary: Update a sub-instance (folder)
 *     tags: [Instance]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: instanceId
 *         required: true
 *         schema:
 *           type: string
 *         description: Root instance ID
 *         example: "507f1f77bcf86cd799439011"
 *       - in: path
 *         name: subId
 *         required: true
 *         schema:
 *           type: string
 *         description: Sub-instance ID
 *         example: "507f1f77bcf86cd799439022"
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *             properties:
 *               name:
 *                 type: string
 *                 description: Updated name of the sub-instance
 *                 example: "Production Environment Updated"
 *     responses:
 *       200:
 *         description: Folder updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       example: "507f1f77bcf86cd799439022"
 *                     name:
 *                       type: string
 *                       example: "Production Environment Updated"
 *                     rootInstanceId:
 *                       type: string
 *                       example: "507f1f77bcf86cd799439011"
 *                     createdAt:
 *                       type: string
 *                       format: date-time
 *                       example: "2025-10-17T12:00:00.000Z"
 *                 message:
 *                   type: string
 *                   example: "Folder updated successfully"
 *       400:
 *         description: Validation error, duplicate name, or name same as service name
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *       403:
 *         description: Forbidden - Cannot update subinstance in use by other users (non-admin)
 *       404:
 *         description: Root instance or sub-instance not found
 */

/**
 * @swagger
 * /api/instances/{instanceId}/sub-instances/{subId}:
 *   delete:
 *     summary: Delete a sub-instance (folder) and all related credentials
 *     tags: [Instance]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: instanceId
 *         required: true
 *         schema:
 *           type: string
 *         description: Root instance ID
 *         example: "507f1f77bcf86cd799439011"
 *       - in: path
 *         name: subId
 *         required: true
 *         schema:
 *           type: string
 *         description: Sub-instance ID
 *         example: "507f1f77bcf86cd799439022"
 *     responses:
 *       200:
 *         description: Folder and all related credentials deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Folder and all related credentials deleted successfully"
 *                 deleted:
 *                   type: object
 *                   properties:
 *                     subInstance:
 *                       type: number
 *                       example: 1
 *                     credentials:
 *                       type: number
 *                       example: 5
 *       400:
 *         description: Invalid instance or sub-instance ID format
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *       403:
 *         description: Forbidden - Cannot delete subinstance in use by other users (non-admin)
 *       404:
 *         description: Root instance or sub-instance not found
 */
