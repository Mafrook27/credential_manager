const creditonalController = require('../../Controllers/user.creditionalController');
const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../../Middleware/authenticateToken');
const { validate } = require('../../Middleware/validate');
const { createCredentialSchema, updateCredentialSchema, shareCredentialSchema } = require('../../validations/credentialValidation');



router.get('/', authenticateToken, creditonalController.getCredentials);
router.post('/', authenticateToken, validate(createCredentialSchema), creditonalController.createCredential);


// router.get('/audit-logs', authenticateToken, creditonalController.getAllAuditLogs);


router.get('/:id/decrypt', authenticateToken, creditonalController.getCredentialDecrypted);
router.get('/:id/audit-logs', authenticateToken, creditonalController.getAuditLogs);
router.post('/:id/share', authenticateToken, validate(shareCredentialSchema), creditonalController.shareCredential);
router.delete('/:id/share/:userId', authenticateToken, creditonalController.revokeAccess);


router.get('/:id', authenticateToken, creditonalController.getCredential);
router.put('/:id', authenticateToken, validate(updateCredentialSchema), creditonalController.updateCredential);
router.delete('/:id', authenticateToken, creditonalController.deleteCredential);
module.exports = router;




/**
 * @swagger
 * tags:
 *   - name: Credentials
 *     description: Credential management endpoints
 */

/**
 * @swagger
 * /api/users/credentials:
 *   get:
 *     summary: Get user's credentials
 *     tags: [Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search by service name or sub-instance name
 *       - in: query
 *         name: type
 *         schema:
 *           type: string
 *         description: Filter by credential type
 *       - in: query
 *         name: shared
 *         schema:
 *           type: string
 *           enum: [shared-with-me, shared-by-me]
 *         description: Filter shared credentials
 *     responses:
 *       200:
 *         description: List of user's credentials
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
 *                     credentials:
 *                       type: array
 *                       items:
 *                         type: object
 */

/**
 * @swagger
 * /api/admin/credentials:
 *   get:
 *     summary: Get all credentials (Admin only)
 *     tags: [Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search by service name or sub-instance name
 *       - in: query
 *         name: type
 *         schema:
 *           type: string
 *         description: Filter by credential type
 *     responses:
 *       200:
 *         description: List of all credentials with admin and others data
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
 *                     adminData:
 *                       type: array
 *                       items:
 *                         type: object
 *                     othersData:
 *                       type: array
 *                       items:
 *                         type: object
 *                 count:
 *                   type: integer
 *                   example: 25
 *       403:
 *         description: Admin access required
 */

/**
 * @swagger
 * /api/users/credentials/{id}:
 *   get:
 *     summary: Get credential details (encrypted)
 *     tags: [Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *     responses:
 *       200:
 *         description: Credential details (encrypted)
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
 *                     credential:
 *                       type: object
 *       403:
 *         description: Access denied
 *       404:
 *         description: Credential not found
 */

/**
 * @swagger
 * /api/admin/credentials/{id}:
 *   get:
 *     summary: Get any credential details (Admin only - encrypted)
 *     tags: [Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *     responses:
 *       200:
 *         description: Credential details (encrypted)
 *       403:
 *         description: Admin access required
 *       404:
 *         description: Credential not found
 */

/**
 * @swagger
 * /api/users/credentials/{id}/decrypt:
 *   get:
 *     summary: Get decrypted credential (Owner/Admin only)
 *     tags: [Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *     responses:
 *       200:
 *         description: Decrypted credential details
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
 *                     credential:
 *                       type: object
 *                       properties:
 *                         username:
 *                           type: string
 *                           example: "user@gmail.com"
 *                         password:
 *                           type: string
 *                           example: "plainpassword123"
 *       403:
 *         description: Access denied
 *       404:
 *         description: Credential not found
 */

/**
 * @swagger
 * /api/admin/credentials/{id}/decrypt:
 *   get:
 *     summary: Get any decrypted credential (Admin only)
 *     tags: [Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *     responses:
 *       200:
 *         description: Decrypted credential details
 *       403:
 *         description: Admin access required
 *       404:
 *         description: Credential not found
 */

/**
 * @swagger
 * /api/users/credentials:
 *   post:
 *     summary: Create new credential
 *     tags: [Credentials]
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
 *               - username
 *               - password
 *             properties:
 *               serviceName:
 *                 type: string
 *                 example: "Gmail"
 *               type:
 *                 type: string
 *                 example: "email"
 *               subInstanceName:
 *                 type: string
 *                 example: "Personal Account"
 *               username:
 *                 type: string
 *                 example: "user@gmail.com"
 *               password:
 *                 type: string
 *                 example: "securepassword123"
 *               url:
 *                 type: string
 *                 example: "https://mail.google.com"
 *               notes:
 *                 type: string
 *                 example: "Personal email account"
 *     responses:
 *       201:
 *         description: Credential created successfully
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
 *                     credential:
 *                       type: object
 *                 message:
 *                   type: string
 *                   example: "Credential created successfully"
 */

/**
 * @swagger
 * /api/users/credentials/{id}:
 *   put:
 *     summary: Update credential (Owner/Admin only)
 *     tags: [Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               serviceName:
 *                 type: string
 *                 example: "Gmail"
 *               type:
 *                 type: string
 *                 example: "email"
 *               subInstanceName:
 *                 type: string
 *                 example: "Personal Account"
 *               username:
 *                 type: string
 *                 example: "user@gmail.com"
 *               password:
 *                 type: string
 *                 example: "newpassword123"
 *               url:
 *                 type: string
 *                 example: "https://mail.google.com"
 *               notes:
 *                 type: string
 *                 example: "Updated personal email account"
 *     responses:
 *       200:
 *         description: Credential updated successfully
 *       403:
 *         description: Access denied
 *       404:
 *         description: Credential not found
 */

/**
 * @swagger
 * /api/admin/credentials/{id}:
 *   put:
 *     summary: Update any credential (Admin only)
 *     tags: [Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               serviceName:
 *                 type: string
 *                 example: "Gmail"
 *               type:
 *                 type: string
 *                 example: "email"
 *               subInstanceName:
 *                 type: string
 *                 example: "Personal Account"
 *               username:
 *                 type: string
 *                 example: "user@gmail.com"
 *               password:
 *                 type: string
 *                 example: "newpassword123"
 *               url:
 *                 type: string
 *                 example: "https://mail.google.com"
 *               notes:
 *                 type: string
 *                 example: "Updated personal email account"
 *     responses:
 *       200:
 *         description: Credential updated successfully
 *       403:
 *         description: Admin access required
 *       404:
 *         description: Credential not found
 */

/**
 * @swagger
 * /api/users/credentials/{id}:
 *   delete:
 *     summary: Delete credential (Owner/Admin only)
 *     tags: [Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *     responses:
 *       200:
 *         description: Credential deleted successfully
 *       403:
 *         description: Access denied
 *       404:
 *         description: Credential not found
 */

/**
 * @swagger
 * /api/admin/credentials/{id}:
 *   delete:
 *     summary: Delete any credential (Admin only)
 *     tags: [Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *     responses:
 *       200:
 *         description: Credential deleted successfully
 *       403:
 *         description: Admin access required
 *       404:
 *         description: Credential not found
 */

/**
 * @swagger
 * /api/users/credentials/{id}/share:
 *   post:
 *     summary: Share credential with another user (Owner/Admin only)
 *     tags: [Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - userId
 *             properties:
 *               userId:
 *                 type: string
 *                 example: "507f1f77bcf86cd799439012"
 *     responses:
 *       200:
 *         description: Credential shared successfully
 *       400:
 *         description: Cannot share with yourself
 *       403:
 *         description: Access denied
 *       404:
 *         description: Credential or user not found
 *       409:
 *         description: Already shared with this user
 */

/**
 * @swagger
 * /api/users/credentials/{id}/share/{userId}:
 *   delete:
 *     summary: Revoke shared access (Owner/Admin only)
 *     tags: [Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID to revoke access from
 *     responses:
 *       200:
 *         description: Access revoked successfully
 *       403:
 *         description: Access denied
 *       404:
 *         description: Credential not found or not shared with this user
 */

/**
 * @swagger
 * /api/users/credentials/{id}/audit-logs:
 *   get:
 *     summary: Get credential audit logs (Owner/Admin only)
 *     tags: [Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *     responses:
 *       200:
 *         description: Audit logs retrieved successfully
 *       403:
 *         description: Access denied
 *       404:
 *         description: Credential not found
 */

/**
 * @swagger
 * /api/admin/credentials/{id}/audit-logs:
 *   get:
 *     summary: Get any credential's audit logs (Admin only)
 *     tags: [Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *     responses:
 *       200:
 *         description: Audit logs retrieved successfully
 *       403:
 *         description: Admin access required
 *       404:
 *         description: Credential not found
 */



/**
 * @swagger
 * /credentials/audit-logs:
 *   get:
 *     summary: Get all audit logs (admin only)
 *     description: Returns all credential audit logs with pagination. Only accessible by users with the `admin` role.
 *     tags:
 *       - Audit Logs
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *         description: Page number for pagination
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 20
 *         description: Number of logs per page
 *       - in: query
 *         name: userId
 *         schema:
 *           type: string
 *         description: Filter logs by user ID
 *       - in: query
 *         name: credentialId
 *         schema:
 *           type: string
 *         description: Filter logs by credential ID
 *       - in: query
 *         name: credentialOwner
 *         schema:
 *           type: string
 *         description: Filter logs by credential owner ID
 *     responses:
 *       200:
 *         description: Audit logs retrieved successfully
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
 *                     auditLogs:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           _id:
 *                             type: string
 *                           action:
 *                             type: string
 *                           timestamp:
 *                             type: string
 *                             format: date-time
 *                           user:
 *                             type: object
 *                             properties:
 *                               _id:
 *                                 type: string
 *                               name:
 *                                 type: string
 *                           credential:
 *                             type: object
 *                             properties:
 *                               _id:
 *                                 type: string
 *                               serviceName:
 *                                 type: string
 *                               type:
 *                                 type: string
 *                 pagination:
 *                   type: object
 *                   properties:
 *                     page:
 *                       type: integer
 *                     limit:
 *                       type: integer
 *                     total:
 *                       type: integer
 *                     totalPages:
 *                       type: integer
 *       403:
 *         description: Access denied (non-admin)
 *       500:
 *         description: Server error
 */




