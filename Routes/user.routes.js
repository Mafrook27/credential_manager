// const express = require('express');
// const router = express.Router();
// const userController = require('../Controllers/userController');
// const { CheckAccess } = require('../Middleware/CheckAccess');
// const { authenticateToken } = require('../Middleware/authenticateToken');
// const { validate } = require('../Middleware/validate');
// const { updateProfileSchema } = require('../validations/userValidation');

// router.get('/list', authenticateToken,CheckAccess, userController.getUserList);
// router.get('/', authenticateToken, userController.getAll);


// router.get('/:id', authenticateToken, userController.getProfile);



// router.put('/:id', authenticateToken, validate(updateProfileSchema), userController.updateProfile);



// router.delete('/:id', authenticateToken, userController.deleteUser);


// router.get('/:id/stats', authenticateToken, userController.getStats);




// router.put('/:id/role', authenticateToken, userController.changeUserRole);


// router.post('/:id/change_password', authenticateToken, userController.changePassword);

// module.exports = router;












// routes/userRoutes.js
const express = require('express');
const router = express.Router();
const userController = require('../Controllers/userController');
const commonController = require('../Controllers/commonController');
const userCredentialController = require('../Controllers/user.creditionalController');
const { authenticateToken } = require('../Middleware/authenticateToken');
const { CheckAccess } = require('../Middleware/CheckAccess');
const { requireUser } = require('../Middleware/Authoize');
const { validate } = require('../Middleware/validate');
const { updateProfileSchema, changePasswordSchema } = require('../validations/userValidation');
const { createCredentialSchema, updateCredentialSchema, shareCredentialSchema } = require('../validations/credentialValidation');
const { track } = require('../util/track');


router.use(authenticateToken, requireUser, CheckAccess);

router.get('/list', track('READ_USER_LIST'), commonController.getUserList);
router.post('/change-password', track('CHANGE_PASSWORD'), validate(changePasswordSchema), commonController.changePassword);


router.get('/credentials', track('READ_ALL_CREDENTIALS'), userCredentialController.getCredentials);
router.post('/credentials',
  track('CREATE_CREDENTIAL'),
  validate(createCredentialSchema),
  userCredentialController.createCredential
);

router.put('/credentials/:credId',
  track('UPDATE_CREDENTIAL'),
  validate(updateCredentialSchema),
  userCredentialController.updateCredential
);
router.get('/credentials/:id/decrypt', track('DECRYPT_CREDENTIAL'), userCredentialController.getCredentialDecrypted);
router.get('/credentials/:id/audit-logs', track('READ_CREDENTIAL_AUDIT_LOGS'), userCredentialController.getAuditLogs);
router.post('/credentials/:id/share', track('SHARE_CREDENTIAL'), validate(shareCredentialSchema), userCredentialController.shareCredential);
router.delete('/credentials/:id/share/:userId', track('REVOKE_CREDENTIAL_ACCESS'), userCredentialController.revokeAccess);
router.get('/credentials/:id', track('READ_CREDENTIAL'), userCredentialController.getCredential);
router.delete('/credentials/:id', track('DELETE_CREDENTIAL'), userCredentialController.deleteCredential);



router.get('/:id/stats', track('READ_USER_STATS'), userController.getStats);
router.get('/:id', track('READ_USER_PROFILE'), userController.getProfile);
router.put('/:id', track('UPDATE_USER_PROFILE'), validate(updateProfileSchema), userController.updateProfile);
router.delete('/:id', track('DELETE_USER'), userController.deleteUser);


module.exports = router;





/**
 * @swagger
 * tags:
 *   - name: Common Routes
 *     description: Shared endpoints accessible by both users and admins
 *   - name: User Profile
 *     description: User profile and account management
 *   - name: User Credentials
 *     description: User credential management - CRUD operations for owned and shared credentials
 */

/**
 * @swagger
 * /api/users/list:
 *   get:
 *     summary: Get user list for dropdowns
 *     description: Retrieves a simplified list of users (ID, name, email) for use in dropdowns and sharing features
 *     tags: [Common Routes]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User list retrieved successfully
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
 *                     users:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           _id:
 *                             type: string
 *                             example: "507f1f77bcf86cd799439011"
 *                           name:
 *                             type: string
 *                             example: "John Doe"
 *                           email:
 *                             type: string
 *                             example: "john.doe@example.com"
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Access denied
 *       404:
 *         description: User not found
 */

/**
 * @swagger
 * /api/users/change-password:
 *   post:
 *     summary: Change current user's password
 *     description: Allows authenticated users to change their own password by providing old and new passwords
 *     tags: [Common Routes]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - oldPassword
 *               - newPassword
 *             properties:
 *               oldPassword:
 *                 type: string
 *                 description: Current password
 *                 example: "OldP@ssw0rd123"
 *               newPassword:
 *                 type: string
 *                 description: New password (minimum 6 characters)
 *                 example: "NewSecureP@ssw0rd456"
 *     responses:
 *       200:
 *         description: Password changed successfully
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
 *                   example: "Password changed successfully"
 *       401:
 *         description: Unauthorized or incorrect current password
 *       403:
 *         description: Access denied
 *       404:
 *         description: User not found
 */

/**
 * @swagger
 * /api/users/{id}:
 *   get:
 *     summary: Get user profile
 *     description: Retrieve user profile information. Users can only access their own profile.
 *     tags: [User Profile]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID (must match authenticated user)
 *         example: "507f1f77bcf86cd799439011"
 *     responses:
 *       200:
 *         description: User profile retrieved successfully
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
 *                     user:
 *                       type: object
 *                       properties:
 *                         _id:
 *                           type: string
 *                           example: "507f1f77bcf86cd799439011"
 *                         name:
 *                           type: string
 *                           example: "John Doe"
 *                         email:
 *                           type: string
 *                           example: "john.doe@example.com"
 *                         role:
 *                           type: string
 *                           example: "user"
 *                         isVerified:
 *                           type: boolean
 *                           example: true
 *                         isActive:
 *                           type: boolean
 *                           example: true
 *                         createdAt:
 *                           type: string
 *                           format: date-time
 *                           example: "2024-01-01T00:00:00.000Z"
 *             example:
 *               success: true
 *               data:
 *                 user:
 *                   _id: "507f1f77bcf86cd799439011"
 *                   name: "John Doe"
 *                   email: "john.doe@example.com"
 *                   role: "user"
 *                   isVerified: true
 *                   isActive: true
 *                   createdAt: "2024-01-01T00:00:00.000Z"
 *       403:
 *         description: Access denied - Can only view own profile
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Access denied"
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "User not found"
 */

/**
 * @swagger
 * /api/users/{id}:
 *   put:
 *     summary: Update user profile
 *     description: Update user profile information (name, email). Users can only update their own profile.
 *     tags: [User Profile]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID (must match authenticated user)
 *         example: "507f1f77bcf86cd799439011"
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 description: Updated name
 *                 example: "John Updated"
 *               email:
 *                 type: string
 *                 format: email
 *                 description: Updated email address
 *                 example: "john.updated@example.com"
 *           example:
 *             name: "John Updated"
 *             email: "john.updated@example.com"
 *     responses:
 *       200:
 *         description: Profile updated successfully
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
 *                   example: "Profile updated successfully"
 *                 data:
 *                   type: object
 *                   properties:
 *                     user:
 *                       type: object
 *                       properties:
 *                         _id:
 *                           type: string
 *                           example: "507f1f77bcf86cd799439011"
 *                         name:
 *                           type: string
 *                           example: "John Updated Doe"
 *                         email:
 *                           type: string
 *                           example: "john.updated@example.com"
 *       403:
 *         description: Access denied - Can only update own profile
 *       404:
 *         description: User not found
 *       409:
 *         description: Email already exists
 */

/**
 * @swagger
 * /api/users/{id}:
 *   delete:
 *     summary: Delete user account
 *     description: Permanently delete user account. Users can only delete their own account.
 *     tags: [User Profile]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID (must match authenticated user)
 *         example: "507f1f77bcf86cd799439011"
 *     responses:
 *       200:
 *         description: User deleted successfully
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
 *                   example: "User deleted successfully"
 *             example:
 *               success: true
 *               message: "User deleted successfully"
 *       403:
 *         description: Access denied - Can only delete own account
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Access denied"
 *       404:
 *         description: User not found
 */

/**
 * @swagger
 * /api/users/{id}/stats:
 *   get:
 *     summary: Get user statistics
 *     description: Retrieve user dashboard statistics including total credentials, shared credentials, and recent activity. Users can only view their own stats.
 *     tags: [User Profile]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID (must match authenticated user)
 *         example: "507f1f77bcf86cd799439011"
 *     responses:
 *       200:
 *         description: User stats retrieved successfully
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
 *                     stats:
 *                       type: object
 *                       properties:
 *                         totalCredentials:
 *                           type: integer
 *                           description: Number of credentials owned by user
 *                           example: 15
 *                         sharedWithMe:
 *                           type: integer
 *                           description: Number of credentials shared with user
 *                           example: 5
 *                         recentActivities:
 *                           type: integer
 *                           description: Number of activities in last 7 days
 *                           example: 12
 *             example:
 *               success: true
 *               data:
 *                 stats:
 *                   totalCredentials: 15
 *                   sharedWithMe: 5
 *                   recentActivities: 12
 *       403:
 *         description: Access denied - Can only view own stats
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: "Access denied"
 *       404:
 *         description: User not found
 */
/**
 * @swagger
 * tags:
 *   - name: User Credentials
 *     description: User credential management (owned and shared credentials)
 */
/**
 * @swagger
 * /api/users/credentials:
 *   get:
 *     summary: Get all my credentials (owned and shared)
 *     description: Retrieve all active (non-deleted) credentials owned by or shared with the authenticated user. Excludes soft-deleted credentials and credentials in deleted subinstances. Supports search filtering.
 *     tags: [User Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search by service name or sub-instance name
 *         example: "Google"
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *         description: Page number
 *         example: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 5
 *         description: Items per page
 *         example: 10
 *     responses:
 *       200:
 *         description: Credentials retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 count:
 *                   type: integer
 *                   example: 5
 *                 total:
 *                   type: integer
 *                   example: 25
 *                 page:
 *                   type: integer
 *                   example: 1
 *                 limit:
 *                   type: integer
 *                   example: 10
 *                 totalPages:
 *                   type: integer
 *                   example: 3
 *                 data:
 *                   type: object
 *                   properties:
 *                     credentials:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           _id:
 *                             type: string
 *                             example: "507f1f77bcf86cd799439011"
 *                           serviceName:
 *                             type: string
 *                             example: "Google"
 *                           type:
 *                             type: string
 *                             example: "email"
 *                           subInstanceName:
 *                             type: string
 *                             example: "Work Account"
 *                           username:
 *                             type: string
 *                             example: "user@example.com"
 *                           url:
 *                             type: string
 *                             example: "https://mail.google.com"
 *                           isOwner:
 *                             type: boolean
 *                             example: true
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Access denied
 *       404:
 *         description: User not found
 */

/**
 * @swagger
 * /api/users/credentials:
 *   post:
 *     summary: Create a new credential
 *     description: Create a new credential entry with flexible fields. Requires rootId and subId as query parameters. All field values will be encrypted before storage. Only one credential per sub-instance is allowed per user. Cannot create credentials in soft-deleted subinstances.
 *     tags: [User Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: rootId
 *         required: true
 *         schema:
 *           type: string
 *         description: Root instance ID (service)
 *         example: "507f1f77bcf86cd799439011"
 *       - in: query
 *         name: subId
 *         required: true
 *         schema:
 *           type: string
 *         description: Sub-instance ID (subinstance)
 *         example: "507f1f77bcf86cd799439022"
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - fields
 *             properties:
 *               fields:
 *                 type: array
 *                 description: Array of credential fields (all values will be encrypted)
 *                 minItems: 1
 *                 items:
 *                   type: object
 *                   required:
 *                     - key
 *                     - value
 *                   properties:
 *                     key:
 *                       type: string
 *                       description: Field name/key
 *                       example: "username"
 *                     value:
 *                       type: string
 *                       description: Field value (will be encrypted)
 *                       example: "john.doe@company.com"
 *                 example:
 *                   - key: "username"
 *                     value: "john.doe@company.com"
 *                   - key: "password"
 *                     value: "SecureP@ssw0rd123"
 *                   - key: "api_key"
 *                     value: "sk_live_abc123xyz"
 *               notes:
 *                 type: string
 *                 description: Additional notes or comments (optional)
 *                 example: "Primary work email account"
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
 *                 message:
 *                   type: string
 *                   example: "Credential created successfully"
 *                 data:
 *                   type: object
 *                   properties:
 *                     credential:
 *                       type: object
 *                       properties:
 *                         _id:
 *                           type: string
 *                           example: "507f1f77bcf86cd799439011"
 *                         serviceName:
 *                           type: string
 *                           example: "Google"
 *                         username:
 *                           type: string
 *                           example: "john.doe@company.com"
 *       400:
 *         description: Bad request - Missing required fields
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Access denied
 *       404:
 *         description: User not found
 */

/**
 * @swagger
 * /api/users/credentials/{id}:
 *   get:
 *     summary: Get credential details (encrypted)
 *     description: Retrieve details of a specific credential. Password will be encrypted. Use /decrypt endpoint to view password. Cannot access soft-deleted credentials or credentials in deleted subinstances.
 *     tags: [User Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *         example: "507f1f77bcf86cd799439011"
 *     responses:
 *       200:
 *         description: Credential details retrieved successfully
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
 *                         _id:
 *                           type: string
 *                           example: "507f1f77bcf86cd799439011"
 *                         serviceName:
 *                           type: string
 *                           example: "Google"
 *                         type:
 *                           type: string
 *                           example: "email"
 *                         subInstanceName:
 *                           type: string
 *                           example: "Work Account"
 *                         username:
 *                           type: string
 *                           example: "john.doe@company.com"
 *                         password:
 *                           type: string
 *                           example: "[ENCRYPTED]"
 *                         url:
 *                           type: string
 *                           example: "https://mail.google.com"
 *                         notes:
 *                           type: string
 *                           example: "Primary work email"
 *                         createdAt:
 *                           type: string
 *                           format: date-time
 *                           example: "2024-01-15T10:30:00.000Z"
 *       403:
 *         description: Access denied - Not owner or not shared with you
 *       404:
 *         description: Credential not found
 */

/**
 * @swagger
 * /api/users/credentials/{credId}:
 *   put:
 *     summary: Update my credential
 *     description: Update a credential you own. Fields and notes can be updated. Service name and sub-instance cannot be changed. Only the owner can update credentials. Cannot update soft-deleted credentials or credentials in deleted subinstances.
 *     tags: [User Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: credId
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *         example: "507f1f77bcf86cd799439011"
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               fields:
 *                 type: array
 *                 description: Updated array of credential fields (all values will be encrypted)
 *                 minItems: 1
 *                 items:
 *                   type: object
 *                   required:
 *                     - key
 *                     - value
 *                   properties:
 *                     key:
 *                       type: string
 *                       description: Field name/key
 *                       example: "username"
 *                     value:
 *                       type: string
 *                       description: Field value (will be encrypted)
 *                       example: "updated.user@example.com"
 *                 example:
 *                   - key: "username"
 *                     value: "updated.user@example.com"
 *                   - key: "password"
 *                     value: "NewP@ssw0rd456"
 *               notes:
 *                 type: string
 *                 description: Updated notes
 *                 example: "Updated notes"
 *     responses:
 *       200:
 *         description: Credential updated successfully
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
 *                   example: "Credential updated successfully"
 *       403:
 *         description: Access denied - Only owner can update
 *       404:
 *         description: Credential not found
 */

/**
 * @swagger
 * /api/users/credentials/{id}:
 *   delete:
 *     summary: Delete my credential
 *     description: Soft delete a credential you own. The credential is marked as deleted but not permanently removed from the database. Only the owner can delete credentials. Creates an audit log entry.
 *     tags: [User Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID to delete
 *         example: "507f1f77bcf86cd799439011"
 *     responses:
 *       200:
 *         description: Credential deleted successfully
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
 *                   example: "Credential deleted successfully"
 *       400:
 *         description: Credential is already deleted
 *       403:
 *         description: Access denied - Only owner can delete
 *       404:
 *         description: Credential not found
 */

/**
 * @swagger
 * /api/users/credentials/{id}/decrypt:
 *   get:
 *     summary: Get decrypted credential
 *     description: Retrieve credential with decrypted password. This action is logged in audit logs for security. Cannot decrypt soft-deleted credentials.
 *     tags: [User Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *         example: "507f1f77bcf86cd799439011"
 *     responses:
 *       200:
 *         description: Decrypted credential retrieved successfully
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
 *                         _id:
 *                           type: string
 *                           example: "507f1f77bcf86cd799439011"
 *                         serviceName:
 *                           type: string
 *                           example: "Google"
 *                         username:
 *                           type: string
 *                           example: "john.doe@company.com"
 *                         password:
 *                           type: string
 *                           example: "SecureP@ssw0rd123"
 *                           description: "Decrypted password"
 *       403:
 *         description: Access denied - Not owner or not shared with you
 *       404:
 *         description: Credential not found
 */

/**
 * @swagger
 * /api/users/credentials/{id}/audit-logs:
 *   get:
 *     summary: Get credential access history
 *     description: View all access logs for a credential (who viewed, decrypted, modified it)
 *     tags: [User Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *         example: "507f1f77bcf86cd799439011"
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *         example: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 5
 *         example: 10
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
 *                 count:
 *                   type: integer
 *                   example: 5
 *                 total:
 *                   type: integer
 *                   example: 25
 *                 data:
 *                   type: object
 *                   properties:
 *                     auditLogs:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           action:
 *                             type: string
 *                             example: "decrypt"
 *                           user:
 *                             type: string
 *                             example: "John Doe"
 *                           timestamp:
 *                             type: string
 *                             example: "2024-01-15T10:30:00.000Z"
 *       403:
 *         description: Access denied
 *       404:
 *         description: Credential not found
 */

/**
 * @swagger
 * /api/users/credentials/{id}/share:
 *   post:
 *     summary: Share credential with another user
 *     description: Share a credential with another user. Only the owner (or admin) can share credentials. Shared users can view and decrypt but cannot modify or delete. Cannot share soft-deleted credentials.
 *     tags: [User Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID to share
 *         example: "507f1f77bcf86cd799439011"
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
 *                 description: ID of the user to share with
 *                 example: "507f1f77bcf86cd799439022"
 *     responses:
 *       200:
 *         description: Credential shared successfully
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
 *                   example: "Credential shared successfully with Jane Doe"
 *       400:
 *         description: Cannot share with yourself
 *       403:
 *         description: Access denied - Only owner can share
 *       404:
 *         description: Credential or user not found
 *       409:
 *         description: Already shared with this user
 */

/**
 * @swagger
 * /api/users/credentials/{id}/share/{userId}:
 *   delete:
 *     summary: Revoke shared access
 *     description: Remove a user's access to your shared credential. Only the owner (or admin) can revoke access.
 *     tags: [User Credentials]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Credential ID
 *         example: "507f1f77bcf86cd799439011"
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID to revoke access from
 *         example: "507f1f77bcf86cd799439022"
 *     responses:
 *       200:
 *         description: Access revoked successfully
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
 *                   example: "Access revoked successfully from Jane Doe"
 *       403:
 *         description: Access denied - Only owner can revoke
 *       404:
 *         description: Credential not found or not shared with this user
 */

/**
 * @swagger
 * components:
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 */

/**
 * @swagger
 * components:
 *   responses:
 *     Unauthorized:
 *       description: Unauthorized - No valid token provided
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               success:
 *                 type: boolean
 *                 example: false
 *               message:
 *                 type: string
 *                 example: "Unauthorized: No token provided"
 *     Forbidden:
 *       description: Forbidden - Insufficient permissions
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               success:
 *                 type: boolean
 *                 example: false
 *               message:
 *                 type: string
 *                 example: "Access denied: User not verified"
 *     NotFound:
 *       description: Resource not found
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               success:
 *                 type: boolean
 *                 example: false
 *               message:
 *                 type: string
 *                 example: "User not found"
 *     Conflict:
 *       description: Resource conflict
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               success:
 *                 type: boolean
 *                 example: false
 *               message:
 *                 type: string
 *                 example: "Email already exists"
 */
















