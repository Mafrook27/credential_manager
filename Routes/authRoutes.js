
/*

/api
├── /auth
│   ├── POST /register
│   ├── POST /login
│   └── POST /logout
│
├── /user
│   ├── GET /                    (current user profile)
│   ├── PUT /                    (update profile)
│   ├── POST /change-password    (change password)
│   ├── GET /stats               (user dashboard stats)
│   └── GET /audit-logs?from&to  (user's access history)
│
├── /credentials
│   ├── GET /?search&type&shared (search/filter credentials)
│   ├── POST /                   (create credential)
│   ├── GET /:id                 (get credential details)
│   ├── PUT /:id                 (update credential)
│   ├── DELETE /:id              (delete credential)
│   ├── POST /:id/share          (share credential)
│   ├── DELETE /:id/share/:userId (revoke access)
│   └── GET /:id/audit-logs      (credential access history)
│






-
// ├── /instances
// │   ├── GET /root-instances      (browse services)
// │   └── GET /sub-instances/:rootId (browse sub-services)
// │



*/







const auth= require('../Controllers/authController');
const express = require('express');
const router = express.Router();
const {authenticateToken: authcate} = require('../Middleware/authenticateToken');
const {validate} = require('../Middleware/validate');
const { registerSchema, loginSchema ,resetPasswordReqSchema,resetPasswordVerifySchema } = require('../validations/authValidation');
const { track } = require('../util/track');
/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - name
 *         - email
 *         - password
 *       properties:
 *         id:
 *           type: string
 *           description: Auto-generated ID
 *         name:
 *           type: string
 *           description: User's full name
 *         email:
 *           type: string
 *           format: email
 *           description: User's email address
 *         password:
 *           type: string
 *           format: password
 *           description: Hashed password
 *         role:
 *           type: string
 *           enum: [user, admin]
 *           default: user
 *         lastLogin:
 *           type: string
 *           format: date-time
 *         createdAt:
 *           type: string
 *           format: date-time
 *         updatedAt:
 *           type: string
 *           format: date-time
 *     AuthResponse:
 *       type: object
 *       properties:
 *         user:
 *           $ref: '#/components/schemas/User'
 *         token:
 *           type: string
 *           description: JWT token for authentication
 */







/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Register a new user account
 *     description: >
 *       Create a new user account. 
 *       User will be in pending status until approved by admin.
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - email
 *               - password
 *             properties:
 *               name:
 *                 type: string
 *                 minLength: 2
 *                 maxLength: 50
 *                 description: Full name of the user
 *                 example: "John Doe"
 *               email:
 *                 type: string
 *                 format: email
 *                 description: Email address (must be unique)
 *                 example: "john.doe@example.com"
 *               password:
 *                 type: string
 *                 minLength: 6
 *                 description: Password (minimum 6 characters)
 *                 example: "SecureP@ss123"
 *     responses:
 *       201:
 *         description: User registered successfully (pending admin approval)
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
 *                   example: "User registered successfully. Awaiting admin approval."
 *                 data:
 *                   type: object
 *                   properties:
 *                     user:
 *                       type: object
 *                       properties:
 *                         id:
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
 *                           example: false
 *       400:
 *         description: Bad request - Missing required fields or validation error
 *       409:
 *         description: Conflict - Email already exists
 *       500:
 *         description: Internal server error
 */



router.post('/register',track('USER_REGISTRATION'),validate(registerSchema) ,auth.register);

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login to get access token
 *     description: Authenticate user with email and password. Returns JWT token for subsequent requests.
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: Registered email address
 *                 example: "admin@example.com"
 *               password:
 *                 type: string
 *                 minLength: 6
 *                 description: User password
 *                 example: "Admin@123"
 *     responses:
 *       200:
 *         description: Login successful - Returns user data and JWT token
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
 *                         lastLogin:
 *                           type: string
 *                           format: date-time
 *                           example: "2024-01-15T10:30:00.000Z"
 *                     token:
 *                       type: string
 *                       description: JWT token - Use this in Authorization header as 'Bearer <token>'
 *                       example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjUwN2YxZjc3YmNmODZjZDc5OTQzOTAxMSIsImlhdCI6MTYzOTU3MjYwMH0.abc123"
 *       400:
 *         description: Bad request - Email and password are required
 *       401:
 *         description: Unauthorized - Invalid email or password
 *       403:
 *         description: Forbidden - User not verified/approved by admin
 *       500:
 *         description: Internal server error
 */


router.post('/login', track('USER_LOGIN'),validate(loginSchema), auth.login);

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: Logout current user
 *     description: Logout the authenticated user and invalidate the current session
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
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
 *                   example: "Logged out successfully"
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *       500:
 *         description: Server error
 */



router.post('/logout', track('USER_LOGOUT') ,authcate ,auth.logout);
/**
 * @swagger
 * /api/auth/reset-password:
 *   post:
 *     summary: Request password reset code
 *     description: Request a 6-digit password reset code. Code will be sent to the registered email address.
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: Registered email address
 *                 example: "john.doe@example.com"
 *     responses:
 *       200:
 *         description: Reset code sent successfully to email
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
 *                   example: "Password reset code sent to john.doe@example.com"
 *       400:
 *         description: Bad request - Invalid email format
 *       404:
 *         description: User not found - Email not registered
 *       500:
 *         description: Server error
 */


router.post('/reset-password',track('PASSWORD_RESET_REQUEST'),validate(resetPasswordReqSchema), auth.resetPasswordReq);

/**
 * @swagger
 * /api/auth/reset-password/verify:
 *   post:
 *     summary: Verify code and reset password
 *     description: Verify the 6-digit reset code and set a new password. Code expires after 10 minutes.
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - token
 *               - newPassword
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: Email address used in reset request
 *                 example: "john.doe@example.com"
 *               token:
 *                 type: string
 *                 description: 6-digit code received via email
 *                 example: "123456"
 *                 minLength: 6
 *                 maxLength: 6
 *               newPassword:
 *                 type: string
 *                 format: password
 *                 description: New password (minimum 6 characters)
 *                 example: "NewSecureP@ss456"
 *                 minLength: 6
 *     responses:
 *       200:
 *         description: Password reset successful - You can now login with new password
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
 *                   example: "Password reset successful. You can now login with your new password."
 *       400:
 *         description: Bad request - Invalid input or expired token
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
router.post('/reset-password/verify', track('PASSWORD_RESET_VERIFY') ,validate(resetPasswordVerifySchema), auth.resetPasswordverify);

                                             

module.exports = router;
