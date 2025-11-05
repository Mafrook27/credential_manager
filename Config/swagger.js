const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Password Manager API',
      version: '1.0.0',
      description: `Secure credential management system API documentation with organized endpoints for authentication, user management, and credential operations.

**Default Admin Credentials (for testing):**
- Email: admin@example.com
- Password: Admin@123

**Getting Started:**
1. Login with admin credentials using POST /api/auth/login
2. Copy the JWT token from the response
3. Click "Authorize" button and enter: Bearer <your_token>
4. You can now test all admin endpoints`,
      contact: {
        name: 'API Support',
        email: 'support@company.com'
      }
    },
    servers: [
      {
        url:'http://localhost:5000', 
       description: 'Development server'
      },
       {
        url: process.env.BACKEND_URL || 'https://your-render-app.onrender.com',
        description: 'Production server'
      }
    ],
    tags: [
      {
        name: 'Authentication',
        description: 'User authentication and authorization endpoints (register, login, logout, password reset)'
      },
      {
        name: 'Common Routes',
        description: 'Shared endpoints accessible by both users and admins (user list, change password)'
      },
      {
        name: 'User Profile',
        description: 'User profile management operations (view, update, delete profile, statistics)'
      },
      {
        name: 'User Credentials',
        description: 'User credential management - CRUD operations for owned and shared credentials'
      },
      {
        name: 'Admin - User Management',
        description: 'Admin operations for managing users (view all users, update, delete, change roles, approve users)'
      },
      {
        name: 'Admin - Credential Management',
        description: 'Admin operations for managing all credentials across the system'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Enter your JWT token in the format: Bearer <token>'
        }
      }
    },
    security: [{
      bearerAuth: []
    }]
  },
  apis: ['./Routes/*.js', './Models/*.js'],
};

const specs = swaggerJsdoc(options);

module.exports = { swaggerUi, specs };