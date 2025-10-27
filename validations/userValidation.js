const Joi = require("joi");

const updateProfileSchema = Joi.object({
  name: Joi.string().min(2).max(50).optional().messages({
    'string.min': 'Name must be at least 2 characters long',
    'string.max': 'Name cannot exceed 50 characters'
  }),
  email: Joi.string().email().lowercase().trim().optional().messages({
    'string.email': 'Please provide a valid email address'
  })
});

const changePasswordSchema = Joi.object({
  oldPassword: Joi.string().min(6).required().messages({
    'string.min': 'Old password must be at least 6 characters long',
    'string.empty': 'Old password is required'
  }),
  newPassword: Joi.string().min(6).required().messages({
    'string.min': 'New password must be at least 6 characters long',
    'string.empty': 'New password is required'
  })
});

const auditLogsQuerySchema = Joi.object({
  from: Joi.date().iso().optional().messages({
    'date.format': 'From date must be in ISO format (YYYY-MM-DD)'
  }),
  to: Joi.date().iso().min(Joi.ref('from')).optional().messages({
    'date.format': 'To date must be in ISO format (YYYY-MM-DD)',
    'date.min': 'To date cannot be before from date'
  })
});

module.exports = { updateProfileSchema, changePasswordSchema, auditLogsQuerySchema };