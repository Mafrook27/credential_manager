const Joi = require('joi');

const createCredentialSchema = Joi.object({

  rootId: Joi.string()
    .pattern(/^[0-9a-fA-F]{24}$/)
    .required()
    .messages({
      'string.empty': 'Root instance ID is required',
      'string.pattern.base': 'Invalid root instance ID format',
      'any.required': 'Root instance ID is required (use ?rootId=xxx in URL)'
    }),
  
  subId: Joi.string()
    .pattern(/^[0-9a-fA-F]{24}$/)
    .required()
    .messages({
      'string.empty': 'Sub-instance ID is required',
      'string.pattern.base': 'Invalid sub-instance ID format',
      'any.required': 'Sub-instance ID is required (use ?subId=xxx in URL)'
    }),
  

  username: Joi.string()
    .trim()
    .min(1)
    .max(100)
    .required()
    .messages({
      'string.empty': 'Username is required',
      'any.required': 'Username is required'
    }),
  
  password: Joi.string()
    .min(1)
    .required()
    .messages({
      'string.empty': 'Password is required',
      'any.required': 'Password is required'
    }),
  
  url: Joi.string()
    .uri()
    .optional()
    .allow('')
    .messages({
      'string.uri': 'Invalid URL format'
    }),
  
  notes: Joi.string()
    .max(500)
    .optional()
    .allow('')
    .messages({
      'string.max': 'Notes cannot exceed 500 characters'
    })
});


const updateCredentialSchema = Joi.object({
  username: Joi.string()
    .trim()
    .min(1)
    .max(100)
    .optional()
    .messages({
      'string.empty': 'Username cannot be empty'
    }),
  
  password: Joi.string()
    .min(1)
    .optional()
    .messages({
      'string.empty': 'Password cannot be empty'
    }),
  
  url: Joi.string()
    .uri()
    .optional()
    .allow('')
    .messages({
      'string.uri': 'Invalid URL format'
    }),
  
  notes: Joi.string()
    .max(500)
    .optional()
    .allow('')
    .messages({
      'string.max': 'Notes cannot exceed 500 characters'
    })
}).min(1).messages({
  'object.min': 'At least one field must be provided for update'
});

const shareCredentialSchema = Joi.object({
  userId: Joi.string()
    .trim()
    .pattern(/^[0-9a-fA-F]{24}$/)
    .required()
    .example('507f1f77bcf86cd799439011')
    .description('ID of the user to share with')
    .messages({
      'string.empty': 'User ID is required',
      'string.pattern.base': 'Invalid user ID format (must be MongoDB ObjectId)',
      'any.required': 'User ID is required'
    })
});

module.exports = { 
  createCredentialSchema, 
  updateCredentialSchema, 
  shareCredentialSchema 
};
