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


  fields: Joi.array()
    .items(
      Joi.object({
        key: Joi.string()
          .trim()
          .min(1)
          .max(100)
          .required()
          .messages({
            'string.empty': 'Field key is required',
            'any.required': 'Field key is required'
          }),
        value: Joi.string()
          .min(1)
          .required()
          .messages({
            'string.empty': 'Field value is required',
            'any.required': 'Field value is required'
          })
      })
    )
    .min(1)
    .required()
    .messages({
      'array.min': 'At least one credential field is required',
      'any.required': 'Fields array is required'
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
  fields: Joi.array()
    .items(
      Joi.object({
        key: Joi.string()
          .trim()
          .min(1)
          .max(100)
          .required()
          .messages({
            'string.empty': 'Field key is required',
            'any.required': 'Field key is required'
          }),
        value: Joi.string()
          .min(1)
          .required()
          .messages({
            'string.empty': 'Field value is required',
            'any.required': 'Field value is required'
          })
      })
    )
    .min(1)
    .optional()
    .messages({
      'array.min': 'At least one credential field is required'
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
