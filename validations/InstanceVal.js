const Joi = require('joi');

const typeOptions = [
  'banking',
  'email',
  'cloud',
  'social',
  'development',
  'database',
  'payment',
  'hosting',
  'communication',
  'other'
];

// Validation schema for creating RootInstance
const createInstanceSchema = Joi.object({
  serviceName: Joi.string()
    .trim()
    .min(2)
    .max(100)
    .required()
    .example('AWS')
    .description('Name of the service (e.g., Gmail, AWS, Azure, GitHub)')
    .messages({
      'string.empty': 'Service name is required',
      'string.min': 'Service name must be at least 2 characters',
      'string.max': 'Service name cannot exceed 100 characters',
      'any.required': 'Service name is required'
    }),
  
  type: Joi.string()
    .valid(...typeOptions)
    .default('other')
    .example('cloud')
    .description('Type of service: banking, email, cloud, social, development, database, payment, hosting, communication, other')
    .messages({
      'any.only': 'Invalid service type. Valid types: banking, email, cloud, social, development, database, payment, hosting, communication, other'
    })
});

// Validation schema for updating RootInstance
const updateInstanceSchema = Joi.object({
  serviceName: Joi.string()
    .trim()
    .min(2)
    .max(100)
    .optional()
    .example('Amazon Web Services')
    .messages({
      'string.empty': 'Service name cannot be empty',
      'string.min': 'Service name must be at least 2 characters',
      'string.max': 'Service name cannot exceed 100 characters'
    }),
  
  type: Joi.string()
    .valid(...typeOptions)
    .optional()
    .example('cloud')
    .messages({
      'any.only': 'Invalid service type. Valid types: banking, email, cloud, social, development, database, payment, hosting, communication, other'
    })
}).min(1).messages({
  'object.min': 'At least one field (serviceName or type) must be provided for update'
});


//--------------------- creating SubInstance
const createSubInstanceSchema = Joi.object({
  name: Joi.string()
    .trim()
    .min(1)
    .max(100)
    .required()
    .example('Production Account')
    .description('Name of the sub-instance/folder (e.g., login, transaction, personal, work)')
    .messages({
      'string.empty': 'Sub-instance name is required',
      'string.min': 'Sub-instance name must be at least 1 character',
      'string.max': 'Sub-instance name cannot exceed 100 characters',
      'any.required': 'Sub-instance name is required'
    })
});


const updateSubInstanceSchema = Joi.object({
  name: Joi.string()
    .trim()
    .min(1)
    .max(100)
    .required()
    .example('Development Environment')
    .description('Updated name of the sub-instance/folder')
    .messages({
      'string.empty': 'Sub-instance name is required',
      'string.min': 'Sub-instance name must be at least 1 character',
      'string.max': 'Sub-instance name cannot exceed 100 characters',
      'any.required': 'Sub-instance name is required'
    })
  });








    module.exports = {
  createInstanceSchema,
  updateSubInstanceSchema,
   createSubInstanceSchema,
  updateInstanceSchema
};


