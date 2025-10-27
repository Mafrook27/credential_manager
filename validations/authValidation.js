const Joi = require("joi");

const registerSchema = Joi.object({
  name: Joi.string().pattern(/^[A-Za-z]+$/)
    .min(2)
    .max(50)
    .required()
.messages({
    'string.empty': 'Name is required',
    'string.min': 'Name must be at least 2 characters long',
    'string.max': 'Name cannot exceed 50 characters'
  }),
  email: Joi.string().email().lowercase().trim().required().messages({
    'string.email': 'Please provide a valid email address',
    'string.empty': 'Email is required'
  }),
  password: Joi.string().min(6).required().messages({
    'string.min': 'Password must be at least 6 characters long',
    'string.empty': 'Password is required'
  }),
 
});

const loginSchema = Joi.object({
  email: Joi.string().email().lowercase().trim().required().messages({
    'string.email': 'Please provide a valid email address',
    'string.empty': 'Email is required'
  }),
  password: Joi.string().min(6).required().messages({
    'string.min': 'Password must be at least 6 characters long',
    'string.empty': 'Password is required'
  })
});

// const changePasswordSchema = Joi.object({
//   oldPassword: Joi.string().min(6).required().messages({
//     'string.min': 'Old password must be at least 6 characters long',
//     'string.empty': 'Old password is required'
//   }),
//   newPassword: Joi.string().min(6).required().messages({
//     'string.min': 'New password must be at least 6 characters long',
//     'string.empty': 'New password is required'
//   })
// });




const resetPasswordReqSchema = Joi.object({
  email: Joi.string().email().required().messages({
    'string.empty': 'Email is required',
    'string.email': 'Email must be a valid format'
  })
}).strict(); // ✅ Rejects extra fields

// Schema for verifying token and resetting password
const resetPasswordVerifySchema = Joi.object({
  email: Joi.string().email().required().messages({
    'string.empty': 'Email is required',
    'string.email': 'Email must be a valid format'
  }),

  token: Joi.string().length(6).required().messages({
    'string.empty': 'Reset token is required',
    'string.length': 'Reset token must be 6 digits'
  }),

  newPassword: Joi.string().min(6).max(100).required().messages({
    'string.empty': 'New password is required',
    'string.min': 'Password must be at least 6 characters',
    'string.max': 'Password cannot exceed 100 characters'
  })
}).strict(); // ✅ Rejects extra fields



module.exports = { registerSchema, loginSchema,resetPasswordReqSchema,resetPasswordVerifySchema  };