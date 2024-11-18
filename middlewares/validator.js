const Joi = require('joi');

exports.signupSchema = Joi.object({
    email: Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({ tlds: { allow: false } })
        .messages({
            'string.email': 'Invalid email format',
            'any.required': 'Email is required',
        }),
    password: Joi.string()
        .required()
        .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{8,}$'))
        .messages({
            'string.pattern.base': 'Password must include at least 1 lowercase, 1 uppercase, 1 number, and be at least 8 characters long.',
            'any.required': 'Password is required',
        }),
});

exports.signinSchema = Joi.object({
    email: Joi.string().email().required().messages({
        'string.email': 'Invalid email format',
        'any.required': 'Email is required',
    }),
    password: Joi.string().required().messages({
        'any.required': 'Password is required',
    }),
});
