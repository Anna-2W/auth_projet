const Joi = require('joi');

// Schéma pour la validation de l'email uniquement
const emailSchema = Joi.object({
    email: Joi.string().email().required(),
});

// Schémas existants pour l'inscription et la connexion
const signupSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
});

const signinSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
});

// Exportation des schémas
module.exports = {
    signupSchema,
    signinSchema,
    emailSchema,
};
