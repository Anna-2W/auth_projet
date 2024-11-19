const { signupSchema } = require('../middlewares/validator');
const { signinSchema } = require('../middlewares/validator');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/usersModel');


exports.signup = async (req, res) => {
    const { email, password } = req.body;
    try {
        // Validation des données
        const { error } = signupSchema.validate({ email, password });
        if (error) {
            return res
                .status(400)
                .json({ success: false, message: error.details[0].message });
        }

        // Vérifier si l'utilisateur existe déjà
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res
                .status(409)
                .json({ success: false, message: 'User already exists!' });
        }

        // Hashage du mot de passe
        const hashedPassword = await bcrypt.hash(password, 12);

        // Création du nouvel utilisateur
        const newUser = new User({
            email,
            password: hashedPassword,
        });

        const result = await newUser.save();

        // Supprimer le mot de passe de la réponse
        result.password = undefined;

        res.status(201).json({
            success: true,
            message: 'Your account has been created successfully',
            result,
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
        });
    }
};

exports.signin = async (req, res) => {
    const { email, password } = req.body;

    try {
        // Validation des données d'entrée
        const { error } = signinSchema.validate({ email, password });
        if (error) {
            return res
                .status(400)
                .json({ success: false, message: error.details[0].message });
        }

        // Vérification de l'utilisateur existant
        const existingUser = await User.findOne({ email }).select('+password'); // Inclure le mot de passe
        if (!existingUser) {
            return res
                .status(404)
                .json({ success: false, message: 'User does not exist!' });
        }

        // Validation du mot de passe
        const isPasswordValid = await bcrypt.compare(password, existingUser.password);
        if (!isPasswordValid) {
            return res
                .status(401)
                .json({ success: false, message: 'Invalid credentials!' });
        }

        // Génération du token JWT
        const token = jwt.sign(
            {
                userId: existingUser._id,
                email: existingUser.email,
                verified: existingUser.verified,
            },
            process.env.TOKEN_SECRET,
            {
                expiresIn: '8h', // Token valide pendant 8 heures
            }
        );

        // Configuration du cookie
        res.cookie('Authorization', 'Bearer ' + token, {
            expires: new Date(Date.now() + 8 * 3600000), // 8 heures
            httpOnly: process.env.NODE_ENV === 'production', // Accès uniquement via HTTP en production
            secure: process.env.NODE_ENV === 'production', // Cookie sécurisé en HTTPS
        });

        // Réponse de succès
        res.status(200).json({
            success: true,
            token,
            message: 'Logged in successfully',
        });
    } catch (error) {
        console.error(error);

        // Réponse en cas d'erreur serveur
        res.status(500).json({
            success: false,
            message: 'Internal server error',
        });
    }
};

exports.signout = async (req, res) => {
    res
        .clearCookie('Authorization')
        .status(200)
        .json({ success: true, message: 'logged out successfully' });
};