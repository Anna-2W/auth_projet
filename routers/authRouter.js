const express = require('express')
const authController = require('../controllers/authController');
const router = express.Router();

router.post("/signup", authController.signup);
router.post("/signing", authController.signin);
router.post("/signout", authController.signout);


module.exports = router;