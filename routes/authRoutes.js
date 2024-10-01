const express = require('express');
const { registerCustomer, registerAdmin, verifyEmail, adminLogin } = require('../controller/authContoller');
const router = express.Router();

router.post('/register/customer', registerCustomer);
router.post('/register/admin', registerAdmin);
router.get('/verify-email/:token', verifyEmail);
router.post('/admin/login', adminLogin);

module.exports = router;
