const User = require('../model/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const dotenv = require('dotenv');

dotenv.config();

// Transporter for sending verification emails
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Helper to send email verification
const sendVerificationEmail = async (user, req) => {
  const verificationLink = `${req.protocol}://${req.get('host')}/auth/verify-email/${user.verificationToken}`;
  await transporter.sendMail({
    to: user.email,
    subject: 'Verify Your Email',
    text: `Please verify your email by clicking this link: ${verificationLink}`,
  });
};

// Register Customer
exports.registerCustomer = async (req, res) => {
  const { firstName, lastName, email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: 'User with this email already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = uuidv4();

    user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      role: 'customer',
      verificationToken,
    });
    await user.save();

    await sendVerificationEmail(user, req);
    res.status(201).json({ msg: 'Customer registered. Please verify your email.' });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
};

// Register Admin
exports.registerAdmin = async (req, res) => {
  const { firstName, lastName, email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: 'User with this email already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = uuidv4();

    user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      role: 'admin',
      verificationToken,
    });
    await user.save();

    await sendVerificationEmail(user, req);
    res.status(201).json({ msg: 'Admin registered. Please verify your email.' });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
};

// Verify email
exports.verifyEmail = async (req, res) => {
  const { token } = req.params;
  try {
    const user = await User.findOne({ verificationToken: token });
    if (!user) return res.render('auth/verify-email', { message: 'Invalid or expired token' });

    user.isVerified = true;
    user.verificationToken = null;
    await user.save();

    res.render('auth/verify-email', { message: 'Email verified. You can now log in.' });
  } catch (error) {
    res.render('auth/verify-email', { message: 'Server error' });
  }
};

// Admin Login
exports.adminLogin = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'User does not exist' });

    if (user.role !== 'admin') {
      return res.status(403).json({ msg: 'You are not allowed to login from here' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(200).json({ token, msg: 'Admin login successful' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
};
