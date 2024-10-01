require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const authRoutes = require('./routes/authRoutes');
const path = require('path');


const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
// Routes
app.use('/auth', authRoutes);

const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || 'localhost';

app.set('views', path.join(__dirname, 'views'));

// Serve static files (optional if you have CSS or JS)
app.use(express.static(path.join(__dirname, 'public')));

// // Example route to render a specific EJS file
// app.get('/', (req, res) => {
//   res.render('auth/register-admin');  // renders 'views/index.ejs'
// })
app.get('/register-customer', (req, res) => {
  res.render('auth/register-customer'); // Renders views/auth/register-customer.ejs
});

// Route for admin registration
app.get('/', (req, res) => {
  res.render('auth/register-admin'); // Renders views/auth/register-admin.ejs
});

// Route for admin login
app.get('/login-admin', (req, res) => {
  res.render('auth/login-admin'); // Renders views/auth/login-admin.ejs
});
mongoose.connect(MONGO_URI)
  .then(() => app.listen(PORT, HOST, () => {
    console.log(`[ready] http://${HOST}:${PORT}`);
}))
  .catch((err) => console.log(err));

  

