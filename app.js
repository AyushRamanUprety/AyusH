const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const cors = require('cors');
const app = express();
require('dotenv').config();

app.use(cors());
// Middleware for parsing form data and JSON (no need for body-parser)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/BistroDB')
  .then(() => console.log('Connected to MongoDB'))
  .catch((error) => console.error('Error connecting to MongoDB:', error));

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Routes
const adminRoutes = require('./routes/admin');
const employeeRoutes = require('./routes/employee');
const contactRoutes = require('./routes/contact');
const reservationRoutes = require('./routes/reservation');
const reviewRoutes = require('./routes/review');
const menuRoutes = require('./routes/menu');
const orderRoutes = require('./routes/order');

app.use('/admin', adminRoutes);       // Route for admin
app.use('/employee', employeeRoutes);
app.use('/contact', contactRoutes);   // Route for contact form
app.use('/reservation', reservationRoutes); // Route for reservations
app.use('/reviews', reviewRoutes);    // Route for reviews
app.use('/menu', menuRoutes);
app.use('/orders', orderRoutes);

// Listen on Port
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
