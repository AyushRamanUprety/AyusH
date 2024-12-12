const express = require('express');
const router = express.Router();
const nodemailer = require('nodemailer');
const Contact = require('../models/Contact');
require('dotenv').config();  // Load environment variables

// Handle POST request for contact form submissions
router.post('/submit', async (req, res) => {
  const { name, email, message } = req.body;

  try {
    // Save the contact message to the database
    const contactMessage = new Contact({ name, email, message });
    await contactMessage.save();

    // Set up Nodemailer transport
    let transporter = nodemailer.createTransport({
      service: 'yahoo',
      auth: {
        user: process.env.EMAIL_USER, // Load from .env
        pass: process.env.EMAIL_PASS  // Load from .env
      }
    });

    // Define the email options
    let mailOptions = {
      from: process.env.EMAIL_USER, // Sender email from .env
      to: process.env.COMPANY_EMAIL, // Company's email address
      subject: `New Message from ${name}`, // Subject line
      text: `
        You have received a new message from ${name} (${email}):

        Message: ${message}

        You can reply to ${name} at this email: ${email}.
      `
    };

    // Send the email
    await transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log('Error sending email: ', error);
        res.status(500).send('Error sending email');
      } else {
        console.log('Email sent: ' + info.response);
        res.redirect('/html/contact.html?success=true'); // Redirect with success message
      }
    });

  } catch (error) {
    console.error('Server Error: ', error);
    res.status(500).send('Server Error');
  }
});

module.exports = router;
