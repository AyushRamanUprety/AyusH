const express = require('express');
const router = express.Router();
const Reservation = require('../models/Reservation');
const nodemailer = require('nodemailer');

// Setup Nodemailer transport
const transporter = nodemailer.createTransport({
    service: 'yahoo',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Handle POST request to make a reservation
router.post('/submit', async (req, res) => {
    const { fullName, email, mobileNumber, numberOfPeople, reservationDate, reservationTime, tableLocation } = req.body;

    try {
        // Save reservation details in the database
        const reservation = new Reservation({
            fullName,
            email,
            mobileNumber,
            numberOfPeople,
            reservationDate,
            reservationTime,
            tableLocation
        });
        await reservation.save();

        // Send email confirmation to the user
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Your Reservation at Mountain Fusion Bistro',
            text: `Dear ${fullName},\n\nThank you for making a reservation at Mountain Fusion Bistro.\n\nDetails of your reservation:\n- Full Name: ${fullName}\n- Mobile Number: ${mobileNumber}\n- Number of People: ${numberOfPeople}\n- Date: ${reservationDate}\n- Time: ${reservationTime}\n- Table Location: ${tableLocation}\n\nWe look forward to welcoming you.\n\nBest Regards,\nMountain Fusion Bistro`
        };

        await transporter.sendMail(mailOptions);

        // Redirect back to the reservation page with a success message
        res.redirect('/html/reservation.html?success=true');
    } catch (error) {
        console.error('Error saving reservation or sending email:', error);
        res.status(500).send('Server Error');
    }
});

module.exports = router;
