const mongoose = require('mongoose');

const reservationSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true }, // Added email field
    mobileNumber: { type: String, required: true },
    numberOfPeople: { type: Number, required: true },
    reservationDate: { type: Date, required: true },
    reservationTime: { type: String, required: true },
    tableLocation: { type: String, required: true }, // Updated to include tableLocation
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Reservation', reservationSchema);
