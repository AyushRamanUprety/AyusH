const mongoose = require('mongoose');

const reviewSchema = new mongoose.Schema({
    name: { type: String, required: true },
    message: { type: String },
    rating: { type: Number, required: true }, // Add rating field
    date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Review', reviewSchema);
