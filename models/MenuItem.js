const mongoose = require('mongoose');

const menuItemSchema = new mongoose.Schema({
    name: { type: String, required: true },
    category: { type: String, required: true },  // Entrées, Mains, Desserts, etc.
    price: { type: Number, required: true },
    imageUrl: { type: String, default: 'dummy-photo.jpg' }, // Default image URL
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('MenuItem', menuItemSchema);
