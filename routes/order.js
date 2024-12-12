const express = require('express');
const router = express.Router();
const Order = require('../models/Order');  // Correctly requiring the Order model

// POST route for saving orders
router.post('/submit', async (req, res) => {
    const { items, totalPrice } = req.body;

    try {
        // Log the received data to ensure it's correct
        console.log('Received Order Data:', req.body);

        const newOrder = new Order({ items, totalPrice });
        await newOrder.save();

        res.status(200).send('Order saved');
    } catch (error) {
        console.error('Error saving order:', error);
        res.status(500).send('Server Error');
    }
});

module.exports = router;
