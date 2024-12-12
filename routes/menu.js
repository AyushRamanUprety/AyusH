const express = require('express');
const router = express.Router();
const MenuItem = require('../models/MenuItem');

// GET route to fetch all menu items
router.get('/all', async (req, res) => {
    try {
        const menuItems = await MenuItem.find();
        res.json(menuItems);
    } catch (error) {
        res.status(500).send('Server Error');
    }
});

module.exports = router;
