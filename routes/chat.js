const express = require('express');
const router = express.Router();

// Chat page route
router.get('/', (req, res) => {
    res.render('chat'); // Render chat.pug
});

module.exports = router;
