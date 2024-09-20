const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const chatRouter = require('./routes/chat');
const app = express();

//const JWT_SECRET = 'your_jwt_secret_key';
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret'; // Change this to a secure secret key
const db = new sqlite3.Database('chat.db');

// Middleware setup
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

// Initialize the SQLite database
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);
});

// Serve the authorization page
app.get('/', (req, res) => {
    res.render('index'); // Render index.pug for login/signup
});

// Register route
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ message: 'Server error' });

        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], function (err) {
            if (err) return res.status(500).json({ message: 'User already exists' });
            res.status(200).json({ message: 'User registered successfully' });
        });
    });
});

// Login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) return res.status(401).json({ message: 'Invalid username or password' });

        bcrypt.compare(password, user.password, (err, match) => {
            if (err || !match) return res.status(401).json({ message: 'Invalid username or password' });

            const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
            res.cookie('token', token, { httpOnly: true, secure: true, maxAge: 3600000 }); // 1 hour
            res.status(200).json({ message: 'Login successful' });
        });
    });
});

// Middleware to verify JWT token
const authenticateJWT = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        console.log("No token provided");
        return res.sendStatus(401);
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log("Token verification failed");
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
};

// Chat page (renders chat.pug)
app.use('/chat', authenticateJWT, chatRouter);
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.status(200).json({ message: 'Logged out successfully' });
});
// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});
