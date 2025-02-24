const express = require('express');
const mysql = require('mysql2');
const otplib = require('otplib');
const qrcode = require('qrcode');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
const PORT = 8000;

// Set up EJS as the template engine
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

// Middleware
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Set up session middleware
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true
}));

// MySQL Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'admin',
    password: 'Shaina071199',
    database: 'twofa'
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
        process.exit(1);
    }
    console.log('Connected to MySQL database.');
});

// Function to generate QR Code file (not always necessary if you use data URLs)
function generateQRCode(otpauth, callback) {
    const qrFilePath = path.join(__dirname, 'public', `qr_${Date.now()}.png`);
    qrcode.toFile(qrFilePath, otpauth, (err) => {
        if (err) {
            console.error('Error generating QR Code:', err);
            return callback(err, null);
        }
        console.log('QR Code generated:', qrFilePath);
        callback(null, qrFilePath);
    });
}

// Register success
app.get('/register-success', (req, res) => {
    res.render('register-success');
});

// Default route
app.get('/', (req, res) => {
    res.redirect('/register');
});

// Register page
app.get('/register', (req, res) => {
    res.render('register');
});

// Handle registration
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;

    if (username.length < 8 || password.length < 8) {
        return res.send('Error: Username and password must be at least 8 characters long.');
    }

    db.query('SELECT email FROM users WHERE email = ?', [email], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }

        if (results.length > 0) {
            return res.status(400).send('Error: This email is already registered. Try another one.');
        }

        // Hash the password
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                console.error('bcrypt hashing error:', err);
                return res.status(500).send('Error hashing password');
            }

            // Insert user
            db.query(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                [username, email, hashedPassword],
                (err, result) => {
                    if (err) {
                        console.error(err);
                        return res.status(500).send('Database error while inserting user.');
                    }

                    // Generate a 2FA secret for this new user
                    const newSecret = otplib.authenticator.generateSecret();

                    // Save it in the users table
                    db.query(
                        'UPDATE users SET secret = ? WHERE id = ?',
                        [newSecret, result.insertId],
                        (err) => {
                            if (err) {
                                console.error(err);
                                return res.status(500).send('Database error while updating user secret.');
                            }
                            res.redirect('/register-success');
                        }
                    );
                }
            );
        });
    });
});

// Login page
app.get('/login', (req, res) => {
    res.render('login');
});

// Handle login
app.post('/login', (req, res) => {
    if (!req.body || !req.body.username || !req.body.password) {
        return res.status(400).send('Error: Username and password are required.');
    }

    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            return res.status(500).send('Database error');
        }

        if (results.length === 0) {
            return res.status(401).send('Invalid credentials');
        }

        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                return res.status(500).send('Server error');
            }

            if (!isMatch) {
                return res.status(401).send('Invalid credentials');
            }

            // Save username in session
            req.session.username = user.username;
            res.redirect('/qr-setup');
        });
    });
});

// QR setup page
app.get('/qr-setup', (req, res) => {
    if (!req.session.username) {
        return res.redirect('/login');
    }

    const username = req.session.username;

    // Retrieve the secret from the database
    db.query('SELECT secret FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Database error');
        }

        if (results.length === 0 || !results[0].secret) {
            return res.status(400).send('No OTP secret found. Register first.');
        }

        const secret = results[0].secret;
        // Create otpauth URL
        const otpauth = otplib.authenticator.keyuri(username, 'SecureNotesApp', secret);

        // Generate QR code as data URL
        qrcode.toDataURL(otpauth, (err, qrCodeUrl) => {
            if (err) {
                console.error('QR Code generation error:', err);
                return res.status(500).send('Error generating QR code');
            }

            res.render('qr-code', { qrCodeUrl });
        });
    });
});

// OTP validation route
app.post('/validate', (req, res) => {
    const { username, otp } = req.body;

    db.query('SELECT secret FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            return res.status(500).send('Server error');
        }
        if (results.length === 0) {
            return res.status(401).send('User not found');
        }

        const secret = results[0].secret;
        if (!secret) {
            return res.status(401).send('No OTP secret found. Generate one first.');
        }

        // Check OTP
        const isValid = otplib.authenticator.check(otp, secret);
        if (isValid) {
            res.send('<h1>2FA Authentication Successful</h1>');
        } else {
            res.status(401).send('<h1>Invalid OTP</h1>');
        }
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
