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

                    // Updates the newly registered in users table
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

app.get('/users-registered', (req, res) => {
    db.query('SELECT username, email, DATE_FORMAT(registered_at, "%W, %M %e %Y %H:%i:%s") AS formatted_date FROM users ORDER BY registered_at DESC', 
    (err, results) => {
        if (err) return res.status(500).send('Database error while fetching users.');

        res.render('users-registered', { users: results });
    });
});

// Login page
app.get('/login', (req, res) => {
    res.render('login');
});

// Handle login
const userAgent = require('user-agent'); // Install this package using: npm install user-agent

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const deviceInfo = req.headers['user-agent']; // Gets the user's device info

    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) return res.status(500).send('Database error');
        if (results.length === 0) return res.status(401).send('Invalid credentials');

        const user = results[0];

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).send('Server error');
            if (!isMatch) return res.status(401).send('Invalid credentials');

            // Store username in session
            req.session.username = user.username;

            // Update last login timestamp and device info
            db.query(
                'UPDATE users SET last_login = NOW(), last_device = ? WHERE username = ?',
                [deviceInfo, username]
            );

            res.redirect('/qr-setup'); // Proceed to 2FA
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
        const otpauth = otplib.authenticator.keyuri(username, '2FA-APP', secret);

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
    const username = req.session.username;
    const otp = req.body.otp;

    db.query('SELECT secret FROM users WHERE username = ?', [username], (err, results) => {
        if (err) return res.status(500).send('Server error');
        if (results.length === 0) return res.status(401).send('User not found');

        const secret = results[0].secret;
        if (!secret) return res.status(401).send('No OTP secret found. Generate one first.');

        // Set OTP expiry time to 30 seconds
        const totp = otplib.authenticator.clone();
        totp.options = { step: 30 };

        // Check OTP
        const isValid = totp.check(otp, secret);
        if (isValid) {
            req.session.authenticated = true; // Store authentication status in session

            // Update last 2FA verification time
            db.query('UPDATE users SET last_2fa = NOW() WHERE username = ?', [username]);

            res.redirect('/dashboard'); // Redirect to dashboard after successful 2FA
        } else {
            res.status(401).send('<h1>Invalid OTP</h1>');
        }
    });
});
app.get('/dashboard', (req, res) => {
    if (!req.session.username || !req.session.authenticated) {
        return res.redirect('/login');
    }

    const username = req.session.username;

    db.query('SELECT username, registered_at, last_login, last_2fa, last_device FROM users WHERE username = ?', 
    [username], (err, results) => {
        if (err) return res.status(500).send('Database error');
        if (results.length === 0) return res.status(404).send('User not found');

        const userData = results[0];

        res.render('dashboard', { user: userData });
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).send('Logout failed');
        res.redirect('/login');
    });
});

// Start the server

// ✅ Start server only if NOT in test mode
let server;
if (process.env.NODE_ENV !== 'test') {
    server = app.listen(PORT, () => {
        console.log(`Server running at http://localhost:${PORT}`);
    });
}

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});                                         
