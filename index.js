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
app.set('views', __dirname + '/views'); // Specify the views directory

// Middleware
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
    password: 'Shaina071199', // Replace with your MySQL password
    database: 'twofa', // Ensure this matches your database
});

// Connect to the database
db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
        process.exit(1);
    }
    console.log('Connected to MySQL database.');
});

// Function to generate QR Code
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

// register success page
app.get('/register-success', (req, res) => {
    res.render('register-success');
});

// register is the default page
app.get('/', (req, res) => {
    res.redirect('/register');
});

// register page
app.get('/register', (req, res) => {
    res.render('register'); // Loads register.ejs
});

// Register page
app.get('/register', (req, res) => {
    res.render('register'); 
});

// Handle registration
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (username.length < 8 || password.length < 8) {
        return res.send('Error: Username and password must be at least 8 characters long.');
    }

    // Check if email already exists before inserting
    db.query('SELECT email FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }

        if (results.length > 0) {
            return res.status(400).send('Error: This email is already registered. Try another one.');
        }

        // Hash the password before inserting
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                console.error("bcrypt hashing error:", err);
                return res.status(500).send('Error hashing password');
            }

            db.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                [username, email, hashedPassword], (err, result) => {
                    if (err) {
                        console.error(err);
                        return res.status(500).send('Database error while inserting user.');
                    }

                    res.redirect('/register-success'); // Redirect to success page
                });
        });
    });
});


// login page
app.get('/login', (req, res) => {
    res.render('login'); 
});


// Handle login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Query the database using a Promise-based approach
        db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).send('Database error');
            }

            // Debug: Print database results
            console.log("DB Query Results:", results);

            if (results.length === 0) {
                console.log("Invalid username:", username);
                return res.status(401).send('Invalid credentials');
            }

            const user = results[0];

            console.log("Stored Hashed Password:", user.password);
            console.log("Entered Plain Password:", password);

            // Compare the hashed password with the entered password
            bcrypt.compare(password, user.password, (err, isMatch) => {
                if (err) {
                    console.error("bcrypt error:", err);
                    return res.status(500).send('Server error');
                }

                if (!isMatch) {
                    console.log("Password does not match");
                    return res.status(401).send('Invalid credentials');
                }

                console.log("Login successful for:", username);

                res.redirect('/dashboard'); // Redirect user to dashboard after login
            });
        });
    } catch (error) {
        console.error("Unexpected error:", error);
        res.status(500).send('Server error');
    }
});

// OTP Validation Route
app.post('/validate', (req, res) => {
    const { username, otp } = req.body;

    // Retrieve the secret key for the user
    const query = 'SELECT secret FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) return res.status(500).send('Server error');
        if (results.length === 0) return res.status(401).send('User not found');

        const secret = results[0].secret;
        if (!secret) return res.status(401).send('No OTP secret found. Generate one first.');

        // Validate the OTP using the secret key
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
