const express = require('express');
const mysql = require('mysql2');
const otplib = require('otplib');
const qrcode = require('qrcode');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = 8000;


// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('views'));

// MySQL Connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'admin',
  password: 'Shaina071199', // Replace with your MySQL password
  database: 'twofa', // Make sure this matches your database
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
  const qrFilePath = path.join(__dirname, 'views', `qr_${Date.now()}.png`);

  qrcode.toFile(qrFilePath, otpauth, (err) => {
    if (err) {
      console.error('Error generating QR Code:', err);
      return callback(err, null);
    }
    console.log('QR Code generated:', qrFilePath);
    callback(null, qrFilePath);
  });
}

app.get('/', (req, res) => {
  res.render('register'); // This loads register.ejs as the home page
});

// register page
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

    // Validate username and password length
    if (username.length < 8) {
        return res.send('Error: Username must be at least 8 characters long.');
    }
    if (password.length < 8) {
        return res.send('Error: Password must be at least 8 characters long.');
    }

    // Check if user already exists
    db.query('SELECT email FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            return res.send('Email already registered. Try another one.');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into database
        db.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword], (err, result) => {
                if (err) throw err;
                res.render('register-success'); // Redirect to success page
            });
    });
});

// home page (login form)
app.get('/', (req, res) => {
  res.send(`
    <h1>Login</h1>
    <form action="/login" method="POST">
      <label>Username:</label>
      <input type="text" name="username" required><br>
      <label>Password:</label>
      <input type="password" name="password" required><br>
      <button type="submit">Login</button>
    </form>
  `);
});

// Login Route (Generate new QR code every login)
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err) throw err;
    if (results.length === 0) {
        return res.status(401).send('Invalid credentials');
    }

    const user = results[0];

    // Compare the hashed password using bcrypt
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(401).send('Incorrect password. Try again.');
    }

    // Generate a new TOTP secret for every login
    const newSecret = otplib.authenticator.generateSecret();

    // Store the new secret temporarily in session instead of updating the database
    req.session.otpSecret = newSecret;

    // Generate a unique otpauth URL
    const otpauth = otplib.authenticator.keyuri(username, 'My2FAApp', newSecret);

    // Generate a QR code for the new secret
    generateQRCode(otpauth, (err, qrPath) => {
        if (err) {
            return res.status(500).send('Failed to generate QR Code');
        }

        res.send(`
            <h1>Scan QR Code with Google Authenticator</h1>
            <img src="/${path.basename(qrPath)}" alt="QR Code"><br>
            <form action="/validate" method="POST">
                <input type="hidden" name="username" value="${username}">
                <label>Enter OTP:</label>
                <input type="text" name="otp" required><br>
                <button type="submit">Validate</button>
            </form>
        `);
    });
});
});

// OTP Validation Route
app.post('/validate', (req, res) => {
  const { username, otp } = req.body;

  // Retrieve the secret key for the user
  const query = 'SELECT secret FROM users WHERE username = ?';
  db.query(query, [username], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Server error');
    }

    if (results.length === 0) {
      return res.status(401).send('User not found');
    }

    const secret = results[0].secret;

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
