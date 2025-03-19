const mysql = require('mysql2');
require('dotenv').config(); // Load environment variables

// Create a MySQL connection pool
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'admin',
    password: process.env.DB_PASSWORD || 'Shaina071199',
    database: process.env.DB_NAME || 'twofa',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test the connection
db.getConnection((err, connection) => {
    if (err) {
        console.error('Database connection failed:', err);
        process.exit(1);
    } else {
        console.log('Connected to MySQL database.');
        connection.release();
    }
});

module.exports = db;
