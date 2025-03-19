const request = require('supertest');
const { app, server } = require('../index'); // Import both app and server
const db = require('../db'); // Import your database connection

describe('Brute Force Attack Test', () => {
    test('Brute force login attempts should be blocked', async () => {
        let response;
        for (let i = 0; i < 10; i++) { // Simulate 10 failed attempts
            response = await request(app).post('/login').send({
                username: 'testuser',
                password: 'wrongpassword'
            });
        }

        // Try logging in one more time
        response = await request(app).post('/login').send({
            username: 'testuser',
            password: 'correctpassword'
        });

        // Expect rate limiting to trigger
        expect(response.status).toBe(429);
        expect(response.text).toContain('Too many login attempts, please try again later');
    });
});

// Ensure proper cleanup after all tests finish
afterAll(async () => {
    if (server && typeof server.close === 'function') {
        await new Promise((resolve) => server.close(resolve));
        console.log("Server closed.");
    }

    if (db && db.end) {
        await new Promise((resolve, reject) => {
            db.end((err) => {
                if (err) {
                    console.error("Error closing DB connection:", err);
                    reject(err);
                } else {
                    console.log("DB connection closed.");
                    resolve();
                }
            });
        });
    }
});


