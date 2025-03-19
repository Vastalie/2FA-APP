const request = require('supertest');
const server = require('../index'); // Import your Express app

describe('Brute Force Attack Test', () => {
    test('Brute force login attempts should be blocked', async () => {
        let response;
        for (let i = 0; i < 10; i++) { // Simulate 10 failed attempts
            response = await request(server).post('/login').send({
                username: 'testuser',
                password: 'wrongpassword'
            });
        }

        // Try logging in one more time
        response = await request(server).post('/login').send({
            username: 'testuser',
            password: 'correctpassword'
        });

        // If rate limiting is enabled, expect 429 (Too Many Requests)
        expect(response.status).toBe(429);
        expect(response.text).toContain('Too many login attempts, please try again later');
    });

    afterAll((done) => {
        server.close(done); // Ensure the server closes properly after the test
    });
});

