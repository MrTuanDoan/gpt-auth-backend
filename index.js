require('dotenv').config();
const express = require('express');
const axios = require('axios');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;

// This is the endpoint OpenAI will call to get the access token
app.post('/token', async (req, res) => {
    console.log('Received token request:', req.body);
    try {
        const response = await axios.post(`https://${AUTH0_DOMAIN}/oauth/token`, {
            grant_type: 'authorization_code',
            client_id: AUTH0_CLIENT_ID,
            client_secret: AUTH0_CLIENT_SECRET,
            code: req.body.code,
            redirect_uri: req.body.redirect_uri // OpenAI provides this
        }, {
            headers: { 'content-type': 'application/x-www-form-urlencoded' }
        });

        // Forward the token response from Auth0 directly to OpenAI
        res.json(response.data);
    } catch (error) {
        console.error('Error exchanging token:', error.response ? error.response.data : error.message);
        res.status(500).json({ error: 'Failed to exchange authorization code for token.' });
    }
});

// This is your protected API endpoint that the GPT Action will call
// It needs to validate the token provided by OpenAI.
app.get('/api/get-user-data', (req, res) => {
    // OpenAI will send the token in the Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized: No token provided.' });
    }

    const token = authHeader.split(' ')[1];

    // **SECURITY**: In a real app, you MUST validate this JWT token.
    // Use a library like 'jwks-rsa' and 'express-jwt' to verify the
    // token signature against Auth0's public key.
    // For this example, we'll assume the token is valid.
    console.log('Received valid token for protected route.');

    res.json({
        message: "Hello, authenticated user!",
        data: "This is secret data only you can see.",
        timestamp: new Date().toISOString()
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Authentication backend listening on port ${PORT}`);
});