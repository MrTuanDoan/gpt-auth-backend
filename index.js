require('dotenv').config();
const express = require('express');
const axios = require('axios');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;

// ----- NEW PROXY ROUTE for Authorization -----
app.get('/authorize', (req, res) => {
    const auth0AuthorizeUrl = `https://${AUTH0_DOMAIN}/authorize`;
    const redirectUrl = new URL(auth0AuthorizeUrl);
    redirectUrl.search = new URLSearchParams(req.query).toString();
    console.log(`Redirecting user to: ${redirectUrl.toString()}`);
    res.redirect(302, redirectUrl.toString());
});

// This is the endpoint OpenAI will call to get the access token
app.post('/token', async (req, res) => {
    console.log('Received token request:', req.body);
    try {
        const response = await axios.post(`https://${AUTH0_DOMAIN}/oauth/token`, {
            grant_type: 'authorization_code',
            client_id: AUTH0_CLIENT_ID,
            client_secret: AUTH0_CLIENT_SECRET,
            code: req.body.code,
            redirect_uri: req.body.redirect_uri
        }, {
            headers: { 'content-type': 'application/x-www-form-urlencoded' }
        });
        res.json(response.data);
    } catch (error) {
        console.error('Error exchanging token:', error.response ? error.response.data : error.message);
        res.status(500).json({ error: 'Failed to exchange authorization code for token.' });
    }
});

// This is your protected API endpoint that the GPT Action will call
app.get('/api/get-user-data', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized: No token provided.' });
    }
    const token = authHeader.split(' ')[1];
    console.log('Received valid token for protected route.');
    res.json({
        message: "Hello, authenticated user!",
        data: "This is secret data only you can see.",
        timestamp: new Date().toISOString()
    });
});

// Export the app object for Vercel's serverless environment
module.exports = app;