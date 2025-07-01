require('dotenv').config();
const express = require('express');
const axios = require('axios');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;

// DANH SÁCH NGƯỜI DÙNG ĐƯỢC PHÉP (WHITELIST)
const allowedUsers = [
    'joequocdoan@gmail.com',
    'yenientu@gmail.com',    
];

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

// ----- CẬP NHẬT PROTECTED API ENDPOINT VỚI LOGGING CHI TIẾT -----
app.get('/api/get-user-data', checkJwt, (req, res) => {
    // ---- BẮT ĐẦU GỠ LỖI ----
    console.log("================ BẮT ĐẦU YÊU CẦU MỚI ================");
    console.log("Toàn bộ nội dung payload của token:", JSON.stringify(req.auth.payload, null, 2));

    const namespace = 'https://gpt-auth.com/';
    const userEmail = req.auth.payload[namespace + 'email'];

    console.log(`Giá trị của userEmail được trích xuất: ${userEmail}`);

    if (!userEmail) {
        console.log("LỖI: Không tìm thấy claim email trong token. Hãy kiểm tra lại Auth0 Action.");
        return res.status(403).json({ error: 'Forbidden', message: 'Không tìm thấy thông tin email trong token.' });
    }

    console.log(`Đang kiểm tra email '${userEmail}' với danh sách whitelist: [${allowedUsers.join(', ')}]`);

    // Kiểm tra xem email có trong whitelist không
    if (!allowedUsers.includes(userEmail)) {
        console.log(`QUYẾT ĐỊNH: TRUY CẬP BỊ TỪ CHỐI cho người dùng: ${userEmail}`);
        console.log("================ KẾT THÚC YÊU CẦU ================\n");
        return res.status(403).json({ error: 'Forbidden', message: 'Bạn không có quyền truy cập tài nguyên này.' });
    }

    console.log(`QUYẾT ĐỊNH: CẤP QUYỀN TRUY CẬP cho người dùng: ${userEmail}`);
    console.log("================ KẾT THÚC YÊU CẦU ================\n");
    res.json({
        message: `Chào mừng trở lại, ${userEmail}!`,
        data: "Đây là dữ liệu bí mật chỉ người dùng được cấp phép mới thấy.",
        timestamp: new Date().toISOString()
    });
});

// Export the app object for Vercel's serverless environment
module.exports = app;