require('dotenv').config();
const express = require('express');
const axios = require('axios');
const { auth } = require('express-oauth2-jwt-bearer');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;

// ----- DANH SÁCH NGƯỜI DÙNG ĐƯỢC PHÉP (WHITELIST) -----
const allowedUsers = [
    'joequocdoan@gmail.com',
    'yenientu@gmail.com',    
    'hoarichser@gmail.com',
    'lyyamaha@gmail.com',
    'mandyngoctran@gmail.com',
    'vunguyenbuf@gmail.com',
    'maituuyen7915@gmail.com', 
    'lethia9293@gmail.com',
    'huyenphamto2812@gmail.com', 
    'ngminh08@gmail.com'
];

// ----- Cấu hình Middleware xác thực JWT -----
const checkJwt = auth({
  audience: `https://${AUTH0_DOMAIN}/api/v2/`, // https://dev-4cakjw5yi0fvbsuv.us.auth0.com/api/v2/
  issuerBaseURL: `https://${AUTH0_DOMAIN}/`,
  tokenSigningAlg: 'RS256'
});

// PROXY ROUTE for Authorization - **UPDATED**
app.get('/authorize', (req, res) => {
    const auth0AuthorizeUrl = `https://${AUTH0_DOMAIN}/authorize`;

    // Lấy tất cả các tham số query từ OpenAI
    const params = new URLSearchParams(req.query);

    // THÊM THAM SỐ 'audience' MỘT CÁCH RÕ RÀNG
    // Giá trị này PHẢI khớp với audience trong cấu hình checkJwt
    params.set('audience', `https://${AUTH0_DOMAIN}/api/v2/`);
    // Luôn buộc hiển thị màn hình đăng nhập để người dùng có thể đổi tài khoản
    params.set('prompt', 'login'); 
    const redirectUrl = new URL(auth0AuthorizeUrl);
    redirectUrl.search = params.toString();

    console.log(`(FORCING LOGIN) Redirecting user to: ${redirectUrl.toString()}`);
    res.redirect(302, redirectUrl.toString());
});

// ----- TOKEN ENDPOINT -----
// Route này được server của OpenAI gọi để trao đổi authorization code lấy access token.
app.post('/token', async (req, res) => {
    console.log('Đã nhận yêu cầu token:', req.body);
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
        console.error('Lỗi khi trao đổi token:', error.response ? error.response.data : error.message);
        res.status(500).json({ error: 'Failed to exchange authorization code for token.' });
    }
});

// ----- PROTECTED API ENDPOINT VỚI LOGIC KIỂM TRA WHITELIST VÀ GỠ LỖI -----
// Route này được GPT Action gọi sau khi người dùng đã đăng nhập thành công.
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
        // Thông báo mới, thân thiện và cung cấp hướng dẫn
        const friendlyMessage = `Rất tiếc, tài khoản email "${userEmail}" chưa được cấp quyền truy cập. Vui lòng đăng nhập lại bằng một tài khoản đã được cấp phép, hoặc liên hệ quản trị viên để được hỗ trợ.`;
        return res.status(403).json({ error: 'Forbidden', message: friendlyMessage });
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