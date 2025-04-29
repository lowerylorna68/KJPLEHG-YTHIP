const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000; // Fallback to 3000 for local testing

// Configuration
const JWT_SECRET = 'your_strong_secret_key'; // Replace with a secure secret key
const ENCRYPTION_KEY = crypto.createHash('sha256').update(JWT_SECRET).digest(); // Generate 32-byte key
const IV_LENGTH = 16; // AES requires a 16-byte initialization vector (IV)

// Middleware
app.use(express.static('public'));
app.use(express.json());

// Rate limiting: Protect endpoints from abuse
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1-minute window
    max: 10, // Limit each IP to 10 requests per window
    message: 'Too many requests. Please try again later.',
});

app.use(limiter);

// Helper Functions
function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${iv.toString('hex')}:${encrypted}`;
}

function decrypt(encryptedText) {
    const [ivHex, encryptedData] = encryptedText.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function loadRedirects() {
    if (!fs.existsSync('redirects.json')) {
        fs.writeFileSync('redirects.json', '{}');
    }
    const data = fs.readFileSync('redirects.json');
    const redirects = JSON.parse(data);
    for (const key in redirects) {
        redirects[key] = decrypt(redirects[key]);
    }
    return redirects;
}

function saveRedirects(redirects) {
    const encryptedRedirects = {};
    for (const key in redirects) {
        encryptedRedirects[key] = encrypt(redirects[key]);
    }
    fs.writeFileSync('redirects.json', JSON.stringify(encryptedRedirects, null, 2));
}

function generateUniqueKey() {
    return crypto.randomBytes(8).toString('hex');
}

function generateToken(key) {
    return jwt.sign({ key }, JWT_SECRET); // Token with no expiration
}

// Routes

// Add a new redirect
app.post('/add-redirect', (req, res) => {
    const { destination } = req.body;

    if (!destination || !/^https?:\/\//.test(destination)) {
        return res.status(400).json({ message: 'Invalid destination URL.' });
    }

    const key = generateUniqueKey();
    const token = generateToken(key);

    const redirects = loadRedirects();
    redirects[key] = destination;
    saveRedirects(redirects);

    const baseUrl = req.protocol + '://' + req.get('host'); // Dynamic base URL

    res.json({
        message: 'Redirect added successfully!',
        redirectUrl: `${baseUrl}/${key}?token=${token}`,
        pathRedirectUrl: `${baseUrl}/${key}/${token}`,
    });
});

// Handle query-based redirects
app.get('/:key/:token/:email?', (req, res) => {
    const { key, token, email: emailFromPath } = req.params;
    const emailFromQuery = req.query.email;

    let email = emailFromPath || emailFromQuery;

    if (email) {
        try {
            email = decodeURIComponent(email); // Decode %40 to @
        } catch (err) {
            console.error('Error decoding email:', err);
            return res.status(400).send('Invalid email encoding.');
        }
    }

    const userAgent = req.headers['user-agent'] || '';
    if (/bot|crawl|spider|preview/i.test(userAgent)) {
        return res.status(403).send('Access denied.');
    }

    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).send('Invalid email format.');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const redirects = loadRedirects();

        if (redirects[key] && decoded.key === key) {
            let destination = redirects[key];

            if (email) {
                if (destination.endsWith('/')) {
                    destination += email;
                } else {
                    destination += `/${email}`;
                }
            }

            res.redirect(destination);
        } else {
            res.status(404).send('Invalid or expired redirect.');
        }
    } catch (err) {
        console.error('Error during redirection:', err);
        res.status(403).send('Invalid or expired token.');
    }
});

// Handle path-based redirects
app.get('/:key/:token', (req, res) => {
    const { key, token } = req.params;

    const userAgent = req.headers['user-agent'] || '';
    if (/bot|crawl|spider|preview/i.test(userAgent)) {
        return res.status(403).send('Access denied.');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const redirects = loadRedirects();

        if (redirects[key] && decoded.key === key) {
            res.redirect(redirects[key]);
        } else {
            res.status(404).send('Invalid or expired redirect.');
        }
    } catch (err) {
        res.status(403).send('Invalid or expired token.');
    }
});

// Fallback for invalid routes
app.use((req, res) => {
    res.status(404).send('Error: Invalid request.');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
