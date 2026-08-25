require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bip39 = require('bip39');
const pool = require('./db');
const multer = require('multer');
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 } // 25MB per file
});

const app = express();

app.use(cors({
  origin: [
    "http://localhost:3000",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:5501",
    "https://robinhood-alliance.web.app",
    "https://rat-production-7ec5.up.railway.app",
    "*"
  ],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

app.use(express.json({ limit: '30mb' }));
app.use(express.urlencoded({ extended: true, limit: '30mb' }));

const PORT = process.env.PORT || 5000;

// ---------- USD RATES (for real bank-style income/expenses) ----------
const FALLBACK_USD = {
  BTC: 95000, ETH: 3500, USDT: 1, TRON: 0.25, TRX: 0.25,
  BNB: 650, XRP: 2.2, XLM: 0.4, USD: 1
};

async function getUsdRates() {
  try {
    const res = await fetch(
      'https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,tether,tron,binancecoin,ripple,stellar&vs_currencies=usd'
    );
    if (!res.ok) throw new Error('rate fail');
    const p = await res.json();
    return {
      BTC: p.bitcoin?.usd || FALLBACK_USD.BTC,
      ETH: p.ethereum?.usd || FALLBACK_USD.ETH,
      USDT: p.tether?.usd || 1,
      TRON: p.tron?.usd || FALLBACK_USD.TRON,
      TRX: p.tron?.usd || FALLBACK_USD.TRON,
      BNB: p.binancecoin?.usd || FALLBACK_USD.BNB,
      XRP: p.ripple?.usd || FALLBACK_USD.XRP,
      XLM: p.stellar?.usd || FALLBACK_USD.XLM,
      USD: 1
    };
  } catch {
    return { ...FALLBACK_USD };
  }
}

function toUsd(amount, currency, rates) {
  const c = (currency || 'USD').toUpperCase();
  const rate = rates[c] ?? FALLBACK_USD[c] ?? 0;
  return Number(amount || 0) * rate;
}

// ---------- HEALTH ----------
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ---------- AUTH MIDDLEWARE ----------
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function isAdmin(req, res, next) {
  if (req.userRole !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ---------- REGISTER ----------
app.post('/api/register', async (req, res) => {
  const { fullName, email, phone, country, password } = req.body;
  if (!fullName || !email || !phone || !country || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  let client = null;
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    client = await pool.connect();
    await client.query('BEGIN');

    const userResult = await client.query(
      `INSERT INTO users (full_name, email, phone, country, password_hash, preferred_currency, is_wallet_linked)
       VALUES ($1, $2, $3, $4, $5, 'USD', false)
       RETURNING id, full_name, email, role, preferred_currency, created_at`,
      [fullName, email, phone, country, passwordHash]
    );
    const newUser = userResult.rows[0];

    const currencies = ['BTC', 'ETH', 'USDT', 'TRON', 'BNB', 'XRP', 'XLM'];
    for (const curr of currencies) {
      await client.query(
        `INSERT INTO wallets (user_id, currency, balance) VALUES ($1, $2, 0)`,
        [newUser.id, curr]
      );
    }

    const mnemonic = bip39.generateMnemonic(128);
    const algorithm = 'aes-256-cbc';
    const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(mnemonic, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    await client.query(
      `INSERT INTO user_seeds (user_id, encrypted_mnemonic, iv) VALUES ($1, $2, $3)`,
      [newUser.id, encrypted, iv.toString('hex')]
    );

    await client.query('COMMIT');

    const token = jwt.sign(
      { id: newUser.id, email: newUser.email, role: newUser.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      success: true,
      user: {
        id: newUser.id,
        fullName: newUser.full_name,
        email: newUser.email,
        role: newUser.role,
        preferred_currency: newUser.preferred_currency || 'USD',
        createdAt: newUser.created_at
      },
      token
    });
  } catch (err) {
    if (client) {
      try { await client.query('ROLLBACK'); } catch (_) {}
    }
    console.error(err);
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: 'Registration failed' });
  } finally {
    if (client) client.release();
  }
});

// ---------- LOGIN ----------
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  try {
    const result = await pool.query(
      'SELECT id, full_name, email, password_hash, role, is_banned, is_suspended FROM users WHERE email = $1 AND deleted_at IS NULL',
      [email]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = result.rows[0];
    if (user.is_banned) return res.status(403).json({ error: 'Account banned' });
    if (user.is_suspended) return res.status(403).json({ error: 'Account suspended' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        role: user.role
      },
      token
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ---------- USER PROFILE (income/expenses = real USD of all tokens) ----------
app.get('/api/user', authenticate, async (req, res) => {
  try {
    const userResult = await pool.query(
      `SELECT id, full_name, email, role, is_banned, is_suspended, is_verified,
              preferred_currency, profile_image, is_wallet_linked, created_at
       FROM users WHERE id = $1`,
      [req.userId]
    );
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const user = userResult.rows[0];

    const txResult = await pool.query(
      `SELECT amount, currency, type, sender_id, receiver_id, amount_usd, status
       FROM transactions
       WHERE (sender_id = $1 OR receiver_id = $1) AND status = 'completed'`,
      [req.userId]
    );

    const rates = await getUsdRates();
    let income = 0;
    let expenses = 0;

    for (const tx of txResult.rows) {
      let usd = Number(tx.amount_usd);
      if (!usd || isNaN(usd) || usd === 0) {
        usd = toUsd(tx.amount, tx.currency, rates);
      }

      const isIn =
        String(tx.receiver_id) === String(req.userId) &&
        ['receive', 'deposit', 'admin_adjust'].includes(tx.type);
      const isOut =
        String(tx.sender_id) === String(req.userId) &&
        ['send', 'withdrawal', 'admin_adjust'].includes(tx.type);

      if (isIn) income += usd;
      if (isOut) expenses += usd;
    }

    await pool.query(
      'UPDATE users SET income = $1, expenses = $2 WHERE id = $3',
      [income, expenses, req.userId]
    );

    res.json({
      id: user.id,
      full_name: user.full_name,
      email: user.email,
      role: user.role,
      is_banned: user.is_banned,
      is_suspended: user.is_suspended,
      is_verified: user.is_verified,
      preferred_currency: user.preferred_currency || 'USD',
      profile_image: user.profile_image || null,
      is_wallet_linked: !!user.is_wallet_linked,
      created_at: user.created_at,
      income,
      expenses
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- KYC SUBMIT (files as Base64 in DB) ----------
// ---------- KYC SUBMIT (files as Base64 in DB) ----------
app.post(
  '/api/kyc',
  authenticate,
  upload.fields([
    { name: 'id_card', maxCount: 1 },
    { name: 'id_card_attachment', maxCount: 1 },
    { name: 'address_verification', maxCount: 1 }
  ]),
  async (req, res) => {
    try {
      const b = req.body || {};
      const files = req.files || {};
      const idFile =
        (files.id_card && files.id_card[0]) ||
        (files.id_card_attachment && files.id_card_attachment[0]) ||
        null;
      const addrFile =
        (files.address_verification && files.address_verification[0]) || null;

      const toDataUrl = (file) => {
        if (!file || !file.buffer) return null;
        const mime = file.mimetype || 'image/jpeg';
        return `data:${mime};base64,${file.buffer.toString('base64')}`;
      };

      const idCardImage = toDataUrl(idFile);
      const addressImage = toDataUrl(addrFile);

      if (!b.full_name || String(b.full_name).trim() === '') {
        return res.status(400).json({ error: 'Full name is required' });
      }

      const result = await pool.query(
        `INSERT INTO kyc_submissions (
          user_id, full_name, gender, marital_status, date_of_birth,
          mode_of_verification, address, city, state, country, zip_code,
          proof_of_address, id_card_image, address_image, status, created_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'pending',NOW())
        RETURNING id, status, created_at`,
        [
          req.userId,
          b.full_name || null,
          b.gender || null,
          b.marital_status || null,
          b.date_of_birth || null,
          b.mode_of_verification || null,
          b.address || null,
          b.city || null,
          b.state || null,
          b.country || null,
          b.zip_code || null,
          b.proof_of_address || null,
          idCardImage,
          addressImage
        ]
      );

      try {
        await pool.query(
          `INSERT INTO admin_audit_logs (admin_id, action, target_user_id, details, created_at)
           VALUES ($1, $2, $3, $4, NOW())`,
          [req.userId, 'kyc_submit', req.userId, JSON.stringify({ kyc_id: result.rows[0].id })]
        );
      } catch (_) {}

      res.json({
        success: true,
        message: 'your Information was successful please wait while your identity is being verified',
        id: result.rows[0].id,
        has_id_card: !!idCardImage,
        has_address_image: !!addressImage
      });
    } catch (err) {
      console.error('KYC error:', err);
      res.status(500).json({ error: err.message || 'Failed to submit KYC. Please try again.' });
    }
  }
);



      // Optional: mark user as having submitted KYC (you can use is_verified later after admin approval)
      await pool.query(
        `INSERT INTO admin_audit_logs (admin_id, action, target_user_id, details, created_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [req.userId, 'kyc_submit', req.userId, JSON.stringify({ kyc_id: result.rows[0].id })]
      ).catch(() => {}); // ignore if admin_id constraint fails for normal users

      res.json({
        success: true,
        message: 'KYC submitted successfully. Please wait while your identity is verified.',
        id: result.rows[0].id
      });
    } catch (err) {
      console.error('KYC error:', err);
      res.status(500).json({ error: 'Failed to submit KYC. Please try again.' });
    }
  }
);

// Admin: list KYC submissions
app.get('/api/admin/kyc', authenticate, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT k.id, k.user_id, k.full_name, k.gender, k.marital_status, k.date_of_birth,
              k.mode_of_verification, k.address, k.city, k.state, k.country, k.zip_code,
              k.proof_of_address, k.status, k.created_at,
              u.email as user_email,
              CASE WHEN k.id_card_image IS NOT NULL THEN true ELSE false END as has_id_card,
              CASE WHEN k.address_image IS NOT NULL THEN true ELSE false END as has_address_image
       FROM kyc_submissions k
       LEFT JOIN users u ON u.id = k.user_id
       ORDER BY k.created_at DESC
       LIMIT 200`
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch KYC list' });
  }
});

// Admin: get one KYC (with images)
app.get('/api/admin/kyc/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT k.*, u.email as user_email, u.full_name as user_full_name
       FROM kyc_submissions k
       LEFT JOIN users u ON u.id = k.user_id
       WHERE k.id = $1`,
      [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch KYC' });
  }
});

// Admin: approve / reject KYC
app.post('/api/admin/kyc/:id/status', authenticate, isAdmin, async (req, res) => {
  const { status } = req.body; // 'approved' | 'rejected' | 'pending'
  if (!['approved', 'rejected', 'pending'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  try {
    const result = await pool.query(
      `UPDATE kyc_submissions SET status = $1 WHERE id = $2
       RETURNING id, user_id, status`,
      [status, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });

    // If approved, mark user verified
    if (status === 'approved' && result.rows[0].user_id) {
      await pool.query(
        'UPDATE users SET is_verified = true WHERE id = $1',
        [result.rows[0].user_id]
      );
    }

    res.json({ success: true, ...result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update status' });
  }
});

// ---------- UPDATE PHONE ----------
app.post('/api/user/phone', authenticate, async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone number is required' });
  try {
    await pool.query('UPDATE users SET phone = $1 WHERE id = $2', [phone, req.userId]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update phone' });
  }
});

// ---------- UPDATE EMAIL ----------
app.post('/api/user/email', authenticate, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const userResult = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.userId]);
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const match = await bcrypt.compare(password, userResult.rows[0].password_hash);
    if (!match) return res.status(401).json({ error: 'Incorrect password' });
    await pool.query('UPDATE users SET email = $1 WHERE id = $2', [email, req.userId]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update email' });
  }
});

// ---------- UPDATE PASSWORD ----------
app.post('/api/user/password', authenticate, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password required' });
  }
  try {
    const userResult = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.userId]);
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const match = await bcrypt.compare(currentPassword, userResult.rows[0].password_hash);
    if (!match) return res.status(401).json({ error: 'Incorrect current password' });
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.userId]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update password' });
  }
});

// ---------- UPDATE PREFERRED CURRENCY ----------
app.post('/api/user/currency', authenticate, async (req, res) => {
  const { currency } = req.body;
  if (!currency) return res.status(400).json({ error: 'Currency required' });
  try {
    await pool.query('UPDATE users SET preferred_currency = $1 WHERE id = $2', [currency, req.userId]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update currency' });
  }
});

// ---------- UPDATE PROFILE IMAGE (Base64) ----------
app.post('/api/user/profile-image', authenticate, async (req, res) => {
  const { profile_image } = req.body;
  if (!profile_image || typeof profile_image !== 'string') {
    return res.status(400).json({ error: 'profile_image (base64 data URL) required' });
  }
  if (profile_image.length > 2800000) {
    return res.status(400).json({ error: 'Image too large (max ~2MB)' });
  }
  if (!profile_image.startsWith('data:image/')) {
    return res.status(400).json({ error: 'Must be a data:image/... base64 string' });
  }
  try {
    await pool.query(
      'UPDATE users SET profile_image = $1 WHERE id = $2',
      [profile_image, req.userId]
    );
    res.json({ success: true, profile_image });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save profile image' });
  }
});

// ---------- WALLETS ----------
app.get('/api/wallets', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT currency, balance FROM wallets WHERE user_id = $1',
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- USER TRANSACTIONS ----------
app.get('/api/transactions', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM transactions 
       WHERE sender_id = $1 OR receiver_id = $1 
       ORDER BY created_at DESC LIMIT 100`,
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- USER NOTIFICATIONS ----------
app.get('/api/notifications', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, message, is_read, created_at 
       FROM notifications 
       WHERE user_id = $1 
       ORDER BY created_at DESC LIMIT 50`,
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

app.post('/api/notifications/:id/read', authenticate, async (req, res) => {
  try {
    const check = await pool.query(
      'SELECT id FROM notifications WHERE id = $1 AND user_id = $2',
      [req.params.id, req.userId]
    );
    if (check.rows.length === 0) {
      return res.status(404).json({ error: 'Notification not found' });
    }
    await pool.query(
      'UPDATE notifications SET is_read = true WHERE id = $1',
      [req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to mark as read' });
  }
});

// ============================================================
//                    ADMIN ROUTES
// ============================================================

app.get('/api/admin/users', authenticate, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, full_name, email, phone, country, role, 
              is_banned, is_suspended, is_verified, is_wallet_linked,
              preferred_currency, income, expenses, created_at
       FROM users 
       WHERE deleted_at IS NULL
       ORDER BY id DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/api/admin/users/:id', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const userResult = await pool.query(
      `SELECT id, full_name, email, phone, country, role, 
              is_banned, is_suspended, is_verified, is_wallet_linked,
              preferred_currency, profile_image, income, expenses, created_at
       FROM users WHERE id = $1 AND deleted_at IS NULL`,
      [id]
    );
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const user = userResult.rows[0];
    const walletResult = await pool.query(
      'SELECT currency, balance FROM wallets WHERE user_id = $1',
      [id]
    );
    user.wallets = walletResult.rows;
    const txResult = await pool.query(
      `SELECT * FROM transactions 
       WHERE sender_id = $1 OR receiver_id = $1 
       ORDER BY created_at DESC LIMIT 100`,
      [id]
    );
    user.transactions = txResult.rows;
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

app.post('/api/admin/users/:id/ban', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { ban } = req.body;
  try {
    await pool.query('UPDATE users SET is_banned = $1 WHERE id = $2', [!!ban, id]);
    await pool.query(
      `INSERT INTO admin_audit_logs (admin_id, action, target_user_id, details, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [req.userId, ban ? 'ban_user' : 'unban_user', id, JSON.stringify({ ban })]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update ban status' });
  }
});

app.post('/api/admin/users/:id/suspend', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { suspend, reason } = req.body;
  try {
    await pool.query(
      'UPDATE users SET is_suspended = $1, suspension_reason = $2 WHERE id = $3',
      [!!suspend, suspend ? (reason || 'Suspended by admin') : null, id]
    );
    await pool.query(
      `INSERT INTO admin_audit_logs (admin_id, action, target_user_id, details, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [req.userId, suspend ? 'suspend_user' : 'unsuspend_user', id, JSON.stringify({ suspend, reason })]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update suspend status' });
  }
});

app.delete('/api/admin/users/:id', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE users SET deleted_at = NOW() WHERE id = $1', [id]);
    await pool.query(
      `INSERT INTO admin_audit_logs (admin_id, action, target_user_id, details, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [req.userId, 'delete_user', id, JSON.stringify({})]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.post('/api/admin/users/:id/verify', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { verify } = req.body;
  try {
    await pool.query('UPDATE users SET is_verified = $1 WHERE id = $2', [!!verify, id]);
    await pool.query(
      `INSERT INTO admin_audit_logs (admin_id, action, target_user_id, details, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [req.userId, verify ? 'verify_user' : 'unverify_user', id, JSON.stringify({ verify })]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update verification' });
  }
});

// ---------- TOGGLE WALLET LINKED ----------
app.post('/api/admin/users/:id/wallet-link', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { linked } = req.body;
  try {
    await pool.query(
      'UPDATE users SET is_wallet_linked = $1 WHERE id = $2',
      [!!linked, id]
    );
    await pool.query(
      `INSERT INTO admin_audit_logs (admin_id, action, target_user_id, details, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [req.userId, linked ? 'wallet_link' : 'wallet_unlink', id, JSON.stringify({ linked: !!linked })]
    );
    res.json({ success: true, is_wallet_linked: !!linked });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update wallet link status' });
  }
});

// ---------- ADJUST BALANCE (credit = income USD, debit = expense USD) ----------
app.post('/api/admin/users/:id/balance', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { currency, amount, operation, description } = req.body;
  if (!currency || !amount || !operation) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  const numericAmount = Number(amount);
  if (isNaN(numericAmount) || numericAmount <= 0) {
    return res.status(400).json({ error: 'Invalid amount' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const walletResult = await client.query(
      'SELECT balance FROM wallets WHERE user_id = $1 AND currency = $2 FOR UPDATE',
      [id, currency]
    );
    if (walletResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Wallet not found' });
    }

    let currentBalance = Number(walletResult.rows[0].balance);
    let newBalance;
    let senderId = null;
    let receiverId = null;
    let txType = 'admin_adjust';

    if (operation === 'credit') {
      newBalance = currentBalance + numericAmount;
      receiverId = id;
      senderId = null;
      txType = 'admin_adjust';
    } else if (operation === 'debit') {
      if (currentBalance < numericAmount) {
        throw new Error('Insufficient balance');
      }
      newBalance = currentBalance - numericAmount;
      senderId = id;
      receiverId = null;
      txType = 'admin_adjust';
    } else {
      throw new Error('Invalid operation');
    }

    await client.query(
      'UPDATE wallets SET balance = $1 WHERE user_id = $2 AND currency = $3',
      [newBalance, id, currency]
    );

    const rates = await getUsdRates();
    const amountUsd = toUsd(numericAmount, currency, rates);
    const desc = description || `${operation} by admin`;

    await client.query(
      `INSERT INTO transactions
         (sender_id, receiver_id, currency, amount, amount_usd, type, status, description, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())`,
      [senderId, receiverId, currency, numericAmount, amountUsd, txType, 'completed', desc]
    );

    await client.query(
      `INSERT INTO admin_audit_logs (admin_id, action, target_user_id, details, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [req.userId, 'balance_adjust', id, JSON.stringify({
        currency, amount: numericAmount, amount_usd: amountUsd, operation, newBalance, description: desc
      })]
    );

    await client.query('COMMIT');
    res.json({ success: true, newBalance, amount_usd: amountUsd });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: err.message || 'Failed to adjust balance' });
  } finally {
    client.release();
  }
});

app.post('/api/admin/impersonate/:id', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'SELECT id, email, role FROM users WHERE id = $1 AND deleted_at IS NULL',
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const user = result.rows[0];
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );
    await pool.query(
      `INSERT INTO admin_audit_logs (admin_id, action, target_user_id, details, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [req.userId, 'impersonate', id, JSON.stringify({})]
    );
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to impersonate' });
  }
});

// ---------- SEND NOTIFICATION ----------
app.post('/api/admin/notifications', authenticate, isAdmin, async (req, res) => {
  const userId = req.body.user_id ?? req.body.userId ?? null;
  const { title, message } = req.body;
  if (!message) return res.status(400).json({ error: 'Message is required' });

  try {
    if (userId && userId !== 'all' && userId !== null) {
      await pool.query(
        `INSERT INTO notifications (user_id, title, message, is_read, created_at)
         VALUES ($1, $2, $3, false, NOW())`,
        [userId, title || 'Admin Notification', message]
      );
    } else {
      const users = await pool.query('SELECT id FROM users WHERE deleted_at IS NULL');
      for (const row of users.rows) {
        await pool.query(
          `INSERT INTO notifications (user_id, title, message, is_read, created_at)
           VALUES ($1, $2, $3, false, NOW())`,
          [row.id, title || 'Admin Notification', message]
        );
      }
    }

    await pool.query(
      `INSERT INTO admin_audit_logs (admin_id, action, details, created_at)
       VALUES ($1, $2, $3, NOW())`,
      [req.userId, 'send_notification', JSON.stringify({ userId, title, message })]
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send notification' });
  }
});

app.get('/api/admin/notifications', authenticate, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT n.id, n.user_id, n.title, n.message, n.is_read, n.created_at,
              u.full_name as user_name, u.email as user_email
       FROM notifications n
       LEFT JOIN users u ON u.id = n.user_id
       ORDER BY n.created_at DESC
       LIMIT 200`
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

app.put('/api/admin/notifications/:id', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { title, message } = req.body;
  try {
    const result = await pool.query(
      `UPDATE notifications SET title = COALESCE($1, title), message = COALESCE($2, message)
       WHERE id = $3 RETURNING *`,
      [title, message, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Notification not found' });
    }
    res.json({ success: true, notification: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update notification' });
  }
});

app.delete('/api/admin/notifications/:id', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM notifications WHERE id = $1 RETURNING id', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Notification not found' });
    }
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete notification' });
  }
});

// ---------- UPDATE USER ----------
app.put('/api/admin/users/:id', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  const {
    full_name, email, phone, country, role,
    is_banned, is_suspended, is_verified, is_wallet_linked,
    preferred_currency, income, expenses
  } = req.body;

  try {
    const fields = [];
    const values = [];
    let idx = 1;

    if (full_name !== undefined) { fields.push(`full_name = $${idx++}`); values.push(full_name); }
    if (email !== undefined) { fields.push(`email = $${idx++}`); values.push(email); }
    if (phone !== undefined) { fields.push(`phone = $${idx++}`); values.push(phone); }
    if (country !== undefined) { fields.push(`country = $${idx++}`); values.push(country); }
    if (role !== undefined) { fields.push(`role = $${idx++}`); values.push(role); }
    if (is_banned !== undefined) { fields.push(`is_banned = $${idx++}`); values.push(is_banned); }
    if (is_suspended !== undefined) { fields.push(`is_suspended = $${idx++}`); values.push(is_suspended); }
    if (is_verified !== undefined) { fields.push(`is_verified = $${idx++}`); values.push(is_verified); }
    if (is_wallet_linked !== undefined) { fields.push(`is_wallet_linked = $${idx++}`); values.push(!!is_wallet_linked); }
    if (preferred_currency !== undefined) { fields.push(`preferred_currency = $${idx++}`); values.push(preferred_currency); }
    if (income !== undefined) { fields.push(`income = $${idx++}`); values.push(Number(income)); }
    if (expenses !== undefined) { fields.push(`expenses = $${idx++}`); values.push(Number(expenses)); }

    if (fields.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    values.push(id);
    const query = `UPDATE users SET ${fields.join(', ')} WHERE id = $${idx} 
                   RETURNING id, full_name, email, phone, country, role, is_banned, is_suspended,
                             is_verified, is_wallet_linked, preferred_currency, income, expenses`;
    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    await pool.query(
      `INSERT INTO admin_audit_logs (admin_id, action, target_user_id, details, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [req.userId, 'update_user', id, JSON.stringify(req.body)]
    );

    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

app.post('/api/admin/users', authenticate, isAdmin, async (req, res) => {
  const { full_name, email, phone, country, password, role } = req.body;
  if (!full_name || !email || !password) {
    return res.status(400).json({ error: 'Name, email and password required' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await client.query(
      `INSERT INTO users (full_name, email, phone, country, password_hash, role, preferred_currency, is_wallet_linked)
       VALUES ($1, $2, $3, $4, $5, $6, 'USD', false)
       RETURNING id, full_name, email, phone, country, role, preferred_currency, created_at`,
      [full_name, email, phone || null, country || null, passwordHash, role || 'user']
    );
    const newUser = result.rows[0];
    const currencies = ['BTC', 'ETH', 'USDT', 'TRON', 'BNB', 'XRP', 'XLM'];
    for (const curr of currencies) {
      await client.query(
        `INSERT INTO wallets (user_id, currency, balance) VALUES ($1, $2, 0)`,
        [newUser.id, curr]
      );
    }
    const mnemonic = bip39.generateMnemonic(128);
    const algorithm = 'aes-256-cbc';
    const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(mnemonic, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    await client.query(
      `INSERT INTO user_seeds (user_id, encrypted_mnemonic, iv) VALUES ($1, $2, $3)`,
      [newUser.id, encrypted, iv.toString('hex')]
    );
    await client.query('COMMIT');
    await pool.query(
      `INSERT INTO admin_audit_logs (admin_id, action, target_user_id, details, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [req.userId, 'create_user', newUser.id, JSON.stringify({ full_name, email, phone, country, role })]
    );
    res.status(201).json({ success: true, user: newUser });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: 'Failed to create user' });
  } finally {
    client.release();
  }
});

// ---------- UPDATE TRANSACTION ----------
app.put('/api/admin/transactions/:id', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { type, status, amount, currency, description } = req.body;

  try {
    const fields = [];
    const values = [];
    let idx = 1;

    if (type !== undefined) { fields.push(`type = $${idx++}`); values.push(type); }
    if (status !== undefined) { fields.push(`status = $${idx++}`); values.push(status); }
    if (amount !== undefined) { fields.push(`amount = $${idx++}`); values.push(Number(amount)); }
    if (currency !== undefined) { fields.push(`currency = $${idx++}`); values.push(currency); }
    if (description !== undefined) { fields.push(`description = $${idx++}`); values.push(description); }

    // Recalc amount_usd if amount or currency changed
    if (amount !== undefined || currency !== undefined) {
      const cur = await pool.query('SELECT amount, currency FROM transactions WHERE id = $1', [id]);
      if (cur.rows.length) {
        const a = amount !== undefined ? Number(amount) : Number(cur.rows[0].amount);
        const c = currency !== undefined ? currency : cur.rows[0].currency;
        const rates = await getUsdRates();
        fields.push(`amount_usd = $${idx++}`);
        values.push(toUsd(a, c, rates));
      }
    }

    if (fields.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    fields.push(`updated_at = NOW()`);
    values.push(id);

    const result = await pool.query(
      `UPDATE transactions SET ${fields.join(', ')} WHERE id = $${idx} RETURNING *`,
      values
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    await pool.query(
      `INSERT INTO admin_audit_logs (admin_id, action, details, created_at)
       VALUES ($1, $2, $3, NOW())`,
      [req.userId, 'update_transaction', JSON.stringify({ tx_id: id, ...req.body })]
    );

    res.json({ success: true, transaction: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update transaction' });
  }
});

// ---------- CREATE TRANSACTION ----------
app.post('/api/admin/transactions', authenticate, isAdmin, async (req, res) => {
  const { user_id, type, status, amount, currency, description } = req.body;
  if (!user_id || !type || !amount || !currency) {
    return res.status(400).json({ error: 'user_id, type, amount, currency required' });
  }

  try {
    let senderId = null;
    let receiverId = null;

    if (['receive', 'deposit'].includes(type)) {
      receiverId = user_id;
    } else if (['send', 'withdrawal'].includes(type)) {
      senderId = user_id;
    } else {
      receiverId = user_id;
    }

    const rates = await getUsdRates();
    const amountUsd = toUsd(Number(amount), currency, rates);

    const result = await pool.query(
      `INSERT INTO transactions
         (sender_id, receiver_id, type, status, amount, amount_usd, currency, description, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
       RETURNING *`,
      [senderId, receiverId, type, status || 'completed', Number(amount), amountUsd, currency, description || null]
    );

    await pool.query(
      `INSERT INTO admin_audit_logs (admin_id, action, target_user_id, details, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [req.userId, 'create_transaction', user_id, JSON.stringify(req.body)]
    );

    res.status(201).json({ success: true, transaction: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create transaction' });
  }
});

// ---------- AUDIT LOG ----------
app.get('/api/admin/audit', authenticate, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT a.id, a.admin_id, a.action, a.target_user_id, a.details, a.created_at,
              u.full_name as admin_name,
              t.full_name as target_user_name
       FROM admin_audit_logs a
       LEFT JOIN users u ON u.id = a.admin_id
       LEFT JOIN users t ON t.id = a.target_user_id
       ORDER BY a.created_at DESC
       LIMIT 300`
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

// ---------- START SERVER ----------
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});
