const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const axios = require('axios');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ============================================================
// SUPABASE CONFIGURATION
// ============================================================
const SUPABASE_URL = "https://rxcrixzkzebvwfxvcrbp.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJ4Y3JpeHpremVidndmeHZjcmJwIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NzYyMzY5MSwiZXhwIjoyMDkzMTk5NjkxfQ.Duvgh_hesCFhTClsAFBp4kE-tDUwp3f0HVNFbGG2lMc";

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ============================================================
// PAKASIR CONFIGURATION
// ============================================================
const PAKASIR_API_KEY = "YOUR_PAKASIR_API_KEY"; // Ganti dengan API key dari Pakasir
const PAKASIR_API_URL = "https://app.pakasir.com/api/v1";

// ============================================================
// ADMIN CONFIGURATION
// ============================================================
const ADMIN_PASSWORD = "67";
let adminToken = null;
let adminTokenExpiry = null;

// ============================================================
// TRANSLATIONS (MULTI-LANGUAGE)
// ============================================================
const translations = {
    id: {
        welcome: "Selamat Datang di Nexus System",
        key_not_found: "Key tidak ditemukan",
        key_expired: "Key sudah kadaluarsa",
        invalid_credentials: "Username atau password salah",
        insufficient_coins: "Saldo coin tidak mencukupi",
        payment_success: "Pembayaran berhasil",
        payment_failed: "Pembayaran gagal",
        key_created: "Key berhasil dibuat",
        select_duration: "Pilih durasi",
        select_device_limit: "Pilih batas device",
        total_price: "Total harga",
        your_coins: "Saldo Coin Anda",
        buy_now: "Beli Sekarang",
        transaction_history: "Riwayat Transaksi"
    },
    en: {
        welcome: "Welcome to Nexus System",
        key_not_found: "Key not found",
        key_expired: "Key has expired",
        invalid_credentials: "Invalid username or password",
        insufficient_coins: "Insufficient coin balance",
        payment_success: "Payment successful",
        payment_failed: "Payment failed",
        key_created: "Key created successfully",
        select_duration: "Select duration",
        select_device_limit: "Select device limit",
        total_price: "Total price",
        your_coins: "Your Coin Balance",
        buy_now: "Buy Now",
        transaction_history: "Transaction History"
    }
};

function t(lang, key) {
    return translations[lang]?.[key] || translations.id[key] || key;
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================
function generateKey() {
    const prefix = "NX";
    const timestamp = Date.now().toString(36).toUpperCase();
    const random = crypto.randomBytes(8).toString('hex').toUpperCase();
    const checksum = crypto.createHash('sha256').update(timestamp + random).digest('hex').substring(0, 8).toUpperCase();
    return `${prefix}-${timestamp}-${random}-${checksum}`;
}

function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

function formatTimeRemaining(expiryMs) {
    const remaining = Math.max(0, expiryMs - Date.now());
    const days = Math.floor(remaining / 86400000);
    const hours = Math.floor((remaining % 86400000) / 3600000);
    const minutes = Math.floor((remaining % 3600000) / 60000);
    
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
}

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || 
           req.socket.remoteAddress || 
           'unknown';
}

async function getSetting(key, defaultValue = 'false') {
    const { data } = await supabase.from('settings').select('value').eq('key', key).maybeSingle();
    return data?.value || defaultValue;
}

async function logSecurityEvent(eventType, details, ip, deviceFp, userId = null) {
    await supabase.from('security_logs').insert({
        event_type: eventType, details, ip_address: ip, device_fingerprint: deviceFp, user_id: userId, timestamp: Date.now()
    });
}

// ============================================================
// MAINTENANCE MODE
// ============================================================
async function isMaintenanceMode() {
    try {
        const { data } = await supabase.from('system_settings').select('value').eq('key', 'maintenance_mode').single();
        return data?.value === 'true';
    } catch { return false; }
}

app.use('/api/', async (req, res, next) => {
    if (req.path.includes('/admin/') || req.path === '/api/health' || req.path === '/api/maintenance-status') return next();
    const maintenance = await isMaintenanceMode();
    if (maintenance) return res.status(503).json({ success: false, maintenance: true, error: 'Service temporarily unavailable' });
    next();
});

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
function verifyAdmin(req, res, next) {
    const token = req.body.token || req.query.token;
    if (!token || token !== adminToken || (adminTokenExpiry && Date.now() > adminTokenExpiry)) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    next();
}

async function verifyReseller(req, res, next) {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(401).json({ success: false, error: 'Reseller credentials required' });
    }
    const { data: user } = await supabase.from('users').select('*').eq('user_id', username).eq('reseller_password', password).eq('role', 'reseller').maybeSingle();
    if (!user) {
        return res.status(401).json({ success: false, error: 'Invalid reseller credentials' });
    }
    req.reseller = user;
    next();
}

// ============================================================
// RESELLER PRICE CONFIG
// ============================================================
const DURATION_OPTIONS = [
    { days: 1, coins: 5 },
    { days: 3, coins: 12 },
    { days: 7, coins: 25 },
    { days: 15, coins: 45 },
    { days: 30, coins: 80 }
];

const DEVICE_LIMIT_OPTIONS = [
    { limit: 1, extra: 0 },
    { limit: 10, extra: 10 },
    { limit: 20, extra: 18 },
    { limit: 30, extra: 25 },
    { limit: 50, extra: 40 }
];

function calculatePrice(durationDays, deviceLimit) {
    const durationPrice = DURATION_OPTIONS.find(d => d.days === durationDays)?.coins || 5;
    const deviceExtra = DEVICE_LIMIT_OPTIONS.find(d => d.limit === deviceLimit)?.extra || 0;
    return durationPrice + deviceExtra;
}

// ============================================================
// API: GET ANNOUNCEMENTS
// ============================================================
app.get('/api/announcements', async (req, res) => {
    const now = Date.now();
    const { data } = await supabase
        .from('announcements')
        .select('*')
        .eq('is_active', true)
        .lt('start_date', now)
        .gt('end_date', now)
        .order('created_at', { ascending: false });
    res.json({ success: true, announcements: data || [] });
});

// ============================================================
// API: GET USER NOTIFICATIONS
// ============================================================
app.get('/api/notifications/:userId', async (req, res) => {
    const { userId } = req.params;
    const { data } = await supabase
        .from('user_notifications')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(50);
    res.json({ success: true, notifications: data || [] });
});

app.post('/api/notifications/read', async (req, res) => {
    const { notificationId, userId } = req.body;
    await supabase.from('user_notifications').update({ is_read: true }).eq('id', notificationId).eq('user_id', userId);
    res.json({ success: true });
});

// ============================================================
// API: RESELLER LOGIN
// ============================================================
app.post('/api/reseller/login', async (req, res) => {
    const { username, password } = req.body;
    const { data: user } = await supabase
        .from('users')
        .select('*')
        .eq('user_id', username)
        .eq('reseller_password', password)
        .eq('role', 'reseller')
        .maybeSingle();
    
    if (!user) {
        return res.json({ success: false, error: 'Invalid credentials' });
    }
    
    const token = generateSessionToken();
    res.json({ success: true, token, user: { user_id: user.user_id, coins: user.coins, language: user.language || 'id' } });
});

// ============================================================
// API: RESELLER CREATE KEY
// ============================================================
app.post('/api/reseller/create-key', verifyReseller, async (req, res) => {
    const { durationDays, deviceLimit, buyerEmail } = req.body;
    const reseller = req.reseller;
    
    const validDurations = [1, 3, 7, 15, 30];
    const validDeviceLimits = [1, 10, 20, 30, 50];
    
    if (!validDurations.includes(durationDays)) {
        return res.json({ success: false, error: 'Invalid duration' });
    }
    if (!validDeviceLimits.includes(deviceLimit)) {
        return res.json({ success: false, error: 'Invalid device limit' });
    }
    
    const price = calculatePrice(durationDays, deviceLimit);
    
    if (reseller.coins < price) {
        return res.json({ success: false, error: 'Insufficient coins', needed: price, current: reseller.coins });
    }
    
    const newKey = generateKey();
    const expiryMs = Date.now() + (durationDays * 24 * 3600000);
    
    // Deduct coins
    await supabase.from('users').update({ coins: reseller.coins - price }).eq('user_id', reseller.user_id);
    
    // Record coin transaction
    await supabase.from('coin_transactions').insert({
        user_id: reseller.user_id,
        amount: -price,
        type: 'purchase',
        reason: `Created key for ${durationDays} days, ${deviceLimit} devices`,
        created_at: Date.now(),
        created_by: reseller.user_id
    });
    
    // Create key
    await supabase.from('keys').insert({
        key_text: newKey,
        user_id: reseller.user_id,
        duration_hours: durationDays * 24,
        duration_days: durationDays,
        expiry_ms: expiryMs,
        created_at: Date.now(),
        status: 'active',
        is_admin_key: 0,
        created_by: 'reseller',
        max_devices: deviceLimit,
        binding_type: 'device'
    });
    
    // Record reseller key
    await supabase.from('reseller_keys').insert({
        key_text: newKey,
        reseller_id: reseller.user_id,
        duration_days: durationDays,
        max_devices: deviceLimit,
        price_coins: price,
        buyer_email: buyerEmail,
        created_at: Date.now(),
        status: 'active'
    });
    
    res.json({
        success: true,
        key: newKey,
        expiryFormatted: new Date(expiryMs).toLocaleString(),
        remainingCoins: reseller.coins - price,
        price: price,
        durationDays: durationDays,
        deviceLimit: deviceLimit
    });
});

// ============================================================
// API: RESELLER GET BALANCE
// ============================================================
app.post('/api/reseller/balance', verifyReseller, async (req, res) => {
    res.json({ success: true, coins: req.reseller.coins, userId: req.reseller.user_id });
});

// ============================================================
// API: RESELLER GET HISTORY
// ============================================================
app.post('/api/reseller/history', verifyReseller, async (req, res) => {
    const { data: keys } = await supabase
        .from('reseller_keys')
        .select('*')
        .eq('reseller_id', req.reseller.user_id)
        .order('created_at', { ascending: false })
        .limit(50);
    
    const { data: transactions } = await supabase
        .from('coin_transactions')
        .select('*')
        .eq('user_id', req.reseller.user_id)
        .order('created_at', { ascending: false })
        .limit(50);
    
    res.json({ success: true, keys: keys || [], transactions: transactions || [] });
});

// ============================================================
// API: RESELLER UPDATE LANGUAGE
// ============================================================
app.post('/api/reseller/language', verifyReseller, async (req, res) => {
    const { language } = req.body;
    await supabase.from('users').update({ language }).eq('user_id', req.reseller.user_id);
    res.json({ success: true });
});

// ============================================================
// API: CREATE PAYMENT (PAKASIR)
// ============================================================
app.post('/api/create-payment', async (req, res) => {
    const { userId, coins, paymentMethod } = req.body;
    
    const pakasirPayload = {
        api_key: PAKASIR_API_KEY,
        amount: coins * 100, // Contoh: 1 coin = 100 IDR
        customer_name: userId,
        customer_email: `${userId}@nexus.com`,
        payment_method: paymentMethod || 'qris',
        return_url: 'https://nexusofc-generate-key.vercel.app/payment-callback.html',
        expired_time: 24,
        order_id: `INV-${Date.now()}-${userId}`
    };
    
    try {
        const response = await axios.post(`${PAKASIR_API_URL}/create-transaction`, pakasirPayload, {
            headers: { 'Content-Type': 'application/json' }
        });
        
        if (response.data && response.data.data) {
            await supabase.from('payment_transactions').insert({
                transaction_id: response.data.data.reference,
                user_id: userId,
                amount: coins * 100,
                coins: coins,
                payment_url: response.data.data.checkout_url,
                status: 'pending',
                created_at: Date.now()
            });
            
            res.json({
                success: true,
                paymentUrl: response.data.data.checkout_url,
                transactionId: response.data.data.reference
            });
        } else {
            res.json({ success: false, error: 'Payment creation failed' });
        }
    } catch (error) {
        console.error('Pakasir error:', error.message);
        res.json({ success: false, error: 'Payment gateway error' });
    }
});

app.post('/api/check-payment', async (req, res) => {
    const { transactionId } = req.body;
    
    const { data: transaction } = await supabase
        .from('payment_transactions')
        .select('*')
        .eq('transaction_id', transactionId)
        .single();
    
    if (!transaction) {
        return res.json({ status: 'not_found', error: 'Transaction not found' });
    }
    
    res.json({
        status: transaction.status,
        coins: transaction.coins,
        amount: transaction.amount
    });
});

// ============================================================
// API: PAYMENT WEBHOOK (Pakasir)
// ============================================================
app.post('/api/payment-webhook', async (req, res) => {
    const { reference, status, amount } = req.body;
    
    if (status === 'success') {
        const { data: transaction } = await supabase
            .from('payment_transactions')
            .select('*')
            .eq('transaction_id', reference)
            .single();
        
        if (transaction && transaction.status === 'pending') {
            await supabase.from('payment_transactions').update({ status: 'completed', completed_at: Date.now() }).eq('transaction_id', reference);
            
            // Add coins to user
            const { data: user } = await supabase.from('users').select('coins').eq('user_id', transaction.user_id).single();
            await supabase.from('users').update({ coins: (user.coins || 0) + transaction.coins }).eq('user_id', transaction.user_id);
            
            await supabase.from('coin_transactions').insert({
                user_id: transaction.user_id,
                amount: transaction.coins,
                type: 'add',
                reason: 'Topup via Pakasir',
                created_at: Date.now(),
                created_by: 'system'
            });
        }
    }
    
    res.json({ success: true });
});

// ============================================================
// ADMIN API (COIN MANAGEMENT, RESELLER, ANNOUNCEMENT, BROADCAST)
// ============================================================

// Get all resellers
app.post('/api/admin/resellers', verifyAdmin, async (req, res) => {
    const { data } = await supabase.from('users').select('*').eq('role', 'reseller').order('created_at', { ascending: false });
    res.json({ success: true, resellers: data || [] });
});

// Create reseller account
app.post('/api/admin/create-reseller', verifyAdmin, async (req, res) => {
    const { username, password, initialCoins = 0 } = req.body;
    
    if (!username || !password) {
        return res.json({ success: false, error: 'Username and password required' });
    }
    
    const { data: existing } = await supabase.from('users').select('user_id').eq('user_id', username).maybeSingle();
    if (existing) {
        return res.json({ success: false, error: 'Username already exists' });
    }
    
    await supabase.from('users').insert({
        user_id: username,
        reseller_password: password,
        role: 'reseller',
        coins: initialCoins,
        reseller_approved: true,
        created_at: Date.now()
    });
    
    res.json({ success: true, message: `Reseller ${username} created with ${initialCoins} coins` });
});

// Add coins to reseller
app.post('/api/admin/add-coins', verifyAdmin, async (req, res) => {
    const { userId, amount, reason } = req.body;
    
    const { data: user } = await supabase.from('users').select('coins').eq('user_id', userId).single();
    if (!user) return res.json({ success: false, error: 'User not found' });
    
    await supabase.from('users').update({ coins: (user.coins || 0) + amount }).eq('user_id', userId);
    
    await supabase.from('coin_transactions').insert({
        user_id: userId,
        amount: amount,
        type: amount > 0 ? 'add' : 'deduct',
        reason: reason || 'Admin adjustment',
        created_at: Date.now(),
        created_by: 'admin'
    });
    
    res.json({ success: true, newBalance: (user.coins || 0) + amount });
});

// Get coin transactions
app.post('/api/admin/coin-transactions', verifyAdmin, async (req, res) => {
    const { userId, limit = 100 } = req.body;
    let query = supabase.from('coin_transactions').select('*').order('created_at', { ascending: false }).limit(limit);
    if (userId) query = query.eq('user_id', userId);
    const { data } = await query;
    res.json({ success: true, transactions: data || [] });
});

// Create announcement
app.post('/api/admin/create-announcement', verifyAdmin, async (req, res) => {
    const { title, content, type, startDate, endDate } = req.body;
    
    await supabase.from('announcements').insert({
        title, content, type: type || 'info',
        start_date: startDate || Date.now(),
        end_date: endDate || (Date.now() + 30 * 24 * 3600000),
        is_active: true,
        created_at: Date.now(),
        created_by: 'admin'
    });
    
    res.json({ success: true });
});

// Get all announcements (admin)
app.post('/api/admin/announcements', verifyAdmin, async (req, res) => {
    const { data } = await supabase.from('announcements').select('*').order('created_at', { ascending: false });
    res.json({ success: true, announcements: data || [] });
});

// Delete announcement
app.post('/api/admin/delete-announcement', verifyAdmin, async (req, res) => {
    const { id } = req.body;
    await supabase.from('announcements').delete().eq('id', id);
    res.json({ success: true });
});

// Broadcast to users
app.post('/api/admin/broadcast', verifyAdmin, async (req, res) => {
    const { title, message, targetRole } = req.body; // targetRole: 'all', 'reseller', 'user'
    
    let query = supabase.from('users').select('user_id');
    if (targetRole && targetRole !== 'all') {
        query = query.eq('role', targetRole);
    }
    
    const { data: users } = await query;
    
    const notifications = users.map(user => ({
        user_id: user.user_id,
        title: title,
        message: message,
        type: 'broadcast',
        created_at: Date.now()
    }));
    
    if (notifications.length > 0) {
        await supabase.from('user_notifications').insert(notifications);
    }
    
    await supabase.from('broadcast_history').insert({
        title, message, target_role: targetRole || 'all',
        total_sent: notifications.length,
        created_at: Date.now(),
        created_by: 'admin'
    });
    
    res.json({ success: true, totalSent: notifications.length });
});

// Get broadcast history
app.post('/api/admin/broadcast-history', verifyAdmin, async (req, res) => {
    const { data } = await supabase.from('broadcast_history').select('*').order('created_at', { ascending: false });
    res.json({ success: true, broadcasts: data || [] });
});

// Get system stats
app.post('/api/admin/stats', verifyAdmin, async (req, res) => {
    const { count: totalKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true });
    const { count: activeKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true }).eq('status', 'active');
    const { count: totalUsers } = await supabase.from('users').select('*', { count: 'exact', head: true });
    const { count: resellers } = await supabase.from('users').select('*', { count: 'exact', head: true }).eq('role', 'reseller');
    const { data: totalCoins } = await supabase.from('users').select('coins');
    const coinSum = totalCoins?.reduce((sum, u) => sum + (u.coins || 0), 0) || 0;
    
    res.json({
        success: true,
        stats: {
            totalKeys: totalKeys || 0,
            activeKeys: activeKeys || 0,
            totalUsers: totalUsers || 0,
            resellers: resellers || 0,
            totalCoins: coinSum
        }
    });
});

// Get all keys (admin)
app.post('/api/admin/keys', verifyAdmin, async (req, res) => {
    const { data: keys } = await supabase.from('keys').select('*').order('created_at', { ascending: false }).limit(500);
    res.json({ success: true, keys: keys || [] });
});

// Admin add key (with custom settings)
app.post('/api/admin/add-key', verifyAdmin, async (req, res) => {
    const { userId, days, hours, minutes, maxDevices, keyText } = req.body;
    const totalHours = (days * 24) + hours + (minutes / 60);
    const expiryMs = Date.now() + (totalHours * 3600000);
    const newKey = keyText || generateKey();
    
    await supabase.from('keys').insert({
        key_text: newKey,
        user_id: userId,
        duration_hours: totalHours,
        duration_days: days,
        duration_minutes: minutes,
        expiry_ms: expiryMs,
        created_at: Date.now(),
        status: 'active',
        is_admin_key: 1,
        created_by: 'admin',
        max_devices: maxDevices || 1
    });
    
    res.json({ success: true, key: newKey, expiryFormatted: new Date(expiryMs).toLocaleString() });
});

// Admin delete key
app.post('/api/admin/delete-key', verifyAdmin, async (req, res) => {
    const { key } = req.body;
    await supabase.from('key_sessions').delete().eq('key_text', key);
    await supabase.from('key_devices').delete().eq('key_text', key);
    await supabase.from('keys').delete().eq('key_text', key);
    res.json({ success: true });
});

// Admin login
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === ADMIN_PASSWORD) {
        adminToken = crypto.randomBytes(32).toString('hex');
        adminTokenExpiry = Date.now() + 3600000;
        res.json({ success: true, token: adminToken });
    } else {
        res.json({ success: false, error: 'Invalid credentials' });
    }
});

// Admin logout
app.post('/api/admin/logout', verifyAdmin, async (req, res) => {
    adminToken = null;
    adminTokenExpiry = null;
    res.json({ success: true });
});

// Maintenance APIs
app.post('/api/admin/maintenance/settings', verifyAdmin, async (req, res) => {
    const { data: settings } = await supabase.from('system_settings').select('*');
    const result = {};
    settings?.forEach(s => { result[s.key] = s.value; });
    res.json({ success: true, settings: result });
});

app.post('/api/admin/maintenance/enable', verifyAdmin, async (req, res) => {
    const { message, estimatedTime } = req.body;
    await supabase.from('system_settings').upsert({ key: 'maintenance_mode', value: 'true', updated_at: Date.now() });
    if (message) await supabase.from('system_settings').upsert({ key: 'maintenance_message', value: message, updated_at: Date.now() });
    if (estimatedTime) await supabase.from('system_settings').upsert({ key: 'maintenance_estimated_time', value: estimatedTime, updated_at: Date.now() });
    res.json({ success: true });
});

app.post('/api/admin/maintenance/disable', verifyAdmin, async (req, res) => {
    await supabase.from('system_settings').upsert({ key: 'maintenance_mode', value: 'false', updated_at: Date.now() });
    res.json({ success: true });
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: Date.now() });
});

// ============================================================
// START SERVER
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 NEXUS SERVER running on port ${PORT}`);
    console.log(`🔐 Admin login: admin / ${ADMIN_PASSWORD}`);
    console.log(`✅ Reseller system ready`);
    console.log(`✅ Multi-language ready`);
    console.log(`✅ Payment gateway ready (Pakasir)`);
});

module.exports = app;