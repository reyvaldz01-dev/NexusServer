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
const PAKASIR_API_KEY = "YOUR_PAKASIR_API_KEY";
const PAKASIR_API_URL = "https://app.pakasir.com/api/v1";

// ============================================================
// ADMIN CONFIGURATION
// ============================================================
const ADMIN_PASSWORD = "67";
let adminToken = null;
let adminTokenExpiry = null;

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

function generateDeviceFingerprint(req) {
    const userAgent = req.headers['user-agent'] || '';
    const acceptLang = req.headers['accept-language'] || '';
    const platform = req.headers['sec-ch-ua-platform'] || '';
    const timezone = req.headers['timezone'] || Intl.DateTimeFormat().resolvedOptions().timeZone;
    const fingerprintString = `${userAgent}|${acceptLang}|${platform}|${timezone}`;
    return crypto.createHash('sha256').update(fingerprintString).digest('hex').substring(0, 64);
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

async function isMaintenanceMode() {
    try {
        const { data } = await supabase.from('system_settings').select('value').eq('key', 'maintenance_mode').single();
        return data?.value === 'true';
    } catch { return false; }
}

// Maintenance middleware
app.use('/api/', async (req, res, next) => {
    if (req.path.includes('/admin/') || req.path === '/api/health' || req.path === '/api/maintenance-status') return next();
    const maintenance = await isMaintenanceMode();
    if (maintenance) return res.status(503).json({ success: false, maintenance: true, error: 'Service temporarily unavailable' });
    next();
});

// Auth middleware
function verifyAdmin(req, res, next) {
    const token = req.body.token || req.query.token;
    if (!token || token !== adminToken || (adminTokenExpiry && Date.now() > adminTokenExpiry)) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    next();
}

async function verifyReseller(req, res, next) {
    const { username, password } = req.body;
    const { data: user } = await supabase.from('users').select('*').eq('user_id', username).eq('reseller_password', password).eq('role', 'reseller').maybeSingle();
    if (!user) return res.status(401).json({ success: false, error: 'Invalid reseller credentials' });
    req.reseller = user;
    next();
}

// ============================================================
// PUBLIC API
// ============================================================
app.get('/api/health', (req, res) => res.json({ status: 'healthy', timestamp: Date.now() }));

app.get('/api/maintenance-status', async (req, res) => {
    const maintenance = await isMaintenanceMode();
    res.json({ success: true, maintenance });
});

// Announcements
app.get('/api/announcements', async (req, res) => {
    const now = Date.now();
    const { data } = await supabase.from('announcements').select('*').eq('is_active', true).lt('start_date', now).gt('end_date', now).order('created_at', { ascending: false });
    res.json({ success: true, announcements: data || [] });
});

// Notifications
app.get('/api/notifications/:userId', async (req, res) => {
    const { data } = await supabase.from('user_notifications').select('*').eq('user_id', req.params.userId).order('created_at', { ascending: false }).limit(50);
    res.json({ success: true, notifications: data || [] });
});

app.post('/api/notifications/read', async (req, res) => {
    await supabase.from('user_notifications').update({ is_read: true }).eq('id', req.body.notificationId).eq('user_id', req.body.userId);
    res.json({ success: true });
});

// ============================================================
// USER CHALLENGE API
// ============================================================
app.post('/api/start', async (req, res) => {
    const { userId } = req.body;
    if (!userId) return res.json({ success: false, error: 'User ID required' });
    let { data: user } = await supabase.from('users').select('*').eq('user_id', userId).maybeSingle();
    if (!user) {
        const { data: newUser } = await supabase.from('users').insert({ user_id: userId, created_at: Date.now() }).select().single();
        user = newUser;
    }
    res.json({ success: true, step1_completed: user.step1_completed || 0, step2_completed: user.step2_completed || 0 });
});

app.post('/api/step1', async (req, res) => {
    const { userId } = req.body;
    const { data: user } = await supabase.from('users').select('*').eq('user_id', userId).single();
    if (!user) return res.json({ success: false, error: 'User not found' });
    if (user.step1_completed === 1) return res.json({ success: true, alreadyCompleted: true });
    await supabase.from('users').update({ step1_completed: 1, step1_completed_at: Date.now() }).eq('user_id', userId);
    res.json({ success: true });
});

app.post('/api/step2', async (req, res) => {
    const { userId } = req.body;
    const { data: user } = await supabase.from('users').select('*').eq('user_id', userId).single();
    if (!user) return res.json({ success: false, error: 'User not found' });
    if (user.step1_completed !== 1) return res.json({ success: false, error: 'Complete step 1 first' });
    if (user.step2_completed === 1) return res.json({ success: true, alreadyCompleted: true });
    await supabase.from('users').update({ step2_completed: 1, step2_completed_at: Date.now() }).eq('user_id', userId);
    res.json({ success: true });
});

app.post('/api/claim', async (req, res) => {
    const { userId, durationHours = 3 } = req.body;
    const ip = getClientIp(req);
    const { data: user } = await supabase.from('users').select('*').eq('user_id', userId).single();
    if (!user) return res.json({ success: false, error: 'User not found' });
    if (user.step2_completed !== 1) return res.json({ success: false, error: 'Complete both steps first' });
    if (user.reward_claimed === 1) return res.json({ success: false, error: 'Reward already claimed' });
    
    const maxKeysPerUser = parseInt(await getSetting('max_keys_per_user', '5'));
    const { count: userKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true }).eq('user_id', userId).eq('status', 'active');
    if (userKeys >= maxKeysPerUser) return res.json({ success: false, error: `Maximum ${maxKeysPerUser} keys per user` });
    
    const newKey = generateKey();
    const expiryMs = Date.now() + (durationHours * 3600000);
    await supabase.from('keys').insert({
        key_text: newKey, user_id: userId, duration_hours: durationHours, expiry_ms: expiryMs,
        created_at: Date.now(), status: 'active', locked_ip: ip, max_devices: 1
    });
    await supabase.from('users').update({ reward_claimed: 1, keys_generated: (user.keys_generated || 0) + 1 }).eq('user_id', userId);
    
    const sessionToken = generateSessionToken();
    await supabase.from('key_sessions').insert({ key_text: newKey, session_token: sessionToken, ip_address: ip, created_at: Date.now(), expires_at: expiryMs, is_active: true });
    
    res.json({ success: true, key: newKey, sessionToken: sessionToken, duration: durationHours, expiryFormatted: new Date(expiryMs).toLocaleString() });
});

app.get('/api/my-key/:userId', async (req, res) => {
    const { data: key } = await supabase.from('keys').select('*').eq('user_id', req.params.userId).eq('status', 'active').gt('expiry_ms', Date.now()).maybeSingle();
    if (!key) return res.json({ hasKey: false });
    res.json({ hasKey: true, key: key.key_text, duration: key.duration_hours, remaining: formatTimeRemaining(key.expiry_ms) });
});

app.post('/api/verify-key', async (req, res) => {
    const { key, sessionToken } = req.body;
    const userIp = getClientIp(req);
    if (!key) return res.json({ valid: false, error: 'Key required' });
    
    const { data: keyData } = await supabase.from('keys').select('*').eq('key_text', key).single();
    if (!keyData) return res.json({ valid: false, error: 'Key not found' });
    if (Date.now() > keyData.expiry_ms) return res.json({ valid: false, error: 'Key expired' });
    if (keyData.status !== 'active') return res.json({ valid: false, error: 'Key not active' });
    
    if (sessionToken) {
        const { data: session } = await supabase.from('key_sessions').select('*').eq('session_token', sessionToken).eq('key_text', key).eq('is_active', true).gt('expires_at', Date.now()).maybeSingle();
        if (session) {
            await supabase.from('key_sessions').update({ last_used_at: Date.now(), ip_address: userIp }).eq('session_token', sessionToken);
            return res.json({ valid: true, key: keyData.key_text, duration: keyData.duration_hours, remaining: formatTimeRemaining(keyData.expiry_ms), message: '✅ Key valid' });
        }
    }
    
    if (!keyData.locked_ip) {
        await supabase.from('keys').update({ locked_ip: userIp, first_used_at: Date.now(), used_count: 1 }).eq('key_text', key);
        const newSessionToken = generateSessionToken();
        await supabase.from('key_sessions').insert({ key_text: key, session_token: newSessionToken, ip_address: userIp, created_at: Date.now(), expires_at: keyData.expiry_ms, is_active: true });
        return res.json({ valid: true, key: keyData.key_text, sessionToken: newSessionToken, duration: keyData.duration_hours, remaining: formatTimeRemaining(keyData.expiry_ms), message: '✅ Key locked' });
    }
    
    if (keyData.locked_ip !== userIp) return res.json({ valid: false, error: `🔒 Key locked to IP: ${keyData.locked_ip}` });
    await supabase.from('keys').update({ used_count: (keyData.used_count || 0) + 1 }).eq('key_text', key);
    return res.json({ valid: true, key: keyData.key_text, duration: keyData.duration_hours, remaining: formatTimeRemaining(keyData.expiry_ms), message: '✅ Key valid' });
});

// ============================================================
// RESELLER API
// ============================================================
const RESELLER_DURATIONS = [
    { days: 1, coins: 5 },
    { days: 3, coins: 12 },
    { days: 7, coins: 25 },
    { days: 15, coins: 45 },
    { days: 30, coins: 80 }
];

const RESELLER_DEVICE_LIMITS = [
    { limit: 1, extra: 0 },
    { limit: 10, extra: 10 },
    { limit: 20, extra: 18 },
    { limit: 30, extra: 25 },
    { limit: 50, extra: 40 }
];

function calculateResellerPrice(durationDays, deviceLimit) {
    const duration = RESELLER_DURATIONS.find(d => d.days === durationDays);
    const device = RESELLER_DEVICE_LIMITS.find(d => d.limit === deviceLimit);
    return (duration?.coins || 5) + (device?.extra || 0);
}

// RESELLER LOGIN
app.post('/api/reseller/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        console.log(`[RESELLER] Login attempt: ${username}`);
        
        if (!username || !password) {
            return res.json({ success: false, error: 'Username and password required' });
        }
        
        const { data: user, error } = await supabase
            .from('users')
            .select('user_id, coins, role, reseller_password, reseller_approved')
            .eq('user_id', username)
            .single();
        
        if (error || !user) {
            console.log(`[RESELLER] User not found: ${username}`);
            return res.json({ success: false, error: 'Invalid credentials' });
        }
        
        if (user.role !== 'reseller') {
            console.log(`[RESELLER] Not a reseller: ${username}, role: ${user.role}`);
            return res.json({ success: false, error: 'Account is not a reseller' });
        }
        
        if (user.reseller_password !== password) {
            console.log(`[RESELLER] Wrong password for: ${username}`);
            return res.json({ success: false, error: 'Invalid credentials' });
        }
        
        if (!user.reseller_approved) {
            return res.json({ success: false, error: 'Account not approved yet' });
        }
        
        console.log(`[RESELLER] Login success: ${username}, Coins: ${user.coins}`);
        
        const token = generateSessionToken();
        
        // Simpan session untuk reseller
        await supabase.from('key_sessions').insert({
            session_token: token,
            key_text: `reseller_${username}`,
            ip_address: getClientIp(req),
            created_at: Date.now(),
            expires_at: Date.now() + 7 * 24 * 3600000,
            is_active: true
        });
        
        res.json({
            success: true,
            token: token,
            user: {
                user_id: user.user_id,
                coins: user.coins || 0,
                language: 'id'
            }
        });
        
    } catch (err) {
        console.error('[RESELLER] Login error:', err);
        res.json({ success: false, error: err.message });
    }
});

// RESELLER GET BALANCE
app.post('/api/reseller/balance', async (req, res) => {
    try {
        const { token, userId } = req.body;
        
        if (!token && !userId) {
            return res.json({ success: false, error: 'Authentication required' });
        }
        
        let resellerId = userId;
        
        // Jika pakai token, cari user dari session
        if (token && !userId) {
            const { data: session } = await supabase
                .from('key_sessions')
                .select('key_text')
                .eq('session_token', token)
                .eq('is_active', true)
                .single();
            
            if (session && session.key_text.startsWith('reseller_')) {
                resellerId = session.key_text.replace('reseller_', '');
            }
        }
        
        if (!resellerId) {
            return res.json({ success: false, error: 'User ID required' });
        }
        
        const { data: user } = await supabase
            .from('users')
            .select('user_id, coins')
            .eq('user_id', resellerId)
            .single();
        
        if (!user) {
            return res.json({ success: false, error: 'User not found' });
        }
        
        res.json({ success: true, coins: user.coins || 0, userId: user.user_id });
        
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// RESELLER CREATE KEY
app.post('/api/reseller/create-key', async (req, res) => {
    try {
        const { userId, durationDays, deviceLimit, buyerEmail } = req.body;
        
        console.log(`[RESELLER] Create key request - User: ${userId}, Duration: ${durationDays}, Device: ${deviceLimit}`);
        
        if (!userId) {
            return res.json({ success: false, error: 'User ID required' });
        }
        
        // Validasi durasi dan device limit
        const validDurations = [1, 3, 7, 15, 30];
        const validDeviceLimits = [1, 10, 20, 30, 50];
        
        if (!validDurations.includes(durationDays)) {
            return res.json({ success: false, error: 'Invalid duration. Choose: 1, 3, 7, 15, 30' });
        }
        if (!validDeviceLimits.includes(deviceLimit)) {
            return res.json({ success: false, error: 'Invalid device limit. Choose: 1, 10, 20, 30, 50' });
        }
        
        // Cek reseller
        const { data: reseller, error: userError } = await supabase
            .from('users')
            .select('*')
            .eq('user_id', userId)
            .single();
        
        if (userError || !reseller) {
            return res.json({ success: false, error: 'Reseller not found' });
        }
        
        if (reseller.role !== 'reseller') {
            return res.json({ success: false, error: 'Account is not a reseller' });
        }
        
        const price = calculateResellerPrice(durationDays, deviceLimit);
        
        console.log(`[RESELLER] Price: ${price} coins, Current coins: ${reseller.coins}`);
        
        if (reseller.coins < price) {
            return res.json({ 
                success: false, 
                error: `Insufficient coins! Need ${price} coins, you have ${reseller.coins}`,
                needed: price,
                current: reseller.coins
            });
        }
        
        // Generate key
        const newKey = generateKey();
        const expiryMs = Date.now() + (durationDays * 24 * 3600000);
        
        // Kurangi coins reseller
        const newBalance = reseller.coins - price;
        await supabase
            .from('users')
            .update({ coins: newBalance })
            .eq('user_id', userId);
        
        // Catat transaksi coin
        await supabase
            .from('coin_transactions')
            .insert({
                user_id: userId,
                amount: -price,
                type: 'purchase',
                reason: `Created key for ${durationDays} days, ${deviceLimit} devices`,
                created_at: Date.now(),
                created_by: userId
            });
        
        // Buat key di tabel keys
        await supabase
            .from('keys')
            .insert({
                key_text: newKey,
                user_id: userId,
                duration_hours: durationDays * 24,
                duration_days: durationDays,
                expiry_ms: expiryMs,
                created_at: Date.now(),
                status: 'active',
                created_by: 'reseller',
                max_devices: deviceLimit,
                current_devices: 0
            });
        
        // Catat di reseller_keys
        await supabase
            .from('reseller_keys')
            .insert({
                key_text: newKey,
                reseller_id: userId,
                duration_days: durationDays,
                max_devices: deviceLimit,
                price_coins: price,
                buyer_email: buyerEmail || null,
                status: 'active',
                created_at: Date.now()
            });
        
        console.log(`[RESELLER] Key created: ${newKey} for ${userId}, Remaining coins: ${newBalance}`);
        
        res.json({
            success: true,
            key: newKey,
            expiryFormatted: new Date(expiryMs).toLocaleString(),
            remainingCoins: newBalance,
            price: price,
            durationDays: durationDays,
            deviceLimit: deviceLimit,
            message: `✅ Key created successfully! Remaining coins: ${newBalance}`
        });
        
    } catch (err) {
        console.error('[RESELLER] Create key error:', err);
        res.json({ success: false, error: err.message });
    }
});

// RESELLER GET HISTORY
app.post('/api/reseller/history', async (req, res) => {
    try {
        const { userId } = req.body;
        
        if (!userId) {
            return res.json({ success: false, error: 'User ID required' });
        }
        
        // Ambil keys yang dibuat reseller
        const { data: keys } = await supabase
            .from('reseller_keys')
            .select('*')
            .eq('reseller_id', userId)
            .order('created_at', { ascending: false })
            .limit(50);
        
        // Ambil transaksi coin
        const { data: transactions } = await supabase
            .from('coin_transactions')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(50);
        
        res.json({ 
            success: true, 
            keys: keys || [], 
            transactions: transactions || [] 
        });
        
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// RESELLER UPDATE LANGUAGE
app.post('/api/reseller/language', async (req, res) => {
    try {
        const { userId, language } = req.body;
        
        await supabase
            .from('users')
            .update({ language: language || 'id' })
            .eq('user_id', userId);
        
        res.json({ success: true });
        
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ============================================================
// PAYMENT API (PAKASIR)
// ============================================================
app.post('/api/create-payment', async (req, res) => {
    const { userId, coins, paymentMethod } = req.body;
    const pakasirPayload = {
        api_key: PAKASIR_API_KEY, amount: coins * 100, customer_name: userId, customer_email: `${userId}@nexus.com`,
        payment_method: paymentMethod || 'qris', return_url: 'https://your-domain.com/payment-callback.html',
        expired_time: 24, order_id: `INV-${Date.now()}-${userId}`
    };
    try {
        const response = await axios.post(`${PAKASIR_API_URL}/create-transaction`, pakasirPayload, { headers: { 'Content-Type': 'application/json' } });
        if (response.data?.data) {
            await supabase.from('payment_transactions').insert({ transaction_id: response.data.data.reference, user_id: userId, amount: coins * 100, coins: coins, payment_url: response.data.data.checkout_url, status: 'pending', created_at: Date.now() });
            res.json({ success: true, paymentUrl: response.data.data.checkout_url, transactionId: response.data.data.reference });
        } else { res.json({ success: false, error: 'Payment creation failed' }); }
    } catch (error) { console.error('Pakasir error:', error.message); res.json({ success: false, error: 'Payment gateway error' }); }
});

app.post('/api/payment-webhook', async (req, res) => {
    const { reference, status } = req.body;
    if (status === 'success') {
        const { data: transaction } = await supabase.from('payment_transactions').select('*').eq('transaction_id', reference).single();
        if (transaction && transaction.status === 'pending') {
            await supabase.from('payment_transactions').update({ status: 'completed', completed_at: Date.now() }).eq('transaction_id', reference);
            const { data: user } = await supabase.from('users').select('coins').eq('user_id', transaction.user_id).single();
            await supabase.from('users').update({ coins: (user.coins || 0) + transaction.coins }).eq('user_id', transaction.user_id);
            await supabase.from('coin_transactions').insert({ user_id: transaction.user_id, amount: transaction.coins, type: 'add', reason: 'Topup via Pakasir', created_at: Date.now(), created_by: 'system' });
        }
    }
    res.json({ success: true });
});

app.post('/api/check-payment', async (req, res) => {
    const { transactionId } = req.body;
    const { data: transaction } = await supabase.from('payment_transactions').select('*').eq('transaction_id', transactionId).single();
    if (!transaction) return res.json({ status: 'not_found', error: 'Transaction not found' });
    res.json({ status: transaction.status, coins: transaction.coins, amount: transaction.amount });
});

// ============================================================
// ADMIN API - RESELLER MANAGEMENT
// ============================================================
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === ADMIN_PASSWORD) {
        adminToken = crypto.randomBytes(32).toString('hex');
        adminTokenExpiry = Date.now() + 3600000;
        res.json({ success: true, token: adminToken });
    } else { res.json({ success: false, error: 'Invalid credentials' }); }
});

app.post('/api/admin/logout', verifyAdmin, (req, res) => {
    adminToken = null; adminTokenExpiry = null;
    res.json({ success: true });
});

app.post('/api/admin/stats', verifyAdmin, async (req, res) => {
    const { count: totalKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true });
    const { count: activeKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true }).eq('status', 'active');
    const { count: totalUsers } = await supabase.from('users').select('*', { count: 'exact', head: true });
    const { count: resellers } = await supabase.from('users').select('*', { count: 'exact', head: true }).eq('role', 'reseller');
    const { data: coinsData } = await supabase.from('users').select('coins');
    const totalCoins = coinsData?.reduce((sum, u) => sum + (u.coins || 0), 0) || 0;
    const { count: totalDevices } = await supabase.from('key_devices').select('*', { count: 'exact', head: true }).eq('is_active', true);
    res.json({ success: true, stats: { totalKeys: totalKeys || 0, activeKeys: activeKeys || 0, totalUsers: totalUsers || 0, resellers: resellers || 0, totalCoins, totalDevices: totalDevices || 0 } });
});

app.post('/api/admin/keys', verifyAdmin, async (req, res) => {
    const { data: keys } = await supabase.from('keys').select('*').order('created_at', { ascending: false }).limit(500);
    res.json({ success: true, keys: keys || [] });
});

app.post('/api/admin/add-key', verifyAdmin, async (req, res) => {
    const { userId, days = 0, hours = 3, minutes = 0, maxDevices = 1, keyText } = req.body;
    const totalHours = (days * 24) + hours + (minutes / 60);
    const expiryMs = Date.now() + (totalHours * 3600000);
    const newKey = keyText || generateKey();
    await supabase.from('keys').insert({ key_text: newKey, user_id: userId, duration_hours: totalHours, duration_days: days, duration_minutes: minutes, expiry_ms: expiryMs, created_at: Date.now(), status: 'active', is_admin_key: 1, created_by: 'admin', max_devices: maxDevices });
    res.json({ success: true, key: newKey, expiryFormatted: new Date(expiryMs).toLocaleString() });
});

app.post('/api/admin/delete-key', verifyAdmin, async (req, res) => {
    const { key } = req.body;
    await supabase.from('key_sessions').delete().eq('key_text', key);
    await supabase.from('key_devices').delete().eq('key_text', key);
    await supabase.from('keys').delete().eq('key_text', key);
    res.json({ success: true });
});

app.post('/api/admin/delete-all-keys', verifyAdmin, async (req, res) => {
    await supabase.from('key_sessions').delete().neq('id', 0);
    await supabase.from('key_devices').delete().neq('id', 0);
    await supabase.from('keys').delete().neq('id', 0);
    res.json({ success: true });
});

app.post('/api/admin/delete-expired-keys', verifyAdmin, async (req, res) => {
    await supabase.from('keys').update({ status: 'expired' }).lt('expiry_ms', Date.now()).eq('status', 'active');
    res.json({ success: true });
});

// Users
app.post('/api/admin/users', verifyAdmin, async (req, res) => {
    const { data: users } = await supabase.from('users').select('*').order('created_at', { ascending: false }).limit(500);
    res.json({ success: true, users: users || [] });
});

app.post('/api/admin/ban-user', verifyAdmin, async (req, res) => {
    await supabase.from('users').update({ banned: 1 }).eq('user_id', req.body.userId);
    res.json({ success: true });
});

app.post('/api/admin/unban-user', verifyAdmin, async (req, res) => {
    await supabase.from('users').update({ banned: 0 }).eq('user_id', req.body.userId);
    res.json({ success: true });
});

// Resellers
app.post('/api/admin/resellers', verifyAdmin, async (req, res) => {
    const { data: resellers } = await supabase.from('users').select('*').eq('role', 'reseller').order('created_at', { ascending: false });
    res.json({ success: true, resellers: resellers || [] });
});

app.post('/api/admin/create-reseller', verifyAdmin, async (req, res) => {
    const { username, password, initialCoins = 0 } = req.body;
    const { data: existing } = await supabase.from('users').select('user_id').eq('user_id', username).maybeSingle();
    if (existing) return res.json({ success: false, error: 'Username already exists' });
    await supabase.from('users').insert({ user_id: username, reseller_password: password, role: 'reseller', coins: initialCoins, reseller_approved: true, created_at: Date.now() });
    res.json({ success: true, message: `Reseller ${username} created with ${initialCoins} coins` });
});

app.post('/api/admin/add-coins', verifyAdmin, async (req, res) => {
    const { userId, amount, reason } = req.body;
    const { data: user } = await supabase.from('users').select('coins').eq('user_id', userId).single();
    if (!user) return res.json({ success: false, error: 'User not found' });
    const newBalance = (user.coins || 0) + amount;
    await supabase.from('users').update({ coins: newBalance }).eq('user_id', userId);
    await supabase.from('coin_transactions').insert({ user_id: userId, amount, type: amount > 0 ? 'add' : 'deduct', reason: reason || 'Admin adjustment', created_at: Date.now(), created_by: 'admin' });
    res.json({ success: true, newBalance });
});

app.post('/api/admin/coin-transactions', verifyAdmin, async (req, res) => {
    let query = supabase.from('coin_transactions').select('*').order('created_at', { ascending: false }).limit(200);
    if (req.body.userId) query = query.eq('user_id', req.body.userId);
    const { data } = await query;
    res.json({ success: true, transactions: data || [] });
});

app.post('/api/admin/reseller-keys', verifyAdmin, async (req, res) => {
    let query = supabase.from('reseller_keys').select('*').order('created_at', { ascending: false }).limit(200);
    if (req.body.resellerId) query = query.eq('reseller_id', req.body.resellerId);
    const { data } = await query;
    res.json({ success: true, keys: data || [] });
});

// Device Management
app.post('/api/admin/key-devices', verifyAdmin, async (req, res) => {
    const { key } = req.body;
    const { data: devices } = await supabase.from('key_devices').select('*').eq('key_text', key).eq('is_active', true).order('first_seen', { ascending: false });
    res.json({ success: true, devices: devices || [] });
});

app.post('/api/admin/remove-device', verifyAdmin, async (req, res) => {
    const { key, deviceFingerprint } = req.body;
    await supabase.from('key_devices').update({ is_active: false }).eq('key_text', key).eq('device_fingerprint', deviceFingerprint);
    const { count: currentDevices } = await supabase.from('key_devices').select('*', { count: 'exact', head: true }).eq('key_text', key).eq('is_active', true);
    await supabase.from('keys').update({ current_devices: currentDevices }).eq('key_text', key);
    res.json({ success: true });
});

app.post('/api/admin/banned-devices', verifyAdmin, async (req, res) => {
    const { data } = await supabase.from('device_blacklist').select('*').order('banned_at', { ascending: false });
    res.json({ success: true, devices: data || [] });
});

app.post('/api/admin/ban-device', verifyAdmin, async (req, res) => {
    const { deviceFingerprint, reason } = req.body;
    await supabase.from('device_blacklist').insert({ device_fingerprint: deviceFingerprint, reason: reason || 'No reason', banned_at: Date.now() });
    res.json({ success: true, message: 'Device banned' });
});

app.post('/api/admin/unban-device', verifyAdmin, async (req, res) => {
    await supabase.from('device_blacklist').delete().eq('device_fingerprint', req.body.deviceFingerprint);
    res.json({ success: true });
});

// IP Ban Management
app.post('/api/admin/banned-ips', verifyAdmin, async (req, res) => {
    const { data } = await supabase.from('ip_blacklist').select('*').order('banned_at', { ascending: false });
    res.json({ success: true, ips: data || [] });
});

app.post('/api/admin/ban-ip', verifyAdmin, async (req, res) => {
    const { ip, reason } = req.body;
    await supabase.from('ip_blacklist').insert({ ip_address: ip, reason: reason || 'No reason', banned_at: Date.now() });
    res.json({ success: true, message: `IP ${ip} banned` });
});

app.post('/api/admin/unban-ip', verifyAdmin, async (req, res) => {
    await supabase.from('ip_blacklist').delete().eq('ip_address', req.body.ip);
    res.json({ success: true });
});

// Security Logs
app.post('/api/admin/security-logs', verifyAdmin, async (req, res) => {
    const { data } = await supabase.from('security_logs').select('*').order('timestamp', { ascending: false }).limit(200);
    res.json({ success: true, logs: data || [] });
});

// Announcements
app.post('/api/admin/announcements', verifyAdmin, async (req, res) => {
    const { data } = await supabase.from('announcements').select('*').order('created_at', { ascending: false });
    res.json({ success: true, announcements: data || [] });
});

app.post('/api/admin/create-announcement', verifyAdmin, async (req, res) => {
    const { title, content, type, startDate, endDate } = req.body;
    await supabase.from('announcements').insert({ title, content, type: type || 'info', start_date: startDate || Date.now(), end_date: endDate || (Date.now() + 30 * 24 * 3600000), is_active: true, created_at: Date.now(), created_by: 'admin' });
    res.json({ success: true });
});

app.post('/api/admin/delete-announcement', verifyAdmin, async (req, res) => {
    await supabase.from('announcements').delete().eq('id', req.body.id);
    res.json({ success: true });
});

// Broadcast
app.post('/api/admin/broadcast', verifyAdmin, async (req, res) => {
    const { title, message, targetRole } = req.body;
    let query = supabase.from('users').select('user_id');
    if (targetRole && targetRole !== 'all') query = query.eq('role', targetRole);
    const { data: users } = await query;
    const notifications = users.map(u => ({ user_id: u.user_id, title, message, type: 'broadcast', created_at: Date.now() }));
    if (notifications.length > 0) await supabase.from('user_notifications').insert(notifications);
    await supabase.from('broadcast_history').insert({ title, message, target_role: targetRole || 'all', total_sent: notifications.length, created_at: Date.now(), created_by: 'admin' });
    res.json({ success: true, totalSent: notifications.length });
});

app.post('/api/admin/broadcast-history', verifyAdmin, async (req, res) => {
    const { data } = await supabase.from('broadcast_history').select('*').order('created_at', { ascending: false });
    res.json({ success: true, broadcasts: data || [] });
});

// Payments
app.post('/api/admin/payment-transactions', verifyAdmin, async (req, res) => {
    let query = supabase.from('payment_transactions').select('*').order('created_at', { ascending: false }).limit(200);
    if (req.body.userId) query = query.eq('user_id', req.body.userId);
    const { data } = await query;
    res.json({ success: true, transactions: data || [] });
});

// Settings
app.post('/api/admin/get-settings', verifyAdmin, async (req, res) => {
    const { data } = await supabase.from('settings').select('*');
    const settings = {};
    if (data) data.forEach(s => { settings[s.key] = s.value; });
    res.json({ success: true, settings: { default_max_devices: settings.default_max_devices || '1', max_keys_per_user: settings.max_keys_per_user || '5', default_duration_hours: settings.default_duration_hours || '3', ip_lock_enabled: settings.ip_lock_enabled || 'true', device_lock_enabled: settings.device_lock_enabled || 'true' } });
});

app.post('/api/admin/settings', verifyAdmin, async (req, res) => {
    const { default_max_devices, max_keys_per_user, default_duration_hours, ip_lock_enabled, device_lock_enabled } = req.body;
    if (default_max_devices !== undefined) await supabase.from('settings').upsert({ key: 'default_max_devices', value: default_max_devices.toString(), updated_at: Date.now() }, { onConflict: 'key' });
    if (max_keys_per_user !== undefined) await supabase.from('settings').upsert({ key: 'max_keys_per_user', value: max_keys_per_user.toString(), updated_at: Date.now() }, { onConflict: 'key' });
    if (default_duration_hours !== undefined) await supabase.from('settings').upsert({ key: 'default_duration_hours', value: default_duration_hours.toString(), updated_at: Date.now() }, { onConflict: 'key' });
    if (ip_lock_enabled !== undefined) await supabase.from('settings').upsert({ key: 'ip_lock_enabled', value: ip_lock_enabled, updated_at: Date.now() }, { onConflict: 'key' });
    if (device_lock_enabled !== undefined) await supabase.from('settings').upsert({ key: 'device_lock_enabled', value: device_lock_enabled, updated_at: Date.now() }, { onConflict: 'key' });
    res.json({ success: true, message: 'Settings saved' });
});

// Maintenance
app.post('/api/admin/maintenance/settings', verifyAdmin, async (req, res) => {
    const { data: settings } = await supabase.from('system_settings').select('*');
    const result = {};
    settings?.forEach(s => { result[s.key] = s.value; });
    res.json({ success: true, settings: { maintenance_mode: result.maintenance_mode || 'false', maintenance_message: result.maintenance_message || 'Server under maintenance', maintenance_estimated_time: result.maintenance_estimated_time || '30 minutes' } });
});

app.post('/api/admin/maintenance/enable', verifyAdmin, async (req, res) => {
    const { message, estimatedTime } = req.body;
    await supabase.from('system_settings').upsert({ key: 'maintenance_mode', value: 'true', updated_at: Date.now() }, { onConflict: 'key' });
    if (message) await supabase.from('system_settings').upsert({ key: 'maintenance_message', value: message, updated_at: Date.now() }, { onConflict: 'key' });
    if (estimatedTime) await supabase.from('system_settings').upsert({ key: 'maintenance_estimated_time', value: estimatedTime, updated_at: Date.now() }, { onConflict: 'key' });
    res.json({ success: true });
});

app.post('/api/admin/maintenance/disable', verifyAdmin, async (req, res) => {
    await supabase.from('system_settings').upsert({ key: 'maintenance_mode', value: 'false', updated_at: Date.now() }, { onConflict: 'key' });
    res.json({ success: true });
});

// ============================================================
// START SERVER
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 NEXUS SERVER running on port ${PORT}`);
    console.log(`🔐 Admin: admin / ${ADMIN_PASSWORD}`);
    console.log(`✅ All endpoints ready (60+ endpoints)`);
});

module.exports = app;