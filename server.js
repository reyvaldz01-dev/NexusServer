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
// CONFIGURATION
// ============================================================
const ADMIN_PASSWORD = "67";
const PAKASIR_API_KEY = "YOUR_PAKASIR_API_KEY";
const PAKASIR_API_URL = "https://app.pakasir.com/api/v1";

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
    return `${prefix}-${timestamp}-${checksum}`;
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
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
}

async function getSetting(key, defaultValue = 'false') {
    try {
        const { data } = await supabase.from('settings').select('value').eq('key', key).maybeSingle();
        return data?.value || defaultValue;
    } catch { return defaultValue; }
}

async function isMaintenanceMode() {
    try {
        const { data } = await supabase.from('system_settings').select('value').eq('key', 'maintenance_mode').single();
        return data?.value === 'true';
    } catch { return false; }
}

// ============================================================
// MIDDLEWARE
// ============================================================
app.use('/api/', async (req, res, next) => {
    if (req.path.includes('/admin/') || req.path === '/api/health' || req.path === '/api/maintenance-status') return next();
    const maintenance = await isMaintenanceMode();
    if (maintenance) return res.status(503).json({ success: false, maintenance: true, error: 'Service temporarily unavailable' });
    next();
});

function verifyAdmin(req, res, next) {
    const token = req.body.token || req.query.token;
    if (!token || token !== adminToken || (adminTokenExpiry && Date.now() > adminTokenExpiry)) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    next();
}

// Rate limiting
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: 'Too many requests' } });
const strictLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, message: { error: 'Rate limit exceeded' } });
app.use('/api/verify-key', strictLimiter);
app.use('/api/claim', limiter);

// ============================================================
// PUBLIC API
// ============================================================
app.get('/api/health', (req, res) => res.json({ status: 'healthy', timestamp: Date.now() }));
app.get('/api/maintenance-status', async (req, res) => {
    res.json({ success: true, maintenance: await isMaintenanceMode() });
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
    const { userId, durationHours = 3, bindingType = 'device' } = req.body;
    const ip = getClientIp(req);
    const deviceFp = generateDeviceFingerprint(req);
    
    const { data: user } = await supabase.from('users').select('*').eq('user_id', userId).single();
    if (!user) return res.json({ success: false, error: 'User not found' });
    if (user.step2_completed !== 1) return res.json({ success: false, error: 'Complete both steps first' });
    if (user.reward_claimed === 1) return res.json({ success: false, error: 'Reward already claimed' });
    
    const maxKeysPerUser = parseInt(await getSetting('max_keys_per_user', '5'));
    const { count: userKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true }).eq('user_id', userId).eq('status', 'active');
    if (userKeys >= maxKeysPerUser) return res.json({ success: false, error: `Maximum ${maxKeysPerUser} keys per user` });
    
    let lockedIp = null, lockedDeviceFp = null, bindingMessage = '';
    switch(bindingType) {
        case 'ip': lockedIp = ip; bindingMessage = 'Bound to IP'; break;
        case 'device': lockedDeviceFp = deviceFp; bindingMessage = 'Bound to Device'; break;
        case 'both': lockedIp = ip; lockedDeviceFp = deviceFp; bindingMessage = 'Bound to IP & Device'; break;
        case 'none': lockedIp = '0.0.0.0'; bindingMessage = 'No Binding'; break;
        default: lockedDeviceFp = deviceFp; bindingMessage = 'Bound to Device';
    }
    
    const newKey = generateKey();
    const expiryMs = Date.now() + (durationHours * 3600000);
    
    await supabase.from('keys').insert({
        key_text: newKey, user_id: userId, duration_hours: durationHours, expiry_ms: expiryMs,
        created_at: Date.now(), status: 'active', locked_ip: lockedIp, locked_device_fingerprint: lockedDeviceFp,
        binding_type: bindingType, max_devices: 1
    });
    
    await supabase.from('users').update({ reward_claimed: 1, keys_generated: (user.keys_generated || 0) + 1 }).eq('user_id', userId);
    
    const sessionToken = generateSessionToken();
    await supabase.from('key_sessions').insert({ key_text: newKey, session_token: sessionToken, ip_address: ip, created_at: Date.now(), expires_at: expiryMs, is_active: true });
    
    res.json({ success: true, key: newKey, sessionToken, duration: durationHours, expiryFormatted: new Date(expiryMs).toLocaleString(), bindingType, bindingMessage });
});

app.get('/api/my-key/:userId', async (req, res) => {
    const { data: key } = await supabase.from('keys').select('*').eq('user_id', req.params.userId).eq('status', 'active').gt('expiry_ms', Date.now()).maybeSingle();
    if (!key) return res.json({ hasKey: false });
    res.json({ hasKey: true, key: key.key_text, duration: key.duration_hours, remaining: formatTimeRemaining(key.expiry_ms), bindingType: key.binding_type });
});

app.post('/api/verify-key', async (req, res) => {
    const { key, sessionToken } = req.body;
    const userIp = getClientIp(req);
    const deviceFp = generateDeviceFingerprint(req);
    
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
    
    const bindingType = keyData.binding_type || 'device';
    
    if ((bindingType === 'ip' || bindingType === 'both') && keyData.locked_ip && keyData.locked_ip !== '0.0.0.0' && keyData.locked_ip !== userIp) {
        return res.json({ valid: false, error: `🔒 Locked to IP: ${keyData.locked_ip}` });
    }
    
    if ((bindingType === 'device' || bindingType === 'both') && keyData.locked_device_fingerprint && keyData.locked_device_fingerprint !== deviceFp) {
        return res.json({ valid: false, error: '🔒 Locked to different device' });
    }
    
    if (!keyData.locked_ip && !keyData.locked_device_fingerprint && bindingType !== 'none') {
        let updateData = {};
        if (bindingType === 'ip' || bindingType === 'both') updateData.locked_ip = userIp;
        if (bindingType === 'device' || bindingType === 'both') updateData.locked_device_fingerprint = deviceFp;
        updateData.first_used_at = Date.now();
        updateData.used_count = 1;
        
        await supabase.from('keys').update(updateData).eq('key_text', key);
        
        const newSessionToken = generateSessionToken();
        await supabase.from('key_sessions').insert({ key_text: key, session_token: newSessionToken, device_fingerprint: deviceFp, ip_address: userIp, created_at: Date.now(), expires_at: keyData.expiry_ms, is_active: true });
        
        let lockMessage = bindingType === 'both' ? 'IP & Device' : (bindingType === 'ip' ? 'IP' : 'Device');
        return res.json({ valid: true, key: keyData.key_text, sessionToken: newSessionToken, duration: keyData.duration_hours, remaining: formatTimeRemaining(keyData.expiry_ms), message: `✅ Locked to ${lockMessage}` });
    }
    
    if (bindingType === 'none') {
        await supabase.from('keys').update({ used_count: (keyData.used_count || 0) + 1 }).eq('key_text', key);
        return res.json({ valid: true, key: keyData.key_text, duration: keyData.duration_hours, remaining: formatTimeRemaining(keyData.expiry_ms), message: '✅ Key valid' });
    }
    
    await supabase.from('keys').update({ used_count: (keyData.used_count || 0) + 1 }).eq('key_text', key);
    return res.json({ valid: true, key: keyData.key_text, duration: keyData.duration_hours, remaining: formatTimeRemaining(keyData.expiry_ms), message: '✅ Key valid' });
});

// ============================================================
// RESELLER API
// ============================================================
const RESELLER_DURATIONS = [
    { days: 1, coins: 5, label: '1 Day' },
    { days: 3, coins: 12, label: '3 Days' },
    { days: 7, coins: 25, label: '7 Days' },
    { days: 15, coins: 45, label: '15 Days' },
    { days: 30, coins: 80, label: '30 Days' }
];

const RESELLER_DEVICE_LIMITS = [
    { limit: 1, extra: 0, label: '1 Device' },
    { limit: 10, extra: 10, label: '10 Devices' },
    { limit: 20, extra: 18, label: '20 Devices' },
    { limit: 30, extra: 25, label: '30 Devices' },
    { limit: 50, extra: 40, label: '50 Devices' }
];

function calculateResellerPrice(durationDays, deviceLimit) {
    const duration = RESELLER_DURATIONS.find(d => d.days === durationDays);
    const device = RESELLER_DEVICE_LIMITS.find(d => d.limit === deviceLimit);
    return (duration?.coins || 5) + (device?.extra || 0);
}

app.post('/api/reseller/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.json({ success: false, error: 'Username and password required' });
        
        const { data: user } = await supabase.from('users').select('user_id, coins, role, reseller_password, reseller_approved').eq('user_id', username).single();
        if (!user || user.role !== 'reseller') return res.json({ success: false, error: 'Invalid credentials' });
        if (user.reseller_password !== password) return res.json({ success: false, error: 'Invalid credentials' });
        if (!user.reseller_approved) return res.json({ success: false, error: 'Account not approved' });
        
        const token = generateSessionToken();
        await supabase.from('key_sessions').insert({ session_token: token, key_text: `reseller_${username}`, ip_address: getClientIp(req), created_at: Date.now(), expires_at: Date.now() + 7 * 24 * 3600000, is_active: true });
        
        res.json({ success: true, token, user: { user_id: user.user_id, coins: user.coins || 0 } });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.post('/api/reseller/create-key', async (req, res) => {
    try {
        const { userId, durationDays, deviceLimit, buyerEmail, bindingType = 'device' } = req.body;
        if (!userId) return res.json({ success: false, error: 'User ID required' });
        
        const validDurations = [1, 3, 7, 15, 30];
        const validDeviceLimits = [1, 10, 20, 30, 50];
        if (!validDurations.includes(durationDays)) return res.json({ success: false, error: 'Invalid duration' });
        if (!validDeviceLimits.includes(deviceLimit)) return res.json({ success: false, error: 'Invalid device limit' });
        
        const { data: reseller } = await supabase.from('users').select('*').eq('user_id', userId).single();
        if (!reseller || reseller.role !== 'reseller') return res.json({ success: false, error: 'Reseller not found' });
        
        const price = calculateResellerPrice(durationDays, deviceLimit);
        if (reseller.coins < price) return res.json({ success: false, error: `Insufficient coins! Need ${price}, you have ${reseller.coins}` });
        
        const newKey = generateKey();
        const expiryMs = Date.now() + (durationDays * 24 * 3600000);
        const newBalance = reseller.coins - price;
        
        await supabase.from('users').update({ coins: newBalance }).eq('user_id', userId);
        await supabase.from('coin_transactions').insert({ user_id: userId, amount: -price, type: 'purchase', reason: `Created ${durationDays}d ${deviceLimit}d key`, created_at: Date.now(), created_by: userId });
        
        await supabase.from('keys').insert({
            key_text: newKey, user_id: userId, duration_hours: durationDays * 24, duration_days: durationDays,
            expiry_ms: expiryMs, created_at: Date.now(), status: 'active', created_by: 'reseller',
            max_devices: deviceLimit, binding_type: bindingType
        });
        
        await supabase.from('reseller_keys').insert({
            key_text: newKey, reseller_id: userId, duration_days: durationDays,
            max_devices: deviceLimit, price_coins: price, buyer_email: buyerEmail || null,
            binding_type: bindingType, created_at: Date.now()
        });
        
        res.json({ success: true, key: newKey, expiryFormatted: new Date(expiryMs).toLocaleString(), remainingCoins: newBalance, price, durationDays, deviceLimit, bindingType });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.post('/api/reseller/balance', async (req, res) => {
    const { userId } = req.body;
    if (!userId) return res.json({ success: false, error: 'User ID required' });
    const { data: user } = await supabase.from('users').select('user_id, coins').eq('user_id', userId).single();
    res.json({ success: true, coins: user?.coins || 0, userId: user?.user_id });
});

app.post('/api/reseller/history', async (req, res) => {
    const { userId } = req.body;
    if (!userId) return res.json({ success: false, error: 'User ID required' });
    const [keys, transactions] = await Promise.all([
        supabase.from('reseller_keys').select('*').eq('reseller_id', userId).order('created_at', { ascending: false }).limit(50),
        supabase.from('coin_transactions').select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(50)
    ]);
    res.json({ success: true, keys: keys.data || [], transactions: transactions.data || [] });
});

// ============================================================
// ADMIN API
// ============================================================
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === ADMIN_PASSWORD) {
        adminToken = crypto.randomBytes(32).toString('hex');
        adminTokenExpiry = Date.now() + 3600000;
        res.json({ success: true, token: adminToken });
    } else {
        res.json({ success: false, error: 'Invalid credentials' });
    }
});

app.post('/api/admin/logout', verifyAdmin, (req, res) => {
    adminToken = null;
    adminTokenExpiry = null;
    res.json({ success: true });
});

app.post('/api/admin/stats', verifyAdmin, async (req, res) => {
    const [{ count: totalKeys }, { count: activeKeys }, { count: totalUsers }, { count: resellers }, { count: totalDevices }] = await Promise.all([
        supabase.from('keys').select('*', { count: 'exact', head: true }),
        supabase.from('keys').select('*', { count: 'exact', head: true }).eq('status', 'active'),
        supabase.from('users').select('*', { count: 'exact', head: true }),
        supabase.from('users').select('*', { count: 'exact', head: true }).eq('role', 'reseller'),
        supabase.from('key_devices').select('*', { count: 'exact', head: true }).eq('is_active', true)
    ]);
    const { data: coinsData } = await supabase.from('users').select('coins');
    const totalCoins = coinsData?.reduce((sum, u) => sum + (u.coins || 0), 0) || 0;
    
    res.json({ success: true, stats: { totalKeys: totalKeys || 0, activeKeys: activeKeys || 0, totalUsers: totalUsers || 0, resellers: resellers || 0, totalCoins, totalDevices: totalDevices || 0 } });
});

app.post('/api/admin/keys', verifyAdmin, async (req, res) => {
    const { data: keys } = await supabase.from('keys').select('*').order('created_at', { ascending: false }).limit(500);
    res.json({ success: true, keys: keys || [] });
});

app.post('/api/admin/add-key', verifyAdmin, async (req, res) => {
    const { userId, days = 0, hours = 3, minutes = 0, maxDevices = 1, keyText, bindingType = 'device' } = req.body;
    const totalHours = (days * 24) + hours + (minutes / 60);
    const expiryMs = Date.now() + (totalHours * 3600000);
    const newKey = keyText || generateKey();
    
    await supabase.from('keys').insert({
        key_text: newKey, user_id: userId, duration_hours: totalHours, duration_days: days, duration_minutes: minutes,
        expiry_ms: expiryMs, created_at: Date.now(), status: 'active', is_admin_key: 1, created_by: 'admin',
        max_devices: maxDevices, binding_type: bindingType
    });
    res.json({ success: true, key: newKey, expiryFormatted: new Date(expiryMs).toLocaleString(), bindingType });
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

app.post('/api/admin/resellers', verifyAdmin, async (req, res) => {
    const { data: resellers } = await supabase.from('users').select('*').eq('role', 'reseller').order('created_at', { ascending: false });
    res.json({ success: true, resellers: resellers || [] });
});

app.post('/api/admin/create-reseller', verifyAdmin, async (req, res) => {
    const { username, password, initialCoins = 0 } = req.body;
    const { data: existing } = await supabase.from('users').select('user_id').eq('user_id', username).maybeSingle();
    if (existing) return res.json({ success: false, error: 'Username exists' });
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
    const { data: devices } = await supabase.from('device_blacklist').select('*').order('banned_at', { ascending: false });
    res.json({ success: true, devices: devices || [] });
});

app.post('/api/admin/ban-device', verifyAdmin, async (req, res) => {
    const { deviceFingerprint, reason } = req.body;
    await supabase.from('device_blacklist').insert({ device_fingerprint: deviceFingerprint, reason: reason || 'No reason', banned_at: Date.now() });
    res.json({ success: true });
});

app.post('/api/admin/unban-device', verifyAdmin, async (req, res) => {
    await supabase.from('device_blacklist').delete().eq('device_fingerprint', req.body.deviceFingerprint);
    res.json({ success: true });
});

app.post('/api/admin/banned-ips', verifyAdmin, async (req, res) => {
    const { data: ips } = await supabase.from('ip_blacklist').select('*').order('banned_at', { ascending: false });
    res.json({ success: true, ips: ips || [] });
});

app.post('/api/admin/ban-ip', verifyAdmin, async (req, res) => {
    const { ip, reason } = req.body;
    await supabase.from('ip_blacklist').insert({ ip_address: ip, reason: reason || 'No reason', banned_at: Date.now() });
    res.json({ success: true });
});

app.post('/api/admin/unban-ip', verifyAdmin, async (req, res) => {
    await supabase.from('ip_blacklist').delete().eq('ip_address', req.body.ip);
    res.json({ success: true });
});

app.post('/api/admin/security-logs', verifyAdmin, async (req, res) => {
    const { data: logs } = await supabase.from('security_logs').select('*').order('timestamp', { ascending: false }).limit(200);
    res.json({ success: true, logs: logs || [] });
});

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
    res.json({ success: true });
});

app.post('/api/admin/maintenance/settings', verifyAdmin, async (req, res) => {
    const { data: settings } = await supabase.from('system_settings').select('*');
    const result = {};
    settings?.forEach(s => { result[s.key] = s.value; });
    res.json({ success: true, settings: { maintenance_mode: result.maintenance_mode || 'false', maintenance_message: result.maintenance_message || 'Server under maintenance', maintenance_estimated_time: result.maintenance_estimated_time || '30 minutes' } });
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

// ============================================================
// ENDPOINT YANG HILANG - TAMBAHKAN INI
// ============================================================

// 1. Delete expired keys
app.post('/api/admin/delete-expired-keys', verifyAdmin, async (req, res) => {
    try {
        const now = Date.now();
        const { data, error } = await supabase
            .from('keys')
            .update({ status: 'expired' })
            .lt('expiry_ms', now)
            .eq('status', 'active');
        
        res.json({ success: true, message: 'Expired keys deleted' });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 2. Delete all keys
app.post('/api/admin/delete-all-keys', verifyAdmin, async (req, res) => {
    try {
        await supabase.from('key_sessions').delete().neq('id', 0);
        await supabase.from('key_devices').delete().neq('id', 0);
        await supabase.from('keys').delete().neq('id', 0);
        res.json({ success: true, message: 'All keys deleted' });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 3. Bulk keys (add multiple keys at once)
app.post('/api/admin/add-bulk-keys', verifyAdmin, async (req, res) => {
    try {
        const { userId, count = 1, days = 0, hours = 3, minutes = 0, maxDevices = 1, bindingType = 'device' } = req.body;
        
        if (!userId) return res.json({ success: false, error: 'User ID required' });
        if (count > 100) return res.json({ success: false, error: 'Max 100 keys at once' });
        
        const totalHours = (days * 24) + hours + (minutes / 60);
        const expiryMs = Date.now() + (totalHours * 3600000);
        const keys = [];
        
        for (let i = 0; i < count; i++) {
            const newKey = generateKey();
            const { error } = await supabase.from('keys').insert({
                key_text: newKey, user_id: userId, duration_hours: totalHours, duration_days: days,
                expiry_ms: expiryMs, created_at: Date.now(), status: 'active', is_admin_key: 1,
                created_by: 'admin', max_devices: maxDevices, binding_type: bindingType
            });
            if (!error) keys.push(newKey);
        }
        
        res.json({ success: true, keys: keys, count: keys.length, expiryFormatted: new Date(expiryMs).toLocaleString() });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 4. Reseller keys history
app.post('/api/admin/reseller-keys', verifyAdmin, async (req, res) => {
    try {
        let query = supabase.from('reseller_keys').select('*').order('created_at', { ascending: false }).limit(200);
        if (req.body.resellerId) query = query.eq('reseller_id', req.body.resellerId);
        const { data } = await query;
        res.json({ success: true, keys: data || [] });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 5. Banned devices list
app.post('/api/admin/banned-devices', verifyAdmin, async (req, res) => {
    try {
        const { data } = await supabase.from('device_blacklist').select('*').order('banned_at', { ascending: false });
        res.json({ success: true, devices: data || [] });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 6. Ban device
app.post('/api/admin/ban-device', verifyAdmin, async (req, res) => {
    try {
        const { deviceFingerprint, reason } = req.body;
        if (!deviceFingerprint) return res.json({ success: false, error: 'Device fingerprint required' });
        await supabase.from('device_blacklist').insert({ device_fingerprint: deviceFingerprint, reason: reason || 'No reason', banned_at: Date.now() });
        res.json({ success: true, message: 'Device banned' });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 7. Unban device
app.post('/api/admin/unban-device', verifyAdmin, async (req, res) => {
    try {
        const { deviceFingerprint } = req.body;
        await supabase.from('device_blacklist').delete().eq('device_fingerprint', deviceFingerprint);
        res.json({ success: true, message: 'Device unbanned' });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 8. Banned IPs list
app.post('/api/admin/banned-ips', verifyAdmin, async (req, res) => {
    try {
        const { data } = await supabase.from('ip_blacklist').select('*').order('banned_at', { ascending: false });
        res.json({ success: true, ips: data || [] });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 9. Ban IP
app.post('/api/admin/ban-ip', verifyAdmin, async (req, res) => {
    try {
        const { ip, reason } = req.body;
        if (!ip) return res.json({ success: false, error: 'IP required' });
        await supabase.from('ip_blacklist').insert({ ip_address: ip, reason: reason || 'No reason', banned_at: Date.now() });
        res.json({ success: true, message: `IP ${ip} banned` });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 10. Unban IP
app.post('/api/admin/unban-ip', verifyAdmin, async (req, res) => {
    try {
        const { ip } = req.body;
        await supabase.from('ip_blacklist').delete().eq('ip_address', ip);
        res.json({ success: true, message: `IP ${ip} unbanned` });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 11. Security logs
app.post('/api/admin/security-logs', verifyAdmin, async (req, res) => {
    try {
        const { data } = await supabase.from('security_logs').select('*').order('timestamp', { ascending: false }).limit(200);
        res.json({ success: true, logs: data || [] });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 12. Announcements list
app.post('/api/admin/announcements', verifyAdmin, async (req, res) => {
    try {
        const { data } = await supabase.from('announcements').select('*').order('created_at', { ascending: false });
        res.json({ success: true, announcements: data || [] });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 13. Create announcement
app.post('/api/admin/create-announcement', verifyAdmin, async (req, res) => {
    try {
        const { title, content, type } = req.body;
        if (!title || !content) return res.json({ success: false, error: 'Title and content required' });
        await supabase.from('announcements').insert({
            title, content, type: type || 'info', is_active: true,
            start_date: Date.now(), end_date: Date.now() + 30 * 24 * 3600000,
            created_at: Date.now(), created_by: 'admin'
        });
        res.json({ success: true, message: 'Announcement created' });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 14. Delete announcement
app.post('/api/admin/delete-announcement', verifyAdmin, async (req, res) => {
    try {
        const { id } = req.body;
        await supabase.from('announcements').delete().eq('id', id);
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 15. Broadcast message
app.post('/api/admin/broadcast', verifyAdmin, async (req, res) => {
    try {
        const { title, message, targetRole } = req.body;
        let query = supabase.from('users').select('user_id');
        if (targetRole && targetRole !== 'all') query = query.eq('role', targetRole);
        const { data: users } = await query;
        
        const notifications = users.map(u => ({ user_id: u.user_id, title, message, type: 'broadcast', created_at: Date.now() }));
        if (notifications.length > 0) await supabase.from('user_notifications').insert(notifications);
        await supabase.from('broadcast_history').insert({ title, message, target_role: targetRole || 'all', total_sent: notifications.length, created_at: Date.now(), created_by: 'admin' });
        res.json({ success: true, totalSent: notifications.length });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 16. Broadcast history
app.post('/api/admin/broadcast-history', verifyAdmin, async (req, res) => {
    try {
        const { data } = await supabase.from('broadcast_history').select('*').order('created_at', { ascending: false });
        res.json({ success: true, broadcasts: data || [] });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 17. User notifications
app.get('/api/notifications/:userId', async (req, res) => {
    try {
        const { data } = await supabase.from('user_notifications').select('*').eq('user_id', req.params.userId).order('created_at', { ascending: false }).limit(50);
        res.json({ success: true, notifications: data || [] });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 18. Mark notification as read
app.post('/api/notifications/read', async (req, res) => {
    try {
        await supabase.from('user_notifications').update({ is_read: true }).eq('id', req.body.notificationId).eq('user_id', req.body.userId);
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});
// ============================================================
// START SERVER
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 NEXUS SERVER running on port ${PORT}`);
    console.log(`🔐 Admin: admin / ${ADMIN_PASSWORD}`);
    console.log(`✅ All endpoints ready`);
});

module.exports = app;