const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

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
// ADMIN CONFIGURATION
// ============================================================
const ADMIN_PASSWORD = "67";
let adminToken = null;
let adminTokenExpiry = null;

// ============================================================
// MAINTENANCE MODE FUNCTIONS
// ============================================================
async function isMaintenanceMode() {
    try {
        const { data } = await supabase
            .from('system_settings')
            .select('value')
            .eq('key', 'maintenance_mode')
            .single();
        return data?.value === 'true';
    } catch (error) {
        return false;
    }
}

async function getMaintenanceMessage() {
    try {
        const { data } = await supabase
            .from('system_settings')
            .select('value')
            .eq('key', 'maintenance_message')
            .single();
        return data?.value || 'Server is under maintenance. Please come back later.';
    } catch (error) {
        return 'Server is under maintenance. Please come back later.';
    }
}

// ============================================================
// MAINTENANCE MIDDLEWARE
// ============================================================
app.use('/api/', async (req, res, next) => {
    if (req.path.includes('/admin/') || req.path === '/api/health' || req.path === '/api/maintenance-status') {
        return next();
    }
    
    const maintenance = await isMaintenanceMode();
    if (maintenance) {
        const message = await getMaintenanceMessage();
        return res.status(503).json({
            success: false,
            maintenance: true,
            message: message,
            error: 'Service temporarily unavailable'
        });
    }
    next();
});

// ============================================================
// RATE LIMITING
// ============================================================
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, error: 'Too many requests, please try again later.' }
});

const strictLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    message: { success: false, error: 'Rate limit exceeded. Try again in an hour.' }
});

app.use('/api/verify-key', strictLimiter);
app.use('/api/claim', limiter);

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
    const seconds = Math.floor((remaining % 60000) / 1000);
    
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    if (minutes > 0) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
}

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || 
           req.headers['cf-connecting-ip'] || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress || 
           'unknown';
}

async function isIpBanned(ip) {
    if (!ip || ip === 'unknown') return false;
    const { data } = await supabase
        .from('ip_blacklist')
        .select('ip_address')
        .eq('ip_address', ip)
        .maybeSingle();
    return !!data;
}

async function isDeviceBanned(deviceFingerprint) {
    if (!deviceFingerprint) return false;
    const { data } = await supabase
        .from('device_blacklist')
        .select('device_fingerprint')
        .eq('device_fingerprint', deviceFingerprint)
        .maybeSingle();
    return !!data;
}

async function getSetting(key, defaultValue = 'false') {
    const { data } = await supabase
        .from('settings')
        .select('value')
        .eq('key', key)
        .maybeSingle();
    return data?.value || defaultValue;
}

async function logSecurityEvent(eventType, details, ip, deviceFp, userId = null) {
    await supabase.from('security_logs').insert({
        event_type: eventType,
        details: details,
        ip_address: ip,
        device_fingerprint: deviceFp,
        user_id: userId,
        timestamp: Date.now()
    });
}

async function incrementFailedAttempts(ip, deviceFp, key = null) {
    const today = new Date().toISOString().split('T')[0];
    
    const { data: record } = await supabase
        .from('failed_attempts')
        .select('attempts, id')
        .eq('ip_address', ip)
        .eq('date', today)
        .maybeSingle();
    
    let newAttempts = 1;
    
    if (record) {
        newAttempts = record.attempts + 1;
        await supabase
            .from('failed_attempts')
            .update({ attempts: newAttempts, last_key: key, device_fingerprint: deviceFp })
            .eq('id', record.id);
    } else {
        await supabase.from('failed_attempts').insert({
            ip_address: ip,
            device_fingerprint: deviceFp,
            date: today,
            attempts: 1,
            last_key: key
        });
    }
    
    if (newAttempts >= 10) {
        await supabase.from('ip_blacklist').insert({
            ip_address: ip,
            reason: `Auto-ban: ${newAttempts} failed key attempts in one day`,
            banned_at: Date.now()
        });
        await logSecurityEvent('AUTO_BAN', `IP auto-banned after ${newAttempts} failed attempts`, ip, deviceFp);
        return true;
    }
    return false;
}

// ============================================================
// DEVICE LIMIT FUNCTIONS
// ============================================================

async function registerDevice(keyText, deviceFingerprint, req) {
    const now = Date.now();
    const deviceName = req.headers['sec-ch-ua'] || req.headers['user-agent']?.substring(0, 100) || 'Unknown Device';
    
    const { data: existing } = await supabase
        .from('key_devices')
        .select('*')
        .eq('key_text', keyText)
        .eq('device_fingerprint', deviceFingerprint)
        .maybeSingle();
    
    if (existing) {
        await supabase
            .from('key_devices')
            .update({ last_seen: now, ip_address: getClientIp(req), user_agent: req.headers['user-agent'] })
            .eq('id', existing.id);
        return { success: true, isNew: false };
    }
    
    const { count: currentDevices } = await supabase
        .from('key_devices')
        .select('*', { count: 'exact', head: true })
        .eq('key_text', keyText)
        .eq('is_active', true);
    
    const { data: keyData } = await supabase
        .from('keys')
        .select('max_devices')
        .eq('key_text', keyText)
        .single();
    
    const maxDevices = keyData?.max_devices || parseInt(await getSetting('default_max_devices', '1'));
    
    if (currentDevices >= maxDevices) {
        return { success: false, error: `Maximum ${maxDevices} device(s) allowed for this key.` };
    }
    
    await supabase.from('key_devices').insert({
        key_text: keyText,
        device_fingerprint: deviceFingerprint,
        device_name: deviceName,
        ip_address: getClientIp(req),
        user_agent: req.headers['user-agent'],
        first_seen: now,
        last_seen: now,
        is_active: true
    });
    
    await supabase
        .from('keys')
        .update({ current_devices: currentDevices + 1 })
        .eq('key_text', keyText);
    
    return { success: true, isNew: true, currentDevices: currentDevices + 1, maxDevices: maxDevices };
}

async function getKeyDevices(keyText) {
    const { data: devices } = await supabase
        .from('key_devices')
        .select('*')
        .eq('key_text', keyText)
        .eq('is_active', true)
        .order('first_seen', { ascending: false });
    return devices || [];
}

// ============================================================
// AUTO DELETE EXPIRED KEYS
// ============================================================
async function deleteExpiredKeys() {
    try {
        const now = Date.now();
        await supabase
            .from('keys')
            .update({ status: 'expired' })
            .lt('expiry_ms', now)
            .eq('status', 'active');
        await supabase
            .from('key_sessions')
            .update({ is_active: false })
            .lt('expires_at', now)
            .eq('is_active', true);
    } catch (err) {
        console.error('Auto delete error:', err);
    }
}

setInterval(async () => {
    await deleteExpiredKeys();
}, 3600000);

setTimeout(async () => {
    await deleteExpiredKeys();
}, 5000);

// ============================================================
// MIDDLEWARE
// ============================================================
async function checkIpBan(req, res, next) {
    const ip = getClientIp(req);
    const banned = await isIpBanned(ip);
    if (banned) {
        return res.status(403).json({ success: false, error: 'Your IP has been banned' });
    }
    next();
}

function verifyAdmin(req, res, next) {
    const token = req.body.token || req.query.token;
    if (!token || token !== adminToken || (adminTokenExpiry && Date.now() > adminTokenExpiry)) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    next();
}

app.use('/api/', checkIpBan);

// ============================================================
// API: START CHALLENGE
// ============================================================
app.post('/api/start', async (req, res) => {
    try {
        const { userId } = req.body;
        const ip = getClientIp(req);
        
        if (!userId) return res.json({ success: false, error: 'User ID required' });
        
        let { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('user_id', userId)
            .maybeSingle();
        
        if (!user) {
            const { data: newUser } = await supabase
                .from('users')
                .insert({ user_id: userId, ip_address: ip, created_at: Date.now() })
                .select()
                .single();
            user = newUser;
        }
        
        res.json({ success: true, step1_completed: user.step1_completed || 0, step2_completed: user.step2_completed || 0 });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.post('/api/step1', async (req, res) => {
    try {
        const { userId } = req.body;
        if (!userId) return res.json({ success: false, error: 'User ID required' });
        
        const { data: user } = await supabase.from('users').select('*').eq('user_id', userId).single();
        if (!user) return res.json({ success: false, error: 'User not found' });
        
        if (user.step1_completed === 1) {
            return res.json({ success: true, alreadyCompleted: true, step: 2 });
        }
        
        await supabase.from('users').update({ step1_completed: 1, step1_completed_at: Date.now() }).eq('user_id', userId);
        res.json({ success: true, message: 'Step 1 completed! Now wait 100 seconds for step 2.', step: 2 });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.post('/api/step2', async (req, res) => {
    try {
        const { userId } = req.body;
        if (!userId) return res.json({ success: false, error: 'User ID required' });
        
        const { data: user } = await supabase.from('users').select('*').eq('user_id', userId).single();
        if (!user) return res.json({ success: false, error: 'User not found' });
        
        if (user.step1_completed !== 1) {
            return res.json({ success: false, error: 'Complete step 1 first!' });
        }
        
        if (user.step2_completed === 1) {
            return res.json({ success: true, alreadyCompleted: true });
        }
        
        await supabase.from('users').update({ step2_completed: 1, step2_completed_at: Date.now() }).eq('user_id', userId);
        res.json({ success: true, message: 'Step 2 completed! You can now claim your key.', canClaim: true });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.post('/api/claim', async (req, res) => {
    try {
        const { userId, durationHours = 3 } = req.body;
        const ip = getClientIp(req);
        
        if (!userId) return res.json({ success: false, error: 'User ID required' });
        
        const { data: user } = await supabase.from('users').select('*').eq('user_id', userId).single();
        if (!user) return res.json({ success: false, error: 'User not found' });
        
        if (user.step2_completed !== 1) return res.json({ success: false, error: 'Complete both steps first!' });
        if (user.reward_claimed === 1) return res.json({ success: false, error: 'Reward already claimed!' });
        
        const maxKeysPerUser = parseInt(await getSetting('max_keys_per_user', '5'));
        const { count: userKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true }).eq('user_id', userId).eq('status', 'active');
        if (userKeys >= maxKeysPerUser) return res.json({ success: false, error: `Maximum ${maxKeysPerUser} keys per user` });
        
        const newKey = generateKey();
        const expiryMs = Date.now() + (durationHours * 3600000);
        const defaultMaxDevices = parseInt(await getSetting('default_max_devices', '1'));
        
        await supabase.from('keys').insert({
            key_text: newKey, user_id: userId, duration_hours: durationHours, expiry_ms: expiryMs,
            created_at: Date.now(), status: 'active', is_admin_key: 0, created_by: 'user',
            locked_ip: ip, max_devices: defaultMaxDevices, current_devices: 0, binding_type: 'device'
        });
        
        await supabase.from('users').update({ reward_claimed: 1, keys_generated: (user.keys_generated || 0) + 1 }).eq('user_id', userId);
        
        const sessionToken = generateSessionToken();
        await supabase.from('key_sessions').insert({
            key_text: newKey, session_token: sessionToken, ip_address: ip,
            created_at: Date.now(), expires_at: expiryMs, is_active: true
        });
        
        res.json({ success: true, key: newKey, sessionToken: sessionToken, duration: durationHours, expiryMs: expiryMs, expiryFormatted: new Date(expiryMs).toLocaleString(), maxDevices: defaultMaxDevices, message: `🔓 Key generated! Can be used on ${defaultMaxDevices} device(s).` });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.post('/api/verify-key', async (req, res) => {
    try {
        const { key, sessionToken } = req.body;
        const userIp = getClientIp(req);
        const deviceFp = generateDeviceFingerprint(req);
        
        if (!key) return res.json({ valid: false, error: 'Key is required' });
        
        const deviceBanned = await isDeviceBanned(deviceFp);
        if (deviceBanned) return res.json({ valid: false, error: 'Your device has been banned' });
        
        const { data: keyData } = await supabase.from('keys').select('*').eq('key_text', key).single();
        if (!keyData) return res.json({ valid: false, error: 'Key not found' });
        
        if (Date.now() > keyData.expiry_ms) {
            await supabase.from('keys').update({ status: 'expired' }).eq('key_text', key);
            return res.json({ valid: false, error: 'Key has expired' });
        }
        
        if (keyData.status !== 'active') return res.json({ valid: false, error: 'Key is not active' });
        
        if (sessionToken) {
            const { data: session } = await supabase.from('key_sessions').select('*').eq('session_token', sessionToken).eq('key_text', key).eq('is_active', true).gt('expires_at', Date.now()).maybeSingle();
            if (session) {
                await supabase.from('key_sessions').update({ last_used_at: Date.now(), ip_address: userIp }).eq('session_token', sessionToken);
                return res.json({ valid: true, key: keyData.key_text, duration: keyData.duration_hours, expiryMs: keyData.expiry_ms, remaining: formatTimeRemaining(keyData.expiry_ms), message: '✅ Key valid' });
            }
        }
        
        const deviceRegistration = await registerDevice(key, deviceFp, req);
        if (!deviceRegistration.success) return res.json({ valid: false, error: deviceRegistration.error });
        
        if (!keyData.locked_ip) {
            await supabase.from('keys').update({ locked_ip: userIp, first_used_at: Date.now(), used_count: 1 }).eq('key_text', key);
            const newSessionToken = generateSessionToken();
            await supabase.from('key_sessions').insert({ key_text: key, session_token: newSessionToken, device_fingerprint: deviceFp, ip_address: userIp, created_at: Date.now(), expires_at: keyData.expiry_ms, is_active: true });
            return res.json({ valid: true, key: keyData.key_text, sessionToken: newSessionToken, duration: keyData.duration_hours, expiryMs: keyData.expiry_ms, remaining: formatTimeRemaining(keyData.expiry_ms), maxDevices: keyData.max_devices, message: `✅ Key locked (${deviceRegistration.currentDevices || 1}/${keyData.max_devices} devices)` });
        }
        
        if (keyData.locked_ip !== userIp) return res.json({ valid: false, error: `🔒 Key is locked to IP: ${keyData.locked_ip}` });
        
        await supabase.from('keys').update({ used_count: (keyData.used_count || 0) + 1 }).eq('key_text', key);
        return res.json({ valid: true, key: keyData.key_text, duration: keyData.duration_hours, expiryMs: keyData.expiry_ms, remaining: formatTimeRemaining(keyData.expiry_ms), message: '✅ Key valid!' });
    } catch (err) {
        res.json({ valid: false, error: err.message });
    }
});

app.get('/api/my-key/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { data: keyData } = await supabase.from('keys').select('*').eq('user_id', userId).eq('status', 'active').gt('expiry_ms', Date.now()).maybeSingle();
        if (!keyData) return res.json({ hasKey: false, message: 'No active key found' });
        res.json({ hasKey: true, key: keyData.key_text, duration: keyData.duration_hours, expiryMs: keyData.expiry_ms, remaining: formatTimeRemaining(keyData.expiry_ms), maxDevices: keyData.max_devices });
    } catch (err) {
        res.json({ hasKey: false, error: err.message });
    }
});

app.get('/api/maintenance-status', async (req, res) => {
    const maintenance = await isMaintenanceMode();
    const message = await getMaintenanceMessage();
    res.json({ success: true, maintenance: maintenance, message: message });
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// ============================================================
// ============================================================
// ADMIN API (LENGKAP)
// ============================================================
// ============================================================

app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    const ip = getClientIp(req);
    
    if (username === 'admin' && password === ADMIN_PASSWORD) {
        adminToken = crypto.randomBytes(32).toString('hex');
        adminTokenExpiry = Date.now() + 3600000;
        await supabase.from('admin_logs').insert({ action: 'LOGIN', details: 'Admin logged in', ip: ip, timestamp: Date.now() });
        res.json({ success: true, token: adminToken, expiry: adminTokenExpiry });
    } else {
        res.json({ success: false, error: 'Invalid credentials' });
    }
});

app.post('/api/admin/stats', verifyAdmin, async (req, res) => {
    const { count: totalKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true });
    const { count: activeKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true }).eq('status', 'active');
    const { count: totalUsers } = await supabase.from('users').select('*', { count: 'exact', head: true });
    const { count: totalDevices } = await supabase.from('key_devices').select('*', { count: 'exact', head: true }).eq('is_active', true);
    const { count: bannedUsers } = await supabase.from('users').select('*', { count: 'exact', head: true }).eq('banned', 1);
    const { count: bannedIps } = await supabase.from('ip_blacklist').select('*', { count: 'exact', head: true });
    const { count: activeSessions } = await supabase.from('key_sessions').select('*', { count: 'exact', head: true }).eq('is_active', true);
    
    res.json({ success: true, stats: { totalKeys: totalKeys || 0, activeKeys: activeKeys || 0, totalUsers: totalUsers || 0, totalDevices: totalDevices || 0, bannedUsers: bannedUsers || 0, bannedIps: bannedIps || 0, activeSessions: activeSessions || 0 } });
});

app.post('/api/admin/keys', verifyAdmin, async (req, res) => {
    const { data: keys } = await supabase.from('keys').select('*').order('created_at', { ascending: false }).limit(500);
    res.json({ success: true, keys: keys || [] });
});

app.post('/api/admin/users', verifyAdmin, async (req, res) => {
    const { data: users } = await supabase.from('users').select('*').order('created_at', { ascending: false }).limit(500);
    res.json({ success: true, users: users || [] });
});

app.post('/api/admin/add-key', verifyAdmin, async (req, res) => {
    try {
        const { userId, hours = 3, keyText, maxDevices = 1 } = req.body;
        if (!userId) return res.json({ success: false, error: 'User ID required' });
        
        const expiryMs = Date.now() + (hours * 3600000);
        const newKey = keyText || generateKey();
        
        await supabase.from('keys').insert({ key_text: newKey, user_id: userId, duration_hours: hours, expiry_ms: expiryMs, created_at: Date.now(), status: 'active', is_admin_key: 1, created_by: 'admin', max_devices: maxDevices, current_devices: 0, binding_type: 'device' });
        
        res.json({ success: true, key: newKey, expiryFormatted: new Date(expiryMs).toLocaleString(), maxDevices: maxDevices });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.post('/api/admin/add-bulk-keys', verifyAdmin, async (req, res) => {
    try {
        const { userId, count = 1, days = 0, hours = 3, minutes = 0, maxDevices = 1, bindingType = 'device' } = req.body;
        if (!userId) return res.json({ success: false, error: 'User ID required' });
        if (count > 100) return res.json({ success: false, error: 'Max 100 keys at once' });
        
        const totalHours = days * 24 + hours + minutes / 60;
        const expiryMs = Date.now() + (totalHours * 3600000);
        const keys = [];
        
        for (let i = 0; i < count; i++) {
            const newKey = generateKey();
            const { error } = await supabase.from('keys').insert({ key_text: newKey, user_id: userId, duration_hours: totalHours, expiry_ms: expiryMs, created_at: Date.now(), status: 'active', is_admin_key: 1, created_by: 'admin', max_devices: maxDevices, current_devices: 0, binding_type: bindingType });
            if (!error) keys.push(newKey);
        }
        
        res.json({ success: true, keys: keys, count: keys.length, expiryMs: expiryMs, expiryFormatted: new Date(expiryMs).toLocaleString(), bindingType: bindingType, message: `✅ Generated ${keys.length} keys with max ${maxDevices} device(s) each!` });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.post('/api/admin/delete-key', verifyAdmin, async (req, res) => {
    const { key } = req.body;
    await supabase.from('key_sessions').delete().eq('key_text', key);
    await supabase.from('key_devices').delete().eq('key_text', key);
    await supabase.from('keys').delete().eq('key_text', key);
    res.json({ success: true });
});

app.post('/api/admin/delete-expired-keys', verifyAdmin, async (req, res) => {
    await deleteExpiredKeys();
    res.json({ success: true, message: 'Expired keys deleted' });
});

app.post('/api/admin/delete-all-keys', verifyAdmin, async (req, res) => {
    await supabase.from('key_sessions').delete().neq('id', 0);
    await supabase.from('key_devices').delete().neq('id', 0);
    await supabase.from('keys').delete().neq('id', 0);
    res.json({ success: true, message: 'All keys deleted' });
});

app.post('/api/admin/ban-user', verifyAdmin, async (req, res) => {
    const { userId } = req.body;
    await supabase.from('users').update({ banned: 1 }).eq('user_id', userId);
    res.json({ success: true });
});

app.post('/api/admin/unban-user', verifyAdmin, async (req, res) => {
    const { userId } = req.body;
    await supabase.from('users').update({ banned: 0 }).eq('user_id', userId);
    res.json({ success: true });
});

app.post('/api/admin/ban-ip', verifyAdmin, async (req, res) => {
    const { ip, reason } = req.body;
    if (!ip) return res.json({ success: false, error: 'IP required' });
    await supabase.from('ip_blacklist').insert({ ip_address: ip, reason: reason || 'No reason', banned_at: Date.now() });
    res.json({ success: true, message: `IP ${ip} banned` });
});

app.post('/api/admin/unban-ip', verifyAdmin, async (req, res) => {
    const { ip } = req.body;
    await supabase.from('ip_blacklist').delete().eq('ip_address', ip);
    res.json({ success: true, message: `IP ${ip} unbanned` });
});

app.post('/api/admin/banned-ips', verifyAdmin, async (req, res) => {
    const { data } = await supabase.from('ip_blacklist').select('*').order('banned_at', { ascending: false });
    res.json({ success: true, ips: data || [] });
});

app.post('/api/admin/ban-device', verifyAdmin, async (req, res) => {
    const { deviceFingerprint, reason } = req.body;
    if (!deviceFingerprint) return res.json({ success: false, error: 'Device fingerprint required' });
    await supabase.from('device_blacklist').insert({ device_fingerprint: deviceFingerprint, reason: reason || 'No reason', banned_at: Date.now() });
    res.json({ success: true, message: 'Device banned' });
});

app.post('/api/admin/unban-device', verifyAdmin, async (req, res) => {
    const { deviceFingerprint } = req.body;
    if (!deviceFingerprint) return res.json({ success: false, error: 'Device fingerprint required' });
    await supabase.from('device_blacklist').delete().eq('device_fingerprint', deviceFingerprint);
    res.json({ success: true, message: 'Device unbanned' });
});

app.post('/api/admin/banned-devices', verifyAdmin, async (req, res) => {
    const { data } = await supabase.from('device_blacklist').select('*').order('banned_at', { ascending: false });
    res.json({ success: true, devices: data || [] });
});

app.post('/api/admin/key-devices', verifyAdmin, async (req, res) => {
    const { key } = req.body;
    if (!key) return res.json({ success: false, error: 'Key required' });
    const { data: devices } = await supabase.from('key_devices').select('*').eq('key_text', key).eq('is_active', true).order('first_seen', { ascending: false });
    res.json({ success: true, devices: devices || [] });
});

app.post('/api/admin/remove-device', verifyAdmin, async (req, res) => {
    const { key, deviceFingerprint } = req.body;
    if (!key || !deviceFingerprint) return res.json({ success: false, error: 'Key and device fingerprint required' });
    
    await supabase.from('key_devices').update({ is_active: false }).eq('key_text', key).eq('device_fingerprint', deviceFingerprint);
    const { count: currentDevices } = await supabase.from('key_devices').select('*', { count: 'exact', head: true }).eq('key_text', key).eq('is_active', true);
    await supabase.from('keys').update({ current_devices: currentDevices }).eq('key_text', key);
    
    res.json({ success: true, message: 'Device removed' });
});

app.post('/api/admin/security-logs', verifyAdmin, async (req, res) => {
    const { limit = 100 } = req.body;
    const { data } = await supabase.from('security_logs').select('*').order('timestamp', { ascending: false }).limit(limit);
    res.json({ success: true, logs: data || [] });
});

app.post('/api/admin/get-settings', verifyAdmin, async (req, res) => {
    const { data } = await supabase.from('settings').select('*');
    const settings = {};
    if (data) data.forEach(s => { settings[s.key] = s.value; });
    res.json({ success: true, settings: { default_max_devices: settings.default_max_devices || '1', max_keys_per_user: settings.max_keys_per_user || '5', default_duration_hours: settings.default_duration_hours || '3' } });
});

app.post('/api/admin/settings', verifyAdmin, async (req, res) => {
    const { default_max_devices, max_keys_per_user, default_duration_hours } = req.body;
    if (default_max_devices !== undefined) await supabase.from('settings').upsert({ key: 'default_max_devices', value: default_max_devices.toString(), updated_at: Date.now() }, { onConflict: 'key' });
    if (max_keys_per_user !== undefined) await supabase.from('settings').upsert({ key: 'max_keys_per_user', value: max_keys_per_user.toString(), updated_at: Date.now() }, { onConflict: 'key' });
    if (default_duration_hours !== undefined) await supabase.from('settings').upsert({ key: 'default_duration_hours', value: default_duration_hours.toString(), updated_at: Date.now() }, { onConflict: 'key' });
    res.json({ success: true, message: 'Settings saved' });
});

app.post('/api/admin/maintenance/settings', verifyAdmin, async (req, res) => {
    const { data: settings } = await supabase.from('system_settings').select('*').in('key', ['maintenance_mode', 'maintenance_message', 'maintenance_estimated_time']);
    const result = {};
    settings?.forEach(s => { result[s.key] = s.value; });
    res.json({ success: true, settings: { maintenance_mode: result.maintenance_mode || 'false', maintenance_message: result.maintenance_message || 'Server is under maintenance', maintenance_estimated_time: result.maintenance_estimated_time || '30 minutes' } });
});

app.post('/api/admin/maintenance/enable', verifyAdmin, async (req, res) => {
    const { message, estimatedTime } = req.body;
    const now = Date.now();
    await supabase.from('system_settings').upsert({ key: 'maintenance_mode', value: 'true', updated_at: now, updated_by: 'admin' }, { onConflict: 'key' });
    if (message) await supabase.from('system_settings').upsert({ key: 'maintenance_message', value: message, updated_at: now }, { onConflict: 'key' });
    if (estimatedTime) await supabase.from('system_settings').upsert({ key: 'maintenance_estimated_time', value: estimatedTime, updated_at: now }, { onConflict: 'key' });
    res.json({ success: true, message: 'Maintenance mode enabled' });
});

app.post('/api/admin/maintenance/disable', verifyAdmin, async (req, res) => {
    await supabase.from('system_settings').upsert({ key: 'maintenance_mode', value: 'false', updated_at: Date.now(), updated_by: 'admin' }, { onConflict: 'key' });
    res.json({ success: true, message: 'Maintenance mode disabled' });
});

app.post('/api/admin/logout', verifyAdmin, async (req, res) => {
    adminToken = null;
    adminTokenExpiry = null;
    res.json({ success: true });
});

// ============================================================
// START SERVER
// ============================================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 NEXUS SERVER running on port ${PORT}`);
    console.log(`🔐 Admin login: admin / ${ADMIN_PASSWORD}`);
    console.log(`📱 Device Limit: Enabled`);
});

module.exports = app;