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
const SUPABASE_URL = "https://ulxydqnbtiihmdphsemd.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVseHlkcW5idGlpaG1kcGhzZW1kIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NTk0MTk0NSwiZXhwIjoyMDkxNTE3OTQ1fQ.Aq4L78N3eJQv7yzqvPqUFat-wjY6L_h7sTY3qnq-x00";

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
// DEVICE LIMIT FUNCTIONS (FITUR BARU)
// ============================================================

async function registerDevice(keyText, deviceFingerprint, req) {
    const now = Date.now();
    const deviceName = req.headers['sec-ch-ua'] || req.headers['user-agent']?.substring(0, 100) || 'Unknown Device';
    
    // Cek apakah device sudah terdaftar
    const { data: existing } = await supabase
        .from('key_devices')
        .select('*')
        .eq('key_text', keyText)
        .eq('device_fingerprint', deviceFingerprint)
        .maybeSingle();
    
    if (existing) {
        // Update last seen
        await supabase
            .from('key_devices')
            .update({ last_seen: now, ip_address: getClientIp(req), user_agent: req.headers['user-agent'] })
            .eq('id', existing.id);
        return { success: true, isNew: false };
    }
    
    // Cek jumlah device saat ini
    const { count: currentDevices } = await supabase
        .from('key_devices')
        .select('*', { count: 'exact', head: true })
        .eq('key_text', keyText)
        .eq('is_active', true);
    
    // Ambil max devices dari key
    const { data: keyData } = await supabase
        .from('keys')
        .select('max_devices')
        .eq('key_text', keyText)
        .single();
    
    const maxDevices = keyData?.max_devices || parseInt(await getSetting('default_max_devices', '1'));
    
    if (currentDevices >= maxDevices) {
        return { success: false, error: `Maximum ${maxDevices} device(s) allowed for this key. Please remove an existing device first.` };
    }
    
    // Register device baru
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
    
    // Update current_devices di tabel keys
    await supabase
        .from('keys')
        .update({ current_devices: currentDevices + 1 })
        .eq('key_text', keyText);
    
    return { success: true, isNew: true, currentDevices: currentDevices + 1, maxDevices: maxDevices };
}

async function removeDevice(keyText, deviceFingerprint) {
    const { data: device } = await supabase
        .from('key_devices')
        .select('*')
        .eq('key_text', keyText)
        .eq('device_fingerprint', deviceFingerprint)
        .maybeSingle();
    
    if (!device) return { success: false, error: 'Device not found' };
    
    await supabase
        .from('key_devices')
        .update({ is_active: false })
        .eq('id', device.id);
    
    // Update current_devices
    const { count: currentDevices } = await supabase
        .from('key_devices')
        .select('*', { count: 'exact', head: true })
        .eq('key_text', keyText)
        .eq('is_active', true);
    
    await supabase
        .from('keys')
        .update({ current_devices: currentDevices })
        .eq('key_text', keyText);
    
    return { success: true, currentDevices: currentDevices };
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
        
        const { data: updatedKeys } = await supabase
            .from('keys')
            .update({ status: 'expired' })
            .lt('expiry_ms', now)
            .eq('status', 'active');
        
        await supabase
            .from('key_sessions')
            .update({ is_active: false })
            .lt('expires_at', now)
            .eq('is_active', true);
        
        return { updated: updatedKeys?.length || 0 };
    } catch (err) {
        console.error('Auto delete error:', err);
        return { updated: 0 };
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
        await logSecurityEvent('BLOCKED_REQUEST', 'Request from banned IP', ip, 'unknown');
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
        const deviceFp = generateDeviceFingerprint(req);
        
        if (!userId) return res.json({ success: false, error: 'User ID required' });
        
        const { data: existingKey } = await supabase
            .from('keys')
            .select('*')
            .eq('user_id', userId)
            .eq('status', 'active')
            .gt('expiry_ms', Date.now())
            .maybeSingle();
        
        if (existingKey) {
            return res.json({ 
                success: false, 
                error: 'You already have an active key',
                key: existingKey.key_text,
                expiry: formatTimeRemaining(existingKey.expiry_ms)
            });
        }
        
        let { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('user_id', userId)
            .maybeSingle();
        
        if (!user) {
            const { data: newUser } = await supabase
                .from('users')
                .insert({
                    user_id: userId,
                    ip_address: ip,
                    device_fingerprint: deviceFp,
                    created_at: Date.now()
                })
                .select()
                .single();
            user = newUser;
        }
        
        await logSecurityEvent('CHALLENGE_START', 'User started challenge', ip, deviceFp, userId);
        
        res.json({ 
            success: true, 
            message: 'Challenge started!',
            step1_completed: user.step1_completed || 0,
            step2_completed: user.step2_completed || 0
        });
        
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ============================================================
// API: STEP 1
// ============================================================
app.post('/api/step1', async (req, res) => {
    try {
        const { userId } = req.body;
        const deviceFp = generateDeviceFingerprint(req);
        
        if (!userId) return res.json({ success: false, error: 'User ID required' });
        
        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('user_id', userId)
            .single();
        
        if (!user) return res.json({ success: false, error: 'User not found' });
        
        if (user.step1_completed === 1) {
            return res.json({ success: true, alreadyCompleted: true, step: 2 });
        }
        
        await supabase
            .from('users')
            .update({ step1_completed: 1, step1_completed_at: Date.now(), device_fingerprint: deviceFp })
            .eq('user_id', userId);
        
        await logSecurityEvent('STEP1_COMPLETE', 'User completed step 1', getClientIp(req), deviceFp, userId);
        
        res.json({ success: true, message: 'Step 1 completed! Now wait 100 seconds for step 2.', step: 2 });
        
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ============================================================
// API: STEP 2
// ============================================================
app.post('/api/step2', async (req, res) => {
    try {
        const { userId } = req.body;
        const deviceFp = generateDeviceFingerprint(req);
        
        if (!userId) return res.json({ success: false, error: 'User ID required' });
        
        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('user_id', userId)
            .single();
        
        if (!user) return res.json({ success: false, error: 'User not found' });
        
        if (user.step1_completed !== 1) {
            return res.json({ success: false, error: 'Complete step 1 first!' });
        }
        
        if (user.step2_completed === 1) {
            return res.json({ success: true, alreadyCompleted: true });
        }
        
        await supabase
            .from('users')
            .update({ step2_completed: 1, step2_completed_at: Date.now() })
            .eq('user_id', userId);
        
        await logSecurityEvent('STEP2_COMPLETE', 'User completed step 2', getClientIp(req), deviceFp, userId);
        
        res.json({ success: true, message: 'Step 2 completed! You can now claim your key.', canClaim: true });
        
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ============================================================
// API: CLAIM KEY (DENGAN MAX DEVICES DEFAULT)
// ============================================================
app.post('/api/claim', async (req, res) => {
    try {
        const { userId, durationHours = 3, maxDevices = null } = req.body;
        const ip = getClientIp(req);
        const deviceFp = generateDeviceFingerprint(req);
        
        if (!userId) return res.json({ success: false, error: 'User ID required' });
        
        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('user_id', userId)
            .single();
        
        if (!user) return res.json({ success: false, error: 'User not found' });
        
        if (user.step2_completed !== 1) {
            return res.json({ success: false, error: 'Complete both steps first!' });
        }
        
        if (user.reward_claimed === 1) {
            return res.json({ success: false, error: 'Reward already claimed!' });
        }
        
        const maxKeysPerUser = parseInt(await getSetting('max_keys_per_user', '5'));
        const { count: userKeys } = await supabase
            .from('keys')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', userId)
            .eq('status', 'active');
        
        if (userKeys >= maxKeysPerUser) {
            return res.json({ success: false, error: `Maximum ${maxKeysPerUser} keys per user` });
        }
        
        const newKey = generateKey();
        const expiryMs = Date.now() + (durationHours * 3600000);
        const finalMaxDevices = maxDevices || parseInt(await getSetting('default_max_devices', '1'));
        
        const { error: insertError } = await supabase.from('keys').insert({
            key_text: newKey,
            user_id: userId,
            duration_hours: durationHours,
            expiry_ms: expiryMs,
            created_at: Date.now(),
            status: 'active',
            is_admin_key: 0,
            created_by: 'user',
            locked_ip: ip,
            locked_device_fingerprint: deviceFp,
            max_devices: finalMaxDevices,
            current_devices: 0,
            binding_type: 'device'
        });
        
        if (insertError) {
            return res.json({ success: false, error: insertError.message });
        }
        
        // Register device pertama
        await registerDevice(newKey, deviceFp, req);
        
        await supabase
            .from('users')
            .update({ reward_claimed: 1, keys_generated: (user.keys_generated || 0) + 1 })
            .eq('user_id', userId);
        
        await logSecurityEvent('KEY_CLAIMED', `Key claimed with max ${finalMaxDevices} device(s)`, ip, deviceFp, userId);
        
        const sessionToken = generateSessionToken();
        await supabase.from('key_sessions').insert({
            key_text: newKey,
            session_token: sessionToken,
            device_fingerprint: deviceFp,
            ip_address: ip,
            created_at: Date.now(),
            expires_at: expiryMs,
            is_active: true
        });
        
        res.json({
            success: true,
            key: newKey,
            sessionToken: sessionToken,
            duration: durationHours,
            expiryMs: expiryMs,
            expiryFormatted: new Date(expiryMs).toLocaleString(),
            maxDevices: finalMaxDevices,
            message: `🔓 Key generated! Can be used on ${finalMaxDevices} device(s).`
        });
        
    } catch (err) {
        console.error('Claim error:', err);
        res.json({ success: false, error: err.message });
    }
});

// ============================================================
// API: VERIFY KEY (DENGAN DEVICE LIMIT CHECK)
// ============================================================
app.post('/api/verify-key', async (req, res) => {
    try {
        const { key, sessionToken } = req.body;
        const userIp = getClientIp(req);
        const deviceFp = generateDeviceFingerprint(req);
        
        if (!key) return res.json({ valid: false, error: 'Key is required' });
        
        console.log(`🔍 [VERIFY] Key: ${key}, Device FP: ${deviceFp.substring(0, 16)}...`);
        
        // Check device ban
        const deviceBanned = await isDeviceBanned(deviceFp);
        if (deviceBanned) {
            await logSecurityEvent('DEVICE_BANNED', 'Banned device tried to verify key', userIp, deviceFp);
            return res.json({ valid: false, error: 'Your device has been banned' });
        }
        
        // Get key data
        const { data: keyData, error } = await supabase
            .from('keys')
            .select('*')
            .eq('key_text', key)
            .single();
        
        if (error || !keyData) {
            await incrementFailedAttempts(userIp, deviceFp, key);
            await logSecurityEvent('KEY_NOT_FOUND', `Key not found: ${key}`, userIp, deviceFp);
            return res.json({ valid: false, error: 'Key not found' });
        }
        
        // Check expiry
        if (Date.now() > keyData.expiry_ms) {
            await supabase.from('keys').update({ status: 'expired' }).eq('key_text', key);
            return res.json({ valid: false, error: 'Key has expired' });
        }
        
        // Check status
        if (keyData.status !== 'active') {
            return res.json({ valid: false, error: 'Key is not active' });
        }
        
        // Check session token
        if (sessionToken) {
            const { data: session } = await supabase
                .from('key_sessions')
                .select('*')
                .eq('session_token', sessionToken)
                .eq('key_text', key)
                .eq('is_active', true)
                .gt('expires_at', Date.now())
                .maybeSingle();
            
            if (session) {
                await supabase
                    .from('key_sessions')
                    .update({ last_used_at: Date.now(), ip_address: userIp })
                    .eq('session_token', sessionToken);
                
                return res.json({
                    valid: true,
                    key: keyData.key_text,
                    duration: keyData.duration_hours,
                    expiryMs: keyData.expiry_ms,
                    remaining: formatTimeRemaining(keyData.expiry_ms),
                    verifiedVia: 'session',
                    message: '✅ Key valid (session)'
                });
            }
        }
        
        // Check device limit (FITUR BARU)
        const deviceRegistration = await registerDevice(key, deviceFp, req);
        if (!deviceRegistration.success) {
            await logSecurityEvent('DEVICE_LIMIT_EXCEEDED', deviceRegistration.error, userIp, deviceFp, keyData.user_id);
            return res.json({ valid: false, error: deviceRegistration.error });
        }
        
        // Check IP lock
        if (keyData.locked_ip && keyData.locked_ip !== '0.0.0.0') {
            if (keyData.locked_ip !== userIp) {
                await incrementFailedAttempts(userIp, deviceFp, key);
                return res.json({ valid: false, error: `🔒 Key is locked to IP: ${keyData.locked_ip}` });
            }
        }
        
        // Check device fingerprint lock
        if (keyData.locked_device_fingerprint && keyData.locked_device_fingerprint !== deviceFp) {
            await incrementFailedAttempts(userIp, deviceFp, key);
            return res.json({ valid: false, error: `🔒 Key is locked to a different device` });
        }
        
        // First time use - lock
        if (!keyData.locked_ip && !keyData.locked_device_fingerprint) {
            await supabase
                .from('keys')
                .update({ locked_ip: userIp, locked_device_fingerprint: deviceFp, first_used_at: Date.now(), used_count: 1 })
                .eq('key_text', key);
            
            const newSessionToken = generateSessionToken();
            await supabase.from('key_sessions').insert({
                key_text: key,
                session_token: newSessionToken,
                device_fingerprint: deviceFp,
                ip_address: userIp,
                created_at: Date.now(),
                expires_at: keyData.expiry_ms,
                is_active: true
            });
            
            return res.json({
                valid: true,
                key: keyData.key_text,
                sessionToken: newSessionToken,
                duration: keyData.duration_hours,
                expiryMs: keyData.expiry_ms,
                remaining: formatTimeRemaining(keyData.expiry_ms),
                maxDevices: keyData.max_devices,
                currentDevices: deviceRegistration.currentDevices || 1,
                message: `✅ Key locked and registered (${deviceRegistration.currentDevices || 1}/${keyData.max_devices} devices)`
            });
        }
        
        // Log usage
        await supabase.from('key_usage').insert({
            key_text: key,
            device_fingerprint: deviceFp,
            ip_address: userIp,
            used_at: Date.now(),
            user_agent: req.headers['user-agent']
        });
        
        await supabase
            .from('keys')
            .update({ used_count: (keyData.used_count || 0) + 1 })
            .eq('key_text', key);
        
        return res.json({
            valid: true,
            key: keyData.key_text,
            duration: keyData.duration_hours,
            expiryMs: keyData.expiry_ms,
            remaining: formatTimeRemaining(keyData.expiry_ms),
            maxDevices: keyData.max_devices,
            currentDevices: deviceRegistration.currentDevices || (keyData.current_devices || 1),
            message: '✅ Key valid!'
        });
        
    } catch (err) {
        console.error('Verify key error:', err);
        res.json({ valid: false, error: err.message });
    }
});

// ============================================================
// API: GET KEY DEVICES (Lihat device yang terdaftar)
// ============================================================
app.post('/api/key-devices', async (req, res) => {
    try {
        const { key, userId } = req.body;
        
        if (!key && !userId) {
            return res.json({ success: false, error: 'Key or User ID required' });
        }
        
        let keyText = key;
        if (!keyText && userId) {
            const { data: userKey } = await supabase
                .from('keys')
                .select('key_text')
                .eq('user_id', userId)
                .eq('status', 'active')
                .maybeSingle();
            if (userKey) keyText = userKey.key_text;
        }
        
        if (!keyText) return res.json({ success: false, error: 'No active key found' });
        
        const devices = await getKeyDevices(keyText);
        
        res.json({
            success: true,
            key: keyText,
            devices: devices.map(d => ({
                device_name: d.device_name,
                first_seen: d.first_seen,
                last_seen: d.last_seen,
                ip_address: d.ip_address
            }))
        });
        
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ============================================================
// API: REMOVE DEVICE
// ============================================================
app.post('/api/remove-device', async (req, res) => {
    try {
        const { key, deviceFingerprint } = req.body;
        
        if (!key || !deviceFingerprint) {
            return res.json({ success: false, error: 'Key and device fingerprint required' });
        }
        
        const result = await removeDevice(key, deviceFingerprint);
        res.json(result);
        
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ============================================================
// API: GET MY KEY
// ============================================================
app.get('/api/my-key/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        
        const { data: keyData } = await supabase
            .from('keys')
            .select('*')
            .eq('user_id', userId)
            .eq('status', 'active')
            .gt('expiry_ms', Date.now())
            .maybeSingle();
        
        if (!keyData) {
            return res.json({ hasKey: false, message: 'No active key found' });
        }
        
        const devices = await getKeyDevices(keyData.key_text);
        
        res.json({
            hasKey: true,
            key: keyData.key_text,
            duration: keyData.duration_hours,
            expiryMs: keyData.expiry_ms,
            remaining: formatTimeRemaining(keyData.expiry_ms),
            maxDevices: keyData.max_devices,
            currentDevices: devices.length,
            devices: devices.map(d => ({ device_name: d.device_name, last_seen: d.last_seen }))
        });
        
    } catch (err) {
        res.json({ hasKey: false, error: err.message });
    }
});

// ============================================================
// API: MAINTENANCE STATUS
// ============================================================
app.get('/api/maintenance-status', async (req, res) => {
    const maintenance = await isMaintenanceMode();
    const message = await getMaintenanceMessage();
    res.json({ success: true, maintenance: maintenance, message: message });
});

// ============================================================
// API: HEALTH CHECK
// ============================================================
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// ============================================================
// ADMIN API
// ============================================================

app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    const ip = getClientIp(req);
    
    if (username === 'admin' && password === ADMIN_PASSWORD) {
        adminToken = crypto.randomBytes(32).toString('hex');
        adminTokenExpiry = Date.now() + 3600000;
        
        await supabase.from('admin_logs').insert({
            action: 'LOGIN',
            details: 'Admin logged in',
            ip: ip,
            timestamp: Date.now()
        });
        
        res.json({ success: true, token: adminToken, expiry: adminTokenExpiry });
    } else {
        res.json({ success: false, error: 'Invalid credentials' });
    }
});

app.post('/api/admin/stats', verifyAdmin, async (req, res) => {
    const { count: totalKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true });
    const { count: activeKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true }).eq('status', 'active');
    const { count: totalUsers } = await supabase.from('users').select('*', { count: 'exact', head: true });
    
    res.json({
        success: true,
        stats: {
            totalKeys: totalKeys || 0,
            activeKeys: activeKeys || 0,
            totalUsers: totalUsers || 0
        }
    });
});

app.post('/api/admin/keys', verifyAdmin, async (req, res) => {
    const { data: keys } = await supabase
        .from('keys')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(500);
    res.json({ success: true, keys: keys || [] });
});

app.post('/api/admin/add-key', verifyAdmin, async (req, res) => {
    try {
        const { userId, keyText, hours = 3, maxDevices = 1 } = req.body;
        
        if (!userId) return res.json({ success: false, error: 'User ID required' });
        
        const expiryMs = Date.now() + (hours * 3600000);
        const newKey = keyText || generateKey();
        
        const { error } = await supabase.from('keys').insert({
            key_text: newKey,
            user_id: userId,
            duration_hours: hours,
            expiry_ms: expiryMs,
            created_at: Date.now(),
            status: 'active',
            is_admin_key: 1,
            created_by: 'admin',
            max_devices: maxDevices,
            current_devices: 0,
            binding_type: 'device'
        });
        
        if (error) return res.json({ success: false, error: error.message });
        
        res.json({ success: true, key: newKey, expiryFormatted: new Date(expiryMs).toLocaleString(), maxDevices: maxDevices });
        
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

app.post('/api/admin/maintenance/enable', verifyAdmin, async (req, res) => {
    const { message, estimatedTime } = req.body;
    const now = Date.now();
    
    await supabase.from('system_settings').upsert({ key: 'maintenance_mode', value: 'true', updated_at: now, updated_by: 'admin' }, { onConflict: 'key' });
    if (message) await supabase.from('system_settings').upsert({ key: 'maintenance_message', value: message, updated_at: now }, { onConflict: 'key' });
    if (estimatedTime) await supabase.from('system_settings').upsert({ key: 'maintenance_estimated_time', value: estimatedTime, updated_at: now }, { onConflict: 'key' });
    
    res.json({ success: true, message: 'Maintenance mode enabled for ALL servers' });
});

app.post('/api/admin/maintenance/disable', verifyAdmin, async (req, res) => {
    await supabase.from('system_settings').upsert({ key: 'maintenance_mode', value: 'false', updated_at: Date.now(), updated_by: 'admin' }, { onConflict: 'key' });
    res.json({ success: true, message: 'Maintenance mode disabled' });
});

app.post('/api/admin/maintenance/settings', verifyAdmin, async (req, res) => {
    const { data: settings } = await supabase
        .from('system_settings')
        .select('*')
        .in('key', ['maintenance_mode', 'maintenance_message', 'maintenance_estimated_time']);
    
    const result = {};
    settings?.forEach(s => { result[s.key] = s.value; });
    res.json({ success: true, settings: result });
});

// ============================================================
// START SERVER
// ============================================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 NEXUS SERVER running on port ${PORT}`);
    console.log(`🔐 Device Limit: Enabled (max devices per key)`);
    console.log(`🔧 Maintenance mode: ${isMaintenanceMode() ? 'ON' : 'OFF'}`);
});

module.exports = app;