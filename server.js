const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors({ origin: '*', credentials: true }));
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

// ============================================================
// MAINTENANCE MIDDLEWARE
// ============================================================
app.use('/api/', async (req, res, next) => {
    if (req.path.includes('/admin/') || req.path === '/api/health' || req.path === '/api/maintenance-status') {
        return next();
    }
    
    const maintenance = await isMaintenanceMode();
    if (maintenance) {
        return res.status(503).json({
            success: false,
            maintenance: true,
            message: 'Server is under maintenance',
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

async function getSetting(key, defaultValue = 'false') {
    try {
        const { data } = await supabase
            .from('settings')
            .select('value')
            .eq('key', key)
            .maybeSingle();
        return data?.value || defaultValue;
    } catch (error) {
        return defaultValue;
    }
}

async function logSecurityEvent(eventType, details, ip, deviceFp, userId = null) {
    try {
        await supabase.from('security_logs').insert({
            event_type: eventType,
            details: details,
            ip_address: ip,
            device_fingerprint: deviceFp,
            user_id: userId,
            timestamp: Date.now()
        });
    } catch (error) {}
}

// ============================================================
// VERIFY ADMIN MIDDLEWARE
// ============================================================
function verifyAdmin(req, res, next) {
    const token = req.body.token || req.query.token;
    if (!token || token !== adminToken || (adminTokenExpiry && Date.now() > adminTokenExpiry)) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    next();
}

// ============================================================
// API: HEALTH CHECK
// ============================================================
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.get('/api/maintenance-status', async (req, res) => {
    const maintenance = await isMaintenanceMode();
    res.json({ success: true, maintenance: maintenance, message: 'Server status' });
});

// ============================================================
// API: START CHALLENGE
// ============================================================
app.post('/api/start', async (req, res) => {
    try {
        const { userId } = req.body;
        const ip = getClientIp(req);
        
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
                    created_at: Date.now()
                })
                .select()
                .single();
            user = newUser;
        }
        
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
            .update({ step1_completed: 1, step1_completed_at: Date.now() })
            .eq('user_id', userId);
        
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
        
        res.json({ success: true, message: 'Step 2 completed! You can now claim your key.', canClaim: true });
        
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ============================================================
// API: CLAIM KEY
// ============================================================
app.post('/api/claim', async (req, res) => {
    try {
        const { userId, durationHours = 3 } = req.body;
        const ip = getClientIp(req);
        
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
            max_devices: 1,
            current_devices: 0
        });
        
        if (insertError) {
            return res.json({ success: false, error: insertError.message });
        }
        
        await supabase
            .from('users')
            .update({ reward_claimed: 1, keys_generated: (user.keys_generated || 0) + 1 })
            .eq('user_id', userId);
        
        const sessionToken = generateSessionToken();
        await supabase.from('key_sessions').insert({
            key_text: newKey,
            session_token: sessionToken,
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
            message: '🔓 Key generated!'
        });
        
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ============================================================
// API: VERIFY KEY
// ============================================================
app.post('/api/verify-key', async (req, res) => {
    try {
        const { key, sessionToken } = req.body;
        const userIp = getClientIp(req);
        
        if (!key) return res.json({ valid: false, error: 'Key is required' });
        
        const { data: keyData } = await supabase
            .from('keys')
            .select('*')
            .eq('key_text', key)
            .single();
        
        if (!keyData) {
            return res.json({ valid: false, error: 'Key not found' });
        }
        
        if (Date.now() > keyData.expiry_ms) {
            await supabase.from('keys').update({ status: 'expired' }).eq('key_text', key);
            return res.json({ valid: false, error: 'Key has expired' });
        }
        
        if (keyData.status !== 'active') {
            return res.json({ valid: false, error: 'Key is not active' });
        }
        
        // Check session
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
                    message: '✅ Key valid'
                });
            }
        }
        
        if (!keyData.locked_ip) {
            await supabase
                .from('keys')
                .update({ locked_ip: userIp, first_used_at: Date.now(), used_count: 1 })
                .eq('key_text', key);
            
            const newSessionToken = generateSessionToken();
            await supabase.from('key_sessions').insert({
                key_text: key,
                session_token: newSessionToken,
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
                message: '✅ Key locked to your IP'
            });
        }
        
        if (keyData.locked_ip !== userIp) {
            return res.json({ valid: false, error: `🔒 Key is locked to IP: ${keyData.locked_ip}` });
        }
        
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
            message: '✅ Key valid!'
        });
        
    } catch (err) {
        res.json({ valid: false, error: err.message });
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
        
        res.json({
            hasKey: true,
            key: keyData.key_text,
            duration: keyData.duration_hours,
            expiryMs: keyData.expiry_ms,
            remaining: formatTimeRemaining(keyData.expiry_ms)
        });
        
    } catch (err) {
        res.json({ hasKey: false, error: err.message });
    }
});

// ============================================================
// ============================================================
// ADMIN API (LENGKAP)
// ============================================================
// ============================================================

// ADMIN LOGIN
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    const ip = getClientIp(req);
    
    console.log(`Admin login attempt: ${username}`);
    
    if (username === 'admin' && password === ADMIN_PASSWORD) {
        adminToken = crypto.randomBytes(32).toString('hex');
        adminTokenExpiry = Date.now() + 3600000;
        
        await supabase.from('admin_logs').insert({
            action: 'LOGIN',
            details: 'Admin logged in',
            ip: ip,
            timestamp: Date.now()
        });
        
        console.log(`Admin login successful, token: ${adminToken.substring(0, 20)}...`);
        res.json({ success: true, token: adminToken, expiry: adminTokenExpiry });
    } else {
        console.log(`Admin login failed for ${username}`);
        res.json({ success: false, error: 'Invalid credentials' });
    }
});

// ADMIN STATS
app.post('/api/admin/stats', verifyAdmin, async (req, res) => {
    try {
        const { count: totalKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true });
        const { count: activeKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true }).eq('status', 'active');
        const { count: totalUsers } = await supabase.from('users').select('*', { count: 'exact', head: true });
        const { count: totalDevices } = await supabase.from('key_devices').select('*', { count: 'exact', head: true }).eq('is_active', true);
        
        res.json({
            success: true,
            stats: {
                totalKeys: totalKeys || 0,
                activeKeys: activeKeys || 0,
                totalUsers: totalUsers || 0,
                totalDevices: totalDevices || 0
            }
        });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ADMIN KEYS LIST
app.post('/api/admin/keys', verifyAdmin, async (req, res) => {
    try {
        const { data: keys } = await supabase
            .from('keys')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(500);
        
        res.json({ success: true, keys: keys || [] });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ADMIN ADD KEY
app.post('/api/admin/add-key', verifyAdmin, async (req, res) => {
    try {
        const { userId, hours = 3, keyText, maxDevices = 1 } = req.body;
        
        if (!userId) {
            return res.json({ success: false, error: 'User ID required' });
        }
        
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
            current_devices: 0
        });
        
        if (error) {
            return res.json({ success: false, error: error.message });
        }
        
        res.json({ 
            success: true, 
            key: newKey, 
            expiryFormatted: new Date(expiryMs).toLocaleString(),
            maxDevices: maxDevices
        });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ADMIN DELETE KEY
app.post('/api/admin/delete-key', verifyAdmin, async (req, res) => {
    try {
        const { key } = req.body;
        await supabase.from('key_sessions').delete().eq('key_text', key);
        await supabase.from('key_devices').delete().eq('key_text', key);
        await supabase.from('keys').delete().eq('key_text', key);
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ADMIN GET SETTINGS
app.post('/api/admin/get-settings', verifyAdmin, async (req, res) => {
    try {
        const { data: settings } = await supabase.from('settings').select('*');
        
        const result = {};
        if (settings) {
            settings.forEach(s => { result[s.key] = s.value; });
        }
        
        res.json({ 
            success: true, 
            settings: {
                default_max_devices: result.default_max_devices || '1',
                max_keys_per_user: result.max_keys_per_user || '5',
                default_duration_hours: result.default_duration_hours || '3'
            }
        });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ADMIN SAVE SETTINGS
app.post('/api/admin/settings', verifyAdmin, async (req, res) => {
    try {
        const { default_max_devices, max_keys_per_user, default_duration_hours } = req.body;
        
        if (default_max_devices !== undefined) {
            await supabase.from('settings').upsert({ key: 'default_max_devices', value: default_max_devices.toString(), updated_at: Date.now() }, { onConflict: 'key' });
        }
        if (max_keys_per_user !== undefined) {
            await supabase.from('settings').upsert({ key: 'max_keys_per_user', value: max_keys_per_user.toString(), updated_at: Date.now() }, { onConflict: 'key' });
        }
        if (default_duration_hours !== undefined) {
            await supabase.from('settings').upsert({ key: 'default_duration_hours', value: default_duration_hours.toString(), updated_at: Date.now() }, { onConflict: 'key' });
        }
        
        res.json({ success: true, message: 'Settings saved' });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ADMIN MAINTENANCE SETTINGS
app.post('/api/admin/maintenance/settings', verifyAdmin, async (req, res) => {
    try {
        const { data: settings } = await supabase
            .from('system_settings')
            .select('*')
            .in('key', ['maintenance_mode', 'maintenance_message', 'maintenance_estimated_time']);
        
        const result = {};
        if (settings) {
            settings.forEach(s => { result[s.key] = s.value; });
        }
        
        res.json({ 
            success: true, 
            settings: {
                maintenance_mode: result.maintenance_mode || 'false',
                maintenance_message: result.maintenance_message || 'Server is under maintenance',
                maintenance_estimated_time: result.maintenance_estimated_time || '30 minutes'
            }
        });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ADMIN ENABLE MAINTENANCE
app.post('/api/admin/maintenance/enable', verifyAdmin, async (req, res) => {
    try {
        const { message, estimatedTime } = req.body;
        const now = Date.now();
        
        await supabase.from('system_settings').upsert({ key: 'maintenance_mode', value: 'true', updated_at: now, updated_by: 'admin' }, { onConflict: 'key' });
        if (message) {
            await supabase.from('system_settings').upsert({ key: 'maintenance_message', value: message, updated_at: now }, { onConflict: 'key' });
        }
        if (estimatedTime) {
            await supabase.from('system_settings').upsert({ key: 'maintenance_estimated_time', value: estimatedTime, updated_at: now }, { onConflict: 'key' });
        }
        
        res.json({ success: true, message: 'Maintenance mode enabled' });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ADMIN DISABLE MAINTENANCE
app.post('/api/admin/maintenance/disable', verifyAdmin, async (req, res) => {
    try {
        await supabase.from('system_settings').upsert({ key: 'maintenance_mode', value: 'false', updated_at: Date.now(), updated_by: 'admin' }, { onConflict: 'key' });
        res.json({ success: true, message: 'Maintenance mode disabled' });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ADMIN LOGOUT
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
    console.log(`🔐 Admin login: admin / 67`);
    console.log(`✅ All endpoints ready`);
});

module.exports = app;