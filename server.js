const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
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

// ============================================================
// HELPER FUNCTIONS
// ============================================================
function generateKey() {
    const prefix = "NX";
    const timestamp = Date.now().toString(36).toUpperCase();
    const random = crypto.randomBytes(6).toString('hex').toUpperCase();
    const checksum = crypto.createHash('sha256').update(timestamp + random).digest('hex').substring(0, 6).toUpperCase();
    return `${prefix}-${timestamp}-${random}-${checksum}`;
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

async function getSetting(key, defaultValue = 'false') {
    const { data } = await supabase
        .from('settings')
        .select('value')
        .eq('key', key)
        .maybeSingle();
    return data?.value || defaultValue;
}

// ============================================================
// AUTO DELETE EXPIRED KEYS
// ============================================================
async function deleteExpiredKeys() {
    try {
        const now = Date.now();
        
        const { data: updatedKeys, error: updateError } = await supabase
            .from('keys')
            .update({ status: 'expired' })
            .lt('expiry_ms', now)
            .eq('status', 'active');
        
        if (updateError) {
            console.error('Error updating expired keys status:', updateError);
        } else if (updatedKeys && updatedKeys.length > 0) {
            console.log(`📅 Updated ${updatedKeys.length} keys status to expired`);
        }
        
        return { updated: updatedKeys?.length || 0 };
    } catch (err) {
        console.error('Auto delete expired keys error:', err);
        return { updated: 0 };
    }
}

setInterval(async () => {
    console.log('🔄 Running scheduled cleanup of expired keys...');
    await deleteExpiredKeys();
}, 3600000);

setTimeout(async () => {
    console.log('🔄 Initial cleanup of expired keys on startup...');
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
    if (!token || token !== adminToken) {
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
        
        if (!userId) {
            return res.json({ success: false, error: 'User ID required' });
        }
        
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
// API: STEP 1 - WAIT 20 SECONDS
// ============================================================
app.post('/api/step1', async (req, res) => {
    try {
        const { userId } = req.body;
        
        if (!userId) {
            return res.json({ success: false, error: 'User ID required' });
        }
        
        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('user_id', userId)
            .single();
        
        if (!user) {
            return res.json({ success: false, error: 'User not found' });
        }
        
        if (user.step1_completed === 1) {
            return res.json({ success: true, alreadyCompleted: true, step: 2 });
        }
        
        await supabase
            .from('users')
            .update({ 
                step1_completed: 1,
                step1_completed_at: Date.now()
            })
            .eq('user_id', userId);
        
        res.json({ 
            success: true, 
            message: 'Step 1 completed! Now wait 100 seconds for step 2.',
            step: 2
        });
        
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ============================================================
// API: STEP 2 - WAIT 100 SECONDS
// ============================================================
app.post('/api/step2', async (req, res) => {
    try {
        const { userId } = req.body;
        
        if (!userId) {
            return res.json({ success: false, error: 'User ID required' });
        }
        
        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('user_id', userId)
            .single();
        
        if (!user) {
            return res.json({ success: false, error: 'User not found' });
        }
        
        if (user.step1_completed !== 1) {
            return res.json({ success: false, error: 'Complete step 1 first!' });
        }
        
        if (user.step2_completed === 1) {
            return res.json({ success: true, alreadyCompleted: true });
        }
        
        await supabase
            .from('users')
            .update({ 
                step2_completed: 1,
                step2_completed_at: Date.now()
            })
            .eq('user_id', userId);
        
        res.json({ 
            success: true, 
            message: 'Step 2 completed! You can now claim your key.',
            canClaim: true
        });
        
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ============================================================
// API: CLAIM KEY (USER CLAIMED - AUTO IP LOCK)
// ============================================================
app.post('/api/claim', async (req, res) => {
    try {
        const { userId, durationHours = 3 } = req.body;
        
        if (!userId) {
            return res.json({ success: false, error: 'User ID required' });
        }
        
        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('user_id', userId)
            .single();
        
        if (!user) {
            return res.json({ success: false, error: 'User not found' });
        }
        
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
        
        // USER KEY: is_admin_key = 0, locked_ip = NULL (auto lock on first use)
        const { error: insertError } = await supabase
            .from('keys')
            .insert({
                key_text: newKey,
                user_id: userId,
                duration_hours: durationHours,
                expiry_ms: expiryMs,
                created_at: Date.now(),
                status: 'active',
                is_admin_key: 0,
                created_by: 'user',
                locked_ip: null
            });
        
        if (insertError) {
            console.error('Insert key error:', insertError);
            return res.json({ success: false, error: insertError.message });
        }
        
        await supabase
            .from('users')
            .update({ 
                reward_claimed: 1,
                keys_generated: (user.keys_generated || 0) + 1
            })
            .eq('user_id', userId);
        
        res.json({
            success: true,
            key: newKey,
            duration: durationHours,
            expiryMs: expiryMs,
            expiryFormatted: new Date(expiryMs).toLocaleString(),
            message: `🔓 Key generated! This key will be locked to the first IP that uses it.`
        });
        
    } catch (err) {
        console.error('Claim error:', err);
        res.json({ success: false, error: err.message });
    }
});

// ============================================================
// API: CHECK STATUS
// ============================================================
app.get('/api/status/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        
        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('user_id', userId)
            .maybeSingle();
        
        if (!user) {
            return res.json({ 
                success: true, 
                hasStarted: false,
                step1_completed: 0,
                step2_completed: 0,
                reward_claimed: 0
            });
        }
        
        res.json({
            success: true,
            hasStarted: true,
            step1_completed: user.step1_completed || 0,
            step2_completed: user.step2_completed || 0,
            reward_claimed: user.reward_claimed || 0
        });
        
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
        
        res.json({
            hasKey: true,
            key: keyData.key_text,
            duration: keyData.duration_hours,
            expiryMs: keyData.expiry_ms,
            remaining: formatTimeRemaining(keyData.expiry_ms),
            isAdminKey: keyData.is_admin_key === 1,
            lockedIp: keyData.locked_ip || 'Not locked yet'
        });
        
    } catch (err) {
        res.json({ hasKey: false, error: err.message });
    }
});

// ============================================================
// API: VERIFY KEY (AUTO IP LOCK ON FIRST USE)
// ============================================================
app.post('/api/verify-key', async (req, res) => {
    try {
        const { key } = req.body;
        const userIp = getClientIp(req);
        
        if (!key) {
            return res.json({ valid: false, error: 'Key is required' });
        }
        
        console.log(`🔍 [VERIFY] Key: ${key}, IP: ${userIp}`);
        
        const { data: keyData, error } = await supabase
            .from('keys')
            .select('*')
            .eq('key_text', key)
            .single();
        
        if (error || !keyData) {
            return res.json({ valid: false, error: 'Key not found' });
        }
        
        if (keyData.status !== 'active') {
            return res.json({ valid: false, error: 'Key is not active' });
        }
        
        if (Date.now() > keyData.expiry_ms) {
            await supabase.from('keys').update({ status: 'expired' }).eq('key_text', key);
            return res.json({ valid: false, error: 'Key has expired' });
        }
        
        const ipLockEnabled = await getSetting('ip_lock_enabled', 'true');
        
        // Handle NO LOCK (0.0.0.0)
        if (keyData.locked_ip === '0.0.0.0') {
            console.log(`✅ [NO LOCK] Key has no IP restriction`);
            
            await supabase
                .from('key_usage')
                .insert({
                    key_text: key,
                    device_id: userIp,
                    used_at: Date.now(),
                    user_agent: req.headers['user-agent'],
                    ip_address: userIp
                });
            
            return res.json({
                valid: true,
                key: keyData.key_text,
                duration: keyData.duration_hours,
                expiryMs: keyData.expiry_ms,
                remaining: formatTimeRemaining(keyData.expiry_ms),
                message: `✅ Key valid! (No IP lock - any IP can use)`
            });
        }
        
        // Handle AUTO LOCK (NULL) - lock to first IP
        if (!keyData.locked_ip) {
            console.log(`🔒 Locking key ${key} to IP: ${userIp}`);
            
            await supabase
                .from('keys')
                .update({ 
                    locked_ip: userIp,
                    used_at: Date.now()
                })
                .eq('key_text', key);
            
            await supabase
                .from('key_usage')
                .insert({
                    key_text: key,
                    device_id: userIp,
                    used_at: Date.now(),
                    user_agent: req.headers['user-agent'],
                    ip_address: userIp
                });
            
            return res.json({
                valid: true,
                key: keyData.key_text,
                duration: keyData.duration_hours,
                expiryMs: keyData.expiry_ms,
                remaining: formatTimeRemaining(keyData.expiry_ms),
                lockedIp: userIp,
                message: `✅ Key locked to your IP: ${userIp}`
            });
        }
        
        // Handle CUSTOM IP LOCK - check if matches
        if (keyData.locked_ip !== userIp) {
            console.log(`❌ [BLOCKED] IP mismatch. Key locked to: ${keyData.locked_ip}, Request from: ${userIp}`);
            return res.json({ 
                valid: false, 
                error: `🔒 This key is locked to IP: ${keyData.locked_ip}. Your IP: ${userIp}. Access denied.`
            });
        }
        
        console.log(`✅ [SUCCESS] IP matches: ${userIp}`);
        
        await supabase
            .from('key_usage')
            .insert({
                key_text: key,
                device_id: userIp,
                used_at: Date.now(),
                user_agent: req.headers['user-agent'],
                ip_address: userIp
            });
        
        return res.json({
            valid: true,
            key: keyData.key_text,
            duration: keyData.duration_hours,
            expiryMs: keyData.expiry_ms,
            remaining: formatTimeRemaining(keyData.expiry_ms),
            lockedIp: keyData.locked_ip,
            message: `✅ Key valid! (Locked to IP: ${keyData.locked_ip})`
        });
        
    } catch (err) {
        console.error('Verify key error:', err);
        res.json({ valid: false, error: err.message });
    }
});

// ============================================================
// API: ADMIN LOGIN
// ============================================================
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    const ip = getClientIp(req);
    
    if (username === 'admin' && password === ADMIN_PASSWORD) {
        adminToken = crypto.randomBytes(32).toString('hex');
        
        await supabase
            .from('admin_logs')
            .insert({
                action: 'LOGIN',
                details: 'Admin logged in',
                ip: ip,
                timestamp: Date.now()
            });
        
        res.json({ success: true, token: adminToken });
    } else {
        res.json({ success: false, error: 'Invalid credentials' });
    }
});

// ============================================================
// API: ADMIN STATISTICS
// ============================================================
app.post('/api/admin/stats', verifyAdmin, async (req, res) => {
    const { count: totalKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true });
    const { count: activeKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true }).eq('status', 'active');
    const { count: totalUsers } = await supabase.from('users').select('*', { count: 'exact', head: true });
    const { count: bannedUsers } = await supabase.from('users').select('*', { count: 'exact', head: true }).eq('banned', 1);
    const { count: adminKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true }).eq('is_admin_key', 1);
    const { count: userKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true }).eq('is_admin_key', 0);
    
    res.json({
        success: true,
        stats: {
            totalKeys: totalKeys || 0,
            activeKeys: activeKeys || 0,
            totalUsers: totalUsers || 0,
            bannedUsers: bannedUsers || 0,
            adminKeys: adminKeys || 0,
            userKeys: userKeys || 0
        }
    });
});

// ============================================================
// API: ADMIN KEYS
// ============================================================
app.post('/api/admin/keys', verifyAdmin, async (req, res) => {
    const { data: keys } = await supabase
        .from('keys')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(500);
    res.json({ success: true, keys: keys || [] });
});

// ============================================================
// API: ADMIN USERS
// ============================================================
app.post('/api/admin/users', verifyAdmin, async (req, res) => {
    const { data: users } = await supabase
        .from('users')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(500);
    res.json({ success: true, users: users || [] });
});

// ============================================================
// API: ADMIN ADD KEY (WITH 3 IP LOCK OPTIONS)
// ============================================================
app.post('/api/admin/add-key', verifyAdmin, async (req, res) => {
    try {
        const { 
            userId, 
            keyText, 
            days = 0, 
            hours = 0, 
            minutes = 0, 
            lockToIp = null 
        } = req.body;
        
        if (!userId) {
            return res.json({ success: false, error: 'User ID required' });
        }
        
        const totalHours = days * 24 + hours + minutes / 60;
        if (totalHours <= 0) {
            return res.json({ success: false, error: 'Duration must be greater than 0' });
        }
        
        const expiryMs = Date.now() + (totalHours * 3600000);
        const newKey = keyText || generateKey();
        
        // Process IP Lock based on value
        let finalLockIp = null;
        let lockMessage = '';
        
        if (lockToIp === '0.0.0.0') {
            // NO LOCK - can be used from any IP
            finalLockIp = '0.0.0.0';
            lockMessage = 'No IP lock (any IP can use)';
        } else if (lockToIp === null || lockToIp === '') {
            // AUTO LOCK - will lock to first IP that uses it
            finalLockIp = null;
            lockMessage = 'Auto-lock on first use';
        } else {
            // CUSTOM IP LOCK - lock to specific IP
            finalLockIp = lockToIp;
            lockMessage = `Locked to IP: ${lockToIp}`;
        }
        
        const { error } = await supabase
            .from('keys')
            .insert({
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
                locked_ip: finalLockIp
            });
        
        if (error) {
            return res.json({ success: false, error: error.message });
        }
        
        // Update user key count
        const { data: user } = await supabase
            .from('users')
            .select('keys_generated')
            .eq('user_id', userId)
            .maybeSingle();
        
        if (user) {
            await supabase
                .from('users')
                .update({ keys_generated: (user.keys_generated || 0) + 1 })
                .eq('user_id', userId);
        } else {
            await supabase
                .from('users')
                .insert({
                    user_id: userId,
                    keys_generated: 1,
                    created_at: Date.now()
                });
        }
        
        res.json({ 
            success: true, 
            key: newKey, 
            expiryMs: expiryMs,
            expiryFormatted: new Date(expiryMs).toLocaleString(),
            lockedIp: finalLockIp === '0.0.0.0' ? 'No Lock' : (finalLockIp || 'Auto-lock'),
            message: `✅ Key created! ${lockMessage}`
        });
        
    } catch (err) {
        console.error('Add key error:', err);
        res.json({ success: false, error: err.message });
    }
});

// ============================================================
// API: ADMIN ADD BULK KEYS
// ============================================================
app.post('/api/admin/add-bulk-keys', verifyAdmin, async (req, res) => {
    try {
        const { 
            userId, 
            count = 1, 
            days = 0, 
            hours = 0, 
            minutes = 0, 
            lockToIp = null 
        } = req.body;
        
        if (!userId) {
            return res.json({ success: false, error: 'User ID required' });
        }
        
        if (count > 100) {
            return res.json({ success: false, error: 'Max 100 keys at once' });
        }
        
        const totalHours = days * 24 + hours + minutes / 60;
        const expiryMs = Date.now() + (totalHours * 3600000);
        const keys = [];
        
        // Process IP Lock based on value
        let finalLockIp = null;
        if (lockToIp === '0.0.0.0') {
            finalLockIp = '0.0.0.0';
        } else if (lockToIp === null || lockToIp === '') {
            finalLockIp = null;
        } else {
            finalLockIp = lockToIp;
        }
        
        for (let i = 0; i < count; i++) {
            const newKey = generateKey();
            const { error } = await supabase
                .from('keys')
                .insert({
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
                    locked_ip: finalLockIp
                });
            
            if (!error) {
                keys.push(newKey);
            }
        }
        
        let lockMessage = '';
        if (finalLockIp === '0.0.0.0') {
            lockMessage = 'No IP lock (any IP can use)';
        } else if (finalLockIp === null) {
            lockMessage = 'Auto-lock on first use';
        } else {
            lockMessage = `Locked to IP: ${finalLockIp}`;
        }
        
        res.json({ 
            success: true, 
            keys: keys,
            count: keys.length,
            expiryMs: expiryMs,
            expiryFormatted: new Date(expiryMs).toLocaleString(),
            message: `✅ Generated ${keys.length} keys! ${lockMessage}`
        });
        
    } catch (err) {
        console.error('Bulk keys error:', err);
        res.json({ success: false, error: err.message });
    }
});

// ============================================================
// API: ADMIN DELETE KEY
// ============================================================
app.post('/api/admin/delete-key', verifyAdmin, async (req, res) => {
    const { key } = req.body;
    await supabase.from('keys').delete().eq('key_text', key);
    res.json({ success: true });
});

// ============================================================
// API: ADMIN DELETE ALL KEYS
// ============================================================
app.post('/api/admin/delete-all-keys', verifyAdmin, async (req, res) => {
    await supabase.from('keys').delete().neq('id', 0);
    res.json({ success: true });
});

// ============================================================
// API: ADMIN DELETE EXPIRED KEYS
// ============================================================
app.post('/api/admin/delete-expired-keys', verifyAdmin, async (req, res) => {
    const result = await deleteExpiredKeys();
    res.json({ success: true, deletedCount: result.updated });
});

// ============================================================
// API: ADMIN BAN USER
// ============================================================
app.post('/api/admin/ban-user', verifyAdmin, async (req, res) => {
    const { userId } = req.body;
    await supabase.from('users').update({ banned: 1 }).eq('user_id', userId);
    res.json({ success: true });
});

// ============================================================
// API: ADMIN UNBAN USER
// ============================================================
app.post('/api/admin/unban-user', verifyAdmin, async (req, res) => {
    const { userId } = req.body;
    await supabase.from('users').update({ banned: 0 }).eq('user_id', userId);
    res.json({ success: true });
});

// ============================================================
// API: ADMIN BAN IP
// ============================================================
app.post('/api/admin/ban-ip', verifyAdmin, async (req, res) => {
    const { ip, reason } = req.body;
    if (!ip) {
        return res.json({ success: false, error: 'IP required' });
    }
    
    const { error } = await supabase
        .from('ip_blacklist')
        .insert({
            ip_address: ip,
            reason: reason || 'No reason provided',
            banned_by: req.body.token,
            banned_at: Date.now()
        });
    
    if (error) {
        return res.json({ success: false, error: error.message });
    }
    
    res.json({ success: true, message: `IP ${ip} banned` });
});

// ============================================================
// API: ADMIN UNBAN IP
// ============================================================
app.post('/api/admin/unban-ip', verifyAdmin, async (req, res) => {
    const { ip } = req.body;
    await supabase.from('ip_blacklist').delete().eq('ip_address', ip);
    res.json({ success: true, message: `IP ${ip} unbanned` });
});

// ============================================================
// API: ADMIN GET BANNED IPS
// ============================================================
app.post('/api/admin/banned-ips', verifyAdmin, async (req, res) => {
    const { data } = await supabase
        .from('ip_blacklist')
        .select('*')
        .order('banned_at', { ascending: false });
    res.json({ success: true, ips: data || [] });
});

// ============================================================
// API: ADMIN GET SETTINGS
// ============================================================
app.post('/api/admin/get-settings', verifyAdmin, async (req, res) => {
    const { data } = await supabase.from('settings').select('*');
    const settings = {};
    if (data) {
        data.forEach(s => { settings[s.key] = s.value; });
    }
    res.json({ success: true, settings });
});

// ============================================================
// API: ADMIN SAVE SETTINGS
// ============================================================
app.post('/api/admin/settings', verifyAdmin, async (req, res) => {
    const { ip_lock_enabled, max_keys_per_user, cooldown_minutes, default_duration_hours } = req.body;
    
    if (ip_lock_enabled !== undefined) {
        await supabase.from('settings').upsert({ key: 'ip_lock_enabled', value: ip_lock_enabled, updated_at: Date.now() });
    }
    if (max_keys_per_user !== undefined) {
        await supabase.from('settings').upsert({ key: 'max_keys_per_user', value: max_keys_per_user.toString(), updated_at: Date.now() });
    }
    if (cooldown_minutes !== undefined) {
        await supabase.from('settings').upsert({ key: 'cooldown_minutes', value: cooldown_minutes.toString(), updated_at: Date.now() });
    }
    if (default_duration_hours !== undefined) {
        await supabase.from('settings').upsert({ key: 'default_duration_hours', value: default_duration_hours.toString(), updated_at: Date.now() });
    }
    
    res.json({ success: true });
});

// ============================================================
// API: ADMIN LOGOUT
// ============================================================
app.post('/api/admin/logout', verifyAdmin, async (req, res) => {
    adminToken = null;
    res.json({ success: true });
});

// ============================================================
// API: UNBAN MYSELF
// ============================================================
app.post('/api/unban-myself', async (req, res) => {
    try {
        const ip = getClientIp(req);
        await supabase.from('ip_blacklist').delete().eq('ip_address', ip);
        res.json({ success: true, message: `IP ${ip} has been unbanned.` });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// ============================================================
// START SERVER
// ============================================================
const PORT = process.env.PORT || 3000;

async function start() {
    app.listen(PORT, () => {
    });
}

start();

module.exports = app;