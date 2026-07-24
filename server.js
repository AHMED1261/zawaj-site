// server.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const { pool, initSchema } = require('./db');
const { signToken, requireAuth, requireAdmin } = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// CSRF Protection
const csrfProtection = csurf({ cookie: true });
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Rate Limiter
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.RATE_LIMIT_MAX ? parseInt(process.env.RATE_LIMIT_MAX) : 5,
  message: { error: 'طلبات كثيرة جدًا، يرجى المحاولة بعد 15 دقيقة.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Security Logger Helper
function securityLog(action, details) {
  console.log(`[SECURITY_LOG] ${new Date().toISOString()} - ACTION: ${action} - DETAILS: ${JSON.stringify(details)}`);
}

// Data Sanitization Helper
function sanitizeData(data) {
  if (!data) return data;
  const sanitized = {};
  for (let key in data) {
    if (typeof data[key] === 'string') {
      sanitized[key] = sanitizeHtml(data[key], { allowedTags: [], allowedAttributes: {} });
    } else {
      sanitized[key] = data[key];
    }
  }
  return sanitized;
}

// Approve User Checker Helper
async function requireApprovedUser(req, res, next) {
  try {
    const [rows] = await pool.query('SELECT status FROM users WHERE id = ?', [req.user.id]);
    if (rows.length && rows[0].status === 'approved') return next();
    res.status(403).json({ error: 'عضوية غير معتمدة للتصفح' });
  } catch (err) {
    next(err);
  }
}

// كل الأعمدة القابلة للتعبئة في الاستمارة (بيوصل من الفرونت اند)
// دالة مشتركة تتأكد إن الأعمدة اللي اتضافت مؤخرًا موجودة فعليًا قبل أي استعلام يستخدمها،
// بديل أضمن لـ "ADD COLUMN IF NOT EXISTS" اللي مش شغالة بثبات على كل إعدادات MySQL
let columnsVerified = false;
async function ensureRecentColumns() {
  if (columnsVerified) return; // نتأكد مرة واحدة بس لكل تشغيلة سيرفر، مش كل طلب
  const checks = [
    ['profile_answers', 'previously_engaged_details', 'TEXT'],
    ['profile_answers', 'marital_home_area', 'VARCHAR(150)']
  ];
  for (const [table, col, def] of checks) {
    const [rows] = await pool.query(
      `SELECT COUNT(*) as cnt FROM information_schema.columns
       WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?`,
      [table, col]
    );
    if (rows[0].cnt === 0) {
      await pool.query(`ALTER TABLE ${table} ADD COLUMN ${col} ${def}`);
      console.log(`ensureRecentColumns: تمت إضافة ${col} إلى ${table}`);
    }
  }
  columnsVerified = true;
}

const ANSWER_FIELDS = [
  'age','weight','height','skin_color','has_beard','exercises','health_issues',
  'education','job','job_type','income_level',
  'marital_status','has_children','children_count','children_ages','custody',
  'previously_engaged','previously_engaged_details','widow_duration','last_divorce_date','divorce_count',
  'current_wives_count','wants_polygamy','polygamy_with_first_wife_knowledge','wants_more_children',
  'father_job','mother_job','siblings_count','siblings_education',
  'governorate','area','area_type','marital_home_location','marital_home_area','housing_type','family_house_living',
  'religiosity_level','prays_regularly','smoker','quran_memorization','watches_series',
  'listens_music','religious_scholars_followed','studied_sharia','form_filled_by',
  'relative_relation','filled_with_knowledge','about_me',
  'partner_general_specs','partner_age_min','partner_age_max','partner_skin_color_preference',
  'partner_marital_status_accepted','accepts_with_children','accepts_children_with_father_custody',
  'accepted_governorates','hijab_preference',
  'partner_education_preference','partner_work_preference',
  'wants_publish_social','contacted_before','notes'
];

// ---------- تسجيل حساب جديد (هاتف + باسورد) ----------
app.post('/api/register', authLimiter, csrfProtection, async (req, res, next) => {
  try {
    const { phone, password, gender } = req.body;
    if (!phone || !password || !gender) {
      return res.status(400).json({ error: 'من فضلك املأ رقم الهاتف وكلمة المرور والنوع' });
    }
    // Password Policy
    if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{6,}$/.test(password)) {
      return res.status(400).json({ error: 'كلمة المرور ضعيفة. يجب أن تحتوي على الأقل 6 أحرف، حرف كبير، حرف صغير، رقم، ورمز خاص.' });
    }
    const password_hash = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (phone, password_hash, gender) VALUES (?, ?, ?)',
      [phone, password_hash, gender]
    );
    securityLog('User_Registered', { userId: result.insertId, role: 'user' });
    const token = signToken({ id: result.insertId, phone, role: 'user' });
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 30*24*60*60*1000 });
    res.status(201).json({ token, message: 'تم إنشاء الحساب، كمّل استمارة البيانات دلوقتي' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'رقم الهاتف ده مسجل قبل كده' });
    }
    next(err);
  }
});

// ---------- تسجيل الدخول ----------
app.post('/api/login', authLimiter, csrfProtection, async (req, res, next) => {
  try {
    const { phone, password } = req.body;
    const [rows] = await pool.query('SELECT * FROM users WHERE phone = ?', [phone]);
    if (!rows.length) {
      securityLog('Failed_Login', { phone: phone, reason: 'user not found' });
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      securityLog('Failed_Login', { phone: phone, reason: 'wrong password' });
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    }

    securityLog('Successful_Login', { userId: user.id, role: 'user' });
    const token = signToken({ id: user.id, phone: user.phone, role: 'user' });
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 30*24*60*60*1000 });
    res.json({ token, status: user.status, gender: user.gender });
  } catch (err) {
    next(err);
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'تم تسجيل الخروج' });
});

// ---------- تعبئة/تحديث استمارة البيانات (كل الحقول إلزامية) ----------
app.post('/api/profile/submit', requireAuth, csrfProtection, async (req, res, next) => {
  try {
    let data = sanitizeData(req.body); // Sanitize user input for XSS

    const [userRows] = await pool.query('SELECT status FROM users WHERE id = ?', [req.user.id]);
    if (!userRows.length) return res.status(404).json({ error: 'الحساب مش موجود' });
    const userStatus = userRows[0].status;

    if (userStatus === 'suspended') {
      return res.status(403).json({ error: 'الحساب موقوف، تواصل مع الإدارة.' });
    }

    // تحقق: كل الحقول إلزامية
    const missing = ANSWER_FIELDS.filter(f => data[f] === undefined || data[f] === null || data[f] === '');
    const conditionallyOptional = new Set([
      'children_count','children_ages','custody','widow_duration','last_divorce_date','divorce_count',
      'current_wives_count','wants_polygamy','polygamy_with_first_wife_knowledge','relative_relation',
      'family_house_living','filled_with_knowledge','has_beard','hijab_preference',
      'previously_engaged_details','accepts_with_children','accepts_children_with_father_custody','notes'
    ]);
    const trulyMissing = missing.filter(f => !conditionallyOptional.has(f));
    if (trulyMissing.length) {
      return res.status(400).json({ error: 'في حقول إلزامية ناقصة', fields: trulyMissing });
    }

    // Server-Side Validation
    if (data.age && (isNaN(data.age) || data.age < 18 || data.age > 100)) return res.status(400).json({ error: 'عمر غير صالح' });
    if (data.height && (isNaN(data.height) || data.height < 100 || data.height > 250)) return res.status(400).json({ error: 'طول غير صالح' });
    if (data.weight && (isNaN(data.weight) || data.weight < 30 || data.weight > 300)) return res.status(400).json({ error: 'وزن غير صالح' });
    if (data.partner_age_min && isNaN(data.partner_age_min)) return res.status(400).json({ error: 'عمر الشريك غير صالح' });
    if (data.partner_age_max && isNaN(data.partner_age_max)) return res.status(400).json({ error: 'عمر الشريك غير صالح' });

    if (userStatus === 'approved' || userStatus === 'needs_revision') {
      // إرسال التعديلات لجدول profile_edits عشان تتراجع
      await pool.query(
        `INSERT INTO profile_edits (user_id, data, status) VALUES (?, ?, 'pending')`,
        [req.user.id, JSON.stringify(data)]
      );
      return res.json({ message: 'تم إرسال التعديلات بنجاح. سيتم مراجعتها من قبل الإدارة.' });
    } else {
      // حفظ مباشر في الاستمارة لأنها لسة ما اتوافقش عليها
      const columns = ANSWER_FIELDS;
      const values = columns.map(f => (data[f] === '' ? null : data[f]));
      const placeholders = columns.map(() => '?').join(',');
      const updateClause = columns.map(c => `${c}=VALUES(${c})`).join(',');

      await pool.query(
        `INSERT INTO profile_answers (user_id, ${columns.join(',')})
         VALUES (?, ${placeholders})
         ON DUPLICATE KEY UPDATE ${updateClause}`,
        [req.user.id, ...values]
      );
      
      await pool.query('UPDATE users SET status = ? WHERE id = ?', ['pending', req.user.id]);
      return res.json({ message: 'تم حفظ بياناتك بنجاح. حسابك قيد المراجعة.' });
    }
  } catch (err) {
    next(err);
  }
});

// حفظ المسودة - للحسابات غير المكتملة فقط
app.post('/api/profile/draft', requireAuth, csrfProtection, async (req, res, next) => {
  try {
    let data = sanitizeData(req.body);
    const [userRows] = await pool.query('SELECT status FROM users WHERE id = ?', [req.user.id]);
    if (!userRows.length || userRows[0].status !== 'incomplete') {
      return res.status(403).json({ error: 'حفظ المسودة متاح فقط للحسابات غير المكتملة' });
    }

    const columns = ANSWER_FIELDS.filter(f => data[f] !== undefined);
    if (!columns.length) return res.json({ message: 'لا توجد بيانات للحفظ' });

    const values = columns.map(f => (data[f] === '' ? null : data[f]));
    const placeholders = columns.map(() => '?').join(',');
    const updateClause = columns.map(c => `${c}=VALUES(${c})`).join(',');

    await pool.query(
      `INSERT INTO profile_answers (user_id, ${columns.join(',')})
       VALUES (?, ${placeholders})
       ON DUPLICATE KEY UPDATE ${updateClause}`,
      [req.user.id, ...values]
    );

    res.json({ message: 'تم حفظ المسودة بنجاح' });
  } catch (err) {
    next(err);
  }
});

// ---------- لوحة تحكم المستخدم (Dashboard) ----------
app.get('/api/user/dashboard', requireAuth, async (req, res, next) => {
  try {
    const [userRows] = await pool.query(
      `SELECT u.id, u.phone, u.gender, u.status, u.created_at, u.updated_at, p.submitted_at 
       FROM users u LEFT JOIN profile_answers p ON p.user_id = u.id 
       WHERE u.id = ?`,
      [req.user.id]
    );
    if (!userRows.length) return res.status(404).json({ error: 'الحساب غير موجود' });
    
    // Check pending edits
    const [editRows] = await pool.query('SELECT created_at FROM profile_edits WHERE user_id = ? AND status = "pending" ORDER BY created_at DESC LIMIT 1', [req.user.id]);
    
    // Check notifications count
    const [notifRows] = await pool.query('SELECT COUNT(*) as unread FROM notifications WHERE user_id = ? AND is_read = false', [req.user.id]);

    // Calculate completion percentage
    const [profileDataRows] = await pool.query('SELECT * FROM profile_answers WHERE user_id = ?', [req.user.id]);
    let completionPercentage = 0;
    if (profileDataRows.length) {
      const answers = profileDataRows[0];
      const filledFields = ANSWER_FIELDS.filter(f => answers[f] !== null && answers[f] !== '').length;
      completionPercentage = Math.round((filledFields / ANSWER_FIELDS.length) * 100);
    }

    res.json({
      profile: userRows[0],
      pending_edit_date: editRows.length ? editRows[0].created_at : null,
      unread_notifications: notifRows[0].unread,
      completion_percentage: completionPercentage
    });
  } catch (err) {
    next(err);
  }
});

app.get('/api/user/profile', requireAuth, async (req, res, next) => {
  try {
    const [rows] = await pool.query('SELECT * FROM profile_answers WHERE user_id = ?', [req.user.id]);
    if (!rows.length) return res.json({});
    res.json(rows[0]);
  } catch (err) {
    next(err);
  }
});

app.get('/api/user/notifications', requireAuth, async (req, res, next) => {
  try {
    const [rows] = await pool.query('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', [req.user.id]);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.post('/api/user/notifications/:id/read', requireAuth, csrfProtection, async (req, res, next) => {
  try {
    await pool.query('UPDATE notifications SET is_read = true WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

app.post('/api/user/password', requireAuth, csrfProtection, async (req, res, next) => {
  try {
    const { current_password, new_password } = req.body;
    const [rows] = await pool.query('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'الحساب غير موجود' });

    const match = await bcrypt.compare(current_password, rows[0].password_hash);
    if (!match) return res.status(400).json({ error: 'كلمة المرور الحالية غير صحيحة' });

    if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{6,}$/.test(new_password)) {
      return res.status(400).json({ error: 'كلمة المرور الجديدة ضعيفة. يجب أن تحتوي على الأقل 6 أحرف، حرف كبير، حرف صغير، رقم، ورمز خاص.' });
    }

    const hash = await bcrypt.hash(new_password, 10);
    await pool.query('UPDATE users SET password_hash = ? WHERE id = ?', [hash, req.user.id]);
    
    // Add notification
    await pool.query('INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)', [req.user.id, 'تغيير كلمة المرور', 'تم تغيير كلمة المرور بنجاح.']);
    securityLog('User_Password_Changed', { userId: req.user.id });
    
    res.json({ message: 'تم تغيير كلمة المرور بنجاح' });
  } catch (err) {
    next(err);
  }
});

// ---------- طلبات الزواج (Marriage Requests) ----------
app.post('/api/requests/:receiver_id/send', requireAuth, csrfProtection, async (req, res, next) => {
  try {
    const senderId = req.user.id;
    const receiverId = Number(req.params.receiver_id);
    
    if (senderId === receiverId) return res.status(400).json({ error: 'لا يمكنك إرسال طلب لنفسك' });
    
    const [senderRows] = await pool.query('SELECT status FROM users WHERE id = ?', [senderId]);
    if (senderRows[0].status !== 'approved') return res.status(403).json({ error: 'حسابك غير معتمد لإرسال الطلبات' });
    
    const [receiverRows] = await pool.query('SELECT status FROM users WHERE id = ?', [receiverId]);
    if (!receiverRows.length) return res.status(404).json({ error: 'المستلم غير موجود' });
    if (receiverRows[0].status !== 'approved') return res.status(400).json({ error: 'المستلم غير معتمد حاليا' });
    
    const [existing] = await pool.query(
      "SELECT id FROM marriage_requests WHERE sender_id = ? AND receiver_id = ? AND status NOT IN ('rejected_by_receiver', 'rejected_by_admin', 'cancelled')",
      [senderId, receiverId]
    );
    if (existing.length) return res.status(400).json({ error: 'يوجد طلب نشط بالفعل بينكم' });
    
    await pool.query('INSERT INTO marriage_requests (sender_id, receiver_id, status) VALUES (?, ?, "pending")', [senderId, receiverId]);
    await pool.query('INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)', [receiverId, 'طلب زواج جديد', 'لقد تلقيت طلب زواج جديد، يرجى مراجعته.']);
    
    res.json({ message: 'تم إرسال الطلب بنجاح' });
  } catch (err) { next(err); }
});

app.get('/api/user/requests/incoming', requireAuth, async (req, res, next) => {
  try {
    const [rows] = await pool.query(
      `SELECT r.id as request_id, r.status, r.created_at, r.updated_at, u.gender, p.age, p.governorate, p.education, p.job, p.marital_status 
       FROM marriage_requests r 
       JOIN users u ON u.id = r.sender_id 
       JOIN profile_answers p ON p.user_id = u.id 
       WHERE r.receiver_id = ? ORDER BY r.updated_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

app.get('/api/user/requests/outgoing', requireAuth, async (req, res, next) => {
  try {
    const [rows] = await pool.query(
      `SELECT r.id as request_id, r.status, r.created_at, r.updated_at, r.receiver_id, u.gender, p.age, p.governorate, p.education, p.job, p.marital_status 
       FROM marriage_requests r 
       JOIN users u ON u.id = r.receiver_id 
       JOIN profile_answers p ON p.user_id = u.id 
       WHERE r.sender_id = ? ORDER BY r.updated_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

app.post('/api/requests/:request_id/accept', requireAuth, csrfProtection, async (req, res, next) => {
  try {
    const [rows] = await pool.query('SELECT * FROM marriage_requests WHERE id = ? AND receiver_id = ? AND status = "pending"', [req.params.request_id, req.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'الطلب غير موجود أو غير متاح للقبول' });
    
    await pool.query('UPDATE marriage_requests SET status = "pending_admin_review" WHERE id = ?', [req.params.request_id]);
    await pool.query('INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)', [rows[0].sender_id, 'تم قبول طلبك مبدئياً', 'الطرف الآخر وافق على طلبك. الطلب الآن قيد المراجعة من الإدارة.']);
    
    res.json({ message: 'تم قبول الطلب، في انتظار مراجعة الإدارة' });
  } catch (err) { next(err); }
});

app.post('/api/requests/:request_id/reject', requireAuth, csrfProtection, async (req, res, next) => {
  try {
    const [rows] = await pool.query('SELECT * FROM marriage_requests WHERE id = ? AND receiver_id = ? AND status = "pending"', [req.params.request_id, req.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'الطلب غير موجود أو غير متاح للرفض' });
    
    await pool.query('UPDATE marriage_requests SET status = "rejected_by_receiver" WHERE id = ?', [req.params.request_id]);
    await pool.query('INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)', [rows[0].sender_id, 'تم رفض طلبك', 'نأسف، الطرف الآخر رفض طلب الزواج.']);
    
    res.json({ message: 'تم رفض الطلب' });
  } catch (err) { next(err); }
});

app.post('/api/requests/:request_id/cancel', requireAuth, csrfProtection, async (req, res, next) => {
  try {
    const [rows] = await pool.query('SELECT * FROM marriage_requests WHERE id = ? AND sender_id = ? AND status IN ("pending", "pending_admin_review")', [req.params.request_id, req.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'الطلب غير موجود أو لا يمكن إلغاؤه الآن' });
    
    await pool.query('UPDATE marriage_requests SET status = "cancelled" WHERE id = ?', [req.params.request_id]);
    
    res.json({ message: 'تم إلغاء الطلب' });
  } catch (err) { next(err); }
});

app.get('/api/requests/:request_id/contact', requireAuth, async (req, res, next) => {
  try {
    const [rows] = await pool.query('SELECT * FROM marriage_requests WHERE id = ? AND status = "approved" AND (sender_id = ? OR receiver_id = ?)', [req.params.request_id, req.user.id, req.user.id]);
    if (!rows.length) return res.status(403).json({ error: 'غير مصرح بعرض وسيلة التواصل' });
    
    const otherUserId = rows[0].sender_id === req.user.id ? rows[0].receiver_id : rows[0].sender_id;
    const [otherUser] = await pool.query('SELECT phone FROM users WHERE id = ?', [otherUserId]);
    
    res.json({ phone: otherUser[0].phone });
  } catch (err) { next(err); }
});

// ---------- عرض البروفايلات المعتمدة فقط + فلاتر (كتابة واختيار) ----------
app.get('/api/profiles', async (req, res, next) => {
  try {
    await ensureRecentColumns();

    const {
      gender, minAge, maxAge, governorate, maritalHomeLocation, maritalStatus, wantsChildren,
      education, smoker, jobType, incomeLevel,
      praysRegularly, exercises, housingType, areaType, hasBeard,
      wantsPolygamy, minHeight, maxHeight,
      minWeight, maxWeight, sort, page = 1, limit = 12
    } = req.query;

    const toArray = v => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

    const where = ["u.status = 'approved'"];
    const params = [];

    if (gender) { where.push('u.gender = ?'); params.push(gender); }
    if (minAge) { where.push('p.age >= ?'); params.push(Number(minAge)); }
    if (maxAge) { where.push('p.age <= ?'); params.push(Number(maxAge)); }
    if (minHeight) { where.push('p.height >= ?'); params.push(Number(minHeight)); }
    if (maxHeight) { where.push('p.height <= ?'); params.push(Number(maxHeight)); }
    if (minWeight) { where.push('p.weight >= ?'); params.push(Number(minWeight)); }
    if (maxWeight) { where.push('p.weight <= ?'); params.push(Number(maxWeight)); }

    const governorates = toArray(governorate);
    if (governorates.length) { where.push(`p.governorate IN (${governorates.map(() => '?').join(',')})`); params.push(...governorates); }

    const maritalHomeLocations = toArray(maritalHomeLocation);
    if (maritalHomeLocations.length) { where.push(`p.marital_home_location IN (${maritalHomeLocations.map(() => '?').join(',')})`); params.push(...maritalHomeLocations); }

    const maritalStatuses = toArray(maritalStatus);
    if (maritalStatuses.length) { where.push(`p.marital_status IN (${maritalStatuses.map(() => '?').join(',')})`); params.push(...maritalStatuses); }

    const educations = toArray(education);
    if (educations.length) { where.push(`p.education IN (${educations.map(() => '?').join(',')})`); params.push(...educations); }
    
    const jobTypes = toArray(jobType);
    if (jobTypes.length) { where.push(`p.job_type IN (${jobTypes.map(() => '?').join(',')})`); params.push(...jobTypes); }

    if (wantsChildren) { where.push('p.wants_more_children = ?'); params.push(wantsChildren); }
    if (smoker) { where.push('p.smoker = ?'); params.push(smoker); }
    if (incomeLevel) { where.push('p.income_level = ?'); params.push(incomeLevel); }
    if (praysRegularly) { where.push('p.prays_regularly = ?'); params.push(praysRegularly); }
    if (exercises) { where.push('p.exercises = ?'); params.push(exercises); }
    if (housingType) { where.push('p.housing_type = ?'); params.push(housingType); }
    if (areaType) { where.push('p.area_type = ?'); params.push(areaType); }
    if (hasBeard) { where.push('p.has_beard = ?'); params.push(hasBeard); }
    if (wantsPolygamy) { where.push('p.wants_polygamy = ?'); params.push(wantsPolygamy); }

    const whereSql = `WHERE ${where.join(' AND ')}`;
    
    let orderSql = 'ORDER BY u.created_at DESC';
    if (sort === 'oldest') orderSql = 'ORDER BY u.created_at ASC';
    else if (sort === 'youngest') orderSql = 'ORDER BY p.age ASC, u.created_at DESC';
    else if (sort === 'oldest_age') orderSql = 'ORDER BY p.age DESC, u.created_at DESC';

    const offset = (Number(page) - 1) * Number(limit);

    // Filter fields returned to users to ONLY allowed fields
    const [rows] = await pool.query(
      `SELECT u.id as user_id, u.gender, p.age, p.governorate, p.education, p.job, p.marital_status, p.about_me, p.marital_home_location, p.marital_home_area, p.wants_more_children
       FROM users u JOIN profile_answers p ON p.user_id = u.id
       ${whereSql}
       ${orderSql}
       LIMIT ? OFFSET ?`,
      [...params, Number(limit), offset]
    );

    const [countRows] = await pool.query(
      `SELECT COUNT(*) as total FROM users u JOIN profile_answers p ON p.user_id = u.id ${whereSql}`,
      params
    );

    res.json({ data: rows, total: countRows[0].total, page: Number(page), limit: Number(limit) });
  } catch (err) {
    next(err);
  }
});

app.get('/api/profiles/:id', async (req, res, next) => {
  try {
    const userId = Number(req.params.id);
    if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: 'معرف غير صالح' });

    // Explicitly select only public display fields, avoiding p.* and private internal fields
    const displayFields = ANSWER_FIELDS.filter(f => !['wants_publish_social', 'contacted_before', 'notes'].includes(f));
    const fieldsSql = displayFields.map(f => `p.${f}`).join(', ');

    const [rows] = await pool.query(
      `SELECT u.id as user_id, u.gender, ${fieldsSql}
       FROM users u JOIN profile_answers p ON p.user_id = u.id
       WHERE u.id = ? AND u.status = 'approved'`,
      [userId]
    );

    if (!rows.length) {
      return res.status(404).json({ error: 'البروفايل غير موجود أو غير معتمد.' });
    }

    res.json({ data: rows[0] });
  } catch (err) {
    next(err);
  }
});



// ============ لوحة المشرف ============

app.post('/api/admin/login', authLimiter, csrfProtection, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const [rows] = await pool.query('SELECT * FROM admins WHERE username = ?', [username]);
    if (!rows.length) {
      securityLog('Admin_Failed_Login', { username, reason: 'not found' });
      return res.status(401).json({ error: 'بيانات دخول غير صحيحة' });
    }
    const match = await bcrypt.compare(password, rows[0].password_hash);
    if (!match) {
      securityLog('Admin_Failed_Login', { username, reason: 'wrong password' });
      return res.status(401).json({ error: 'بيانات دخول غير صحيحة' });
    }
    securityLog('Admin_Successful_Login', { adminId: rows[0].id, username });
    const token = signToken({ id: rows[0].id, username, role: 'admin' }, '2d');
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 2*24*60*60*1000 });
    res.json({ token });
  } catch (err) {
    next(err);
  }
});

app.get('/api/admin/users', requireAdmin, async (req, res, next) => {
  try {
    const status = req.query.status || 'pending';
    let rows;
    if (status === 'pending_edits') {
      [rows] = await pool.query(
        `SELECT u.id, u.phone, u.gender, u.status, u.created_at, p.*, e.data as pending_data
         FROM profile_edits e 
         INNER JOIN users u ON u.id = e.user_id 
         LEFT JOIN profile_answers p ON p.user_id = u.id
         WHERE e.status = 'pending' ORDER BY e.created_at ASC`
      );
    } else {
      [rows] = await pool.query(
        `SELECT u.id, u.phone, u.gender, u.status, u.created_at, p.*
         FROM users u LEFT JOIN profile_answers p ON p.user_id = u.id
         WHERE u.status = ? ORDER BY u.created_at ASC`,
        [status]
      );
    }
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.post('/api/admin/users/:id/approve', requireAdmin, csrfProtection, async (req, res, next) => {
  try {
    const userId = Number(req.params.id);
    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({ error: 'رقم الحساب غير صحيح' });
    }

    const [result] = await pool.query(
      `UPDATE users u
       INNER JOIN profile_answers p ON p.user_id = u.id
       SET u.status = 'approved'
       WHERE u.id = ? AND (u.status = 'pending' OR u.status = 'needs_revision')`,
      [userId]
    );
    if (!result.affectedRows) {
      return res.status(409).json({ error: 'لا يمكن اعتماد هذا الحساب. تأكد أنه أرسل الاستمارة.' });
    }
    await pool.query('INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)', [userId, 'تم اعتماد الحساب', 'تم مراجعة حسابك واعتماده بنجاح. يمكنك الآن تصفح البروفايلات.']);
    securityLog('Profile_Approved', { adminId: req.admin.id, targetUserId: userId });
    res.json({ message: 'تم اعتماد الحساب' });
  } catch (err) {
    next(err);
  }
});

app.post('/api/admin/users/:id/reject', requireAdmin, csrfProtection, async (req, res, next) => {
  try {
    const { reason } = req.body;
    await pool.query("UPDATE users SET status = 'rejected', admin_notes = ? WHERE id = ?", [reason || null, req.params.id]);
    await pool.query('INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)', [req.params.id, 'تم رفض الحساب', 'تم رفض حسابك بواسطة الإدارة.' + (reason ? ' السبب: ' + reason : '')]);
    securityLog('Profile_Rejected', { adminId: req.admin.id, targetUserId: req.params.id, reason });
    res.json({ message: 'تم رفض الحساب' });
  } catch (err) {
    next(err);
  }
});

app.post('/api/admin/users/:id/suspend', requireAdmin, csrfProtection, async (req, res, next) => {
  try {
    await pool.query("UPDATE users SET status = 'suspended' WHERE id = ?", [req.params.id]);
    await pool.query('INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)', [req.params.id, 'تم إيقاف الحساب', 'تم إيقاف حسابك بواسطة الإدارة.']);
    securityLog('Account_Suspended', { adminId: req.admin.id, targetUserId: req.params.id });
    res.json({ message: 'تم إيقاف الحساب' });
  } catch (err) {
    next(err);
  }
});

app.post('/api/admin/users/:id/revise', requireAdmin, csrfProtection, async (req, res, next) => {
  try {
    const { reason } = req.body;
    await pool.query("UPDATE users SET status = 'needs_revision', admin_notes = ? WHERE id = ?", [reason || null, req.params.id]);
    await pool.query('INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)', [req.params.id, 'مطلوب تعديل الحساب', 'طلب المشرف تعديل بعض بيانات حسابك.' + (reason ? ' السبب: ' + reason : '')]);
    securityLog('Profile_Needs_Revision', { adminId: req.admin.id, targetUserId: req.params.id, reason });
    res.json({ message: 'تم طلب التعديل' });
  } catch (err) {
    next(err);
  }
});

// ---------- تعديلات البروفايل المعلقة (Pending Edits) ----------
app.get('/api/admin/users/:id/pending-edit', requireAdmin, async (req, res, next) => {
  try {
    const [rows] = await pool.query('SELECT * FROM profile_edits WHERE user_id = ? AND status = "pending" ORDER BY created_at DESC LIMIT 1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'مفيش تعديلات معلقة' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

app.post('/api/admin/users/:id/approve-edit', requireAdmin, csrfProtection, async (req, res, next) => {
  try {
    const [editRows] = await pool.query('SELECT * FROM profile_edits WHERE user_id = ? AND status = "pending" ORDER BY created_at DESC LIMIT 1', [req.params.id]);
    if (!editRows.length) return res.status(404).json({ error: 'مفيش تعديلات معلقة' });
    
    const edit = editRows[0];
    const updates = typeof edit.data === 'string' ? JSON.parse(edit.data) : edit.data;
    
    const allowedFields = ANSWER_FIELDS.filter(f => updates[f] !== undefined);
    if (allowedFields.length) {
      const setClause = allowedFields.map(f => `${f} = ?`).join(', ');
      const values = allowedFields.map(f => (updates[f] === '' ? null : updates[f]));
      await pool.query(`UPDATE profile_answers SET ${setClause} WHERE user_id = ?`, [...values, req.params.id]);
    }
    
    await pool.query('UPDATE profile_edits SET status = "approved" WHERE id = ?', [edit.id]);
    await pool.query('UPDATE users SET status = "approved" WHERE id = ?', [req.params.id]);
    await pool.query('INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)', [req.params.id, 'تم قبول التعديلات', 'تمت الموافقة على تعديلات حسابك بنجاح.']);
    securityLog('Profile_Edit_Approved', { adminId: req.admin.id, targetUserId: req.params.id });
    
    res.json({ message: 'تم قبول التعديلات' });
  } catch (err) { next(err); }
});

app.post('/api/admin/users/:id/reject-edit', requireAdmin, csrfProtection, async (req, res, next) => {
  try {
    const [editRows] = await pool.query('SELECT * FROM profile_edits WHERE user_id = ? AND status = "pending" ORDER BY created_at DESC LIMIT 1', [req.params.id]);
    if (!editRows.length) return res.status(404).json({ error: 'مفيش تعديلات معلقة' });
    
    await pool.query('UPDATE profile_edits SET status = "rejected" WHERE id = ?', [editRows[0].id]);
    await pool.query('INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)', [req.params.id, 'تم رفض التعديلات', 'تم رفض تعديلات حسابك بواسطة الإدارة.']);
    securityLog('Profile_Edit_Rejected', { adminId: req.admin.id, targetUserId: req.params.id });
    
    res.json({ message: 'تم رفض التعديلات' });
  } catch (err) { next(err); }
});

// ---------- طلبات الزواج (Admin) ----------
app.get('/api/admin/requests', requireAdmin, async (req, res, next) => {
  try {
    const [rows] = await pool.query(`
      SELECT r.*, s.phone as sender_phone, rec.phone as receiver_phone 
      FROM marriage_requests r
      JOIN users s ON r.sender_id = s.id
      JOIN users rec ON r.receiver_id = rec.id
      WHERE r.status = 'pending_admin_review'
      ORDER BY r.updated_at ASC
    `);
    res.json(rows);
  } catch (err) { next(err); }
});

app.post('/api/admin/requests/:request_id/approve', requireAdmin, csrfProtection, async (req, res, next) => {
  try {
    const [rows] = await pool.query('SELECT * FROM marriage_requests WHERE id = ? AND status = "pending_admin_review"', [req.params.request_id]);
    if (!rows.length) return res.status(404).json({ error: 'الطلب غير متاح' });
    
    await pool.query('UPDATE marriage_requests SET status = "approved", admin_id = ?, decision_date = NOW() WHERE id = ?', [req.admin.id, req.params.request_id]);
    
    await pool.query('INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)', [rows[0].sender_id, 'تمت الموافقة النهائية', 'الإدارة وافقت على طلب الزواج، يمكنك الآن رؤية وسيلة التواصل.']);
    await pool.query('INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)', [rows[0].receiver_id, 'تمت الموافقة النهائية', 'الإدارة وافقت على طلب الزواج، يمكنك الآن رؤية وسيلة التواصل.']);
    
    res.json({ message: 'تم اعتماد الطلب' });
  } catch (err) { next(err); }
});

app.post('/api/admin/requests/:request_id/reject', requireAdmin, csrfProtection, async (req, res, next) => {
  try {
    const [rows] = await pool.query('SELECT * FROM marriage_requests WHERE id = ? AND status = "pending_admin_review"', [req.params.request_id]);
    if (!rows.length) return res.status(404).json({ error: 'الطلب غير متاح' });
    
    await pool.query('UPDATE marriage_requests SET status = "rejected_by_admin", admin_id = ?, decision_date = NOW() WHERE id = ?', [req.admin.id, req.params.request_id]);
    
    await pool.query('INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)', [rows[0].sender_id, 'تم رفض طلبك من الإدارة', 'نأسف، رفضت الإدارة طلب الزواج.']);
    
    res.json({ message: 'تم رفض الطلب' });
  } catch (err) { next(err); }
});

// تعديل بيانات الاستمارة المباشر - المشرف بس يقدر يعمل كده
app.patch('/api/admin/users/:id/profile', requireAdmin, csrfProtection, async (req, res, next) => {
  try {
    const updates = sanitizeData(req.body);
    const allowedFields = ANSWER_FIELDS.filter(f => updates[f] !== undefined);
    if (!allowedFields.length) return res.status(400).json({ error: 'مفيش بيانات للتعديل' });

    const setClause = allowedFields.map(f => `${f} = ?`).join(', ');
    const values = allowedFields.map(f => (updates[f] === '' ? null : updates[f]));

    await pool.query(
      `UPDATE profile_answers SET ${setClause} WHERE user_id = ?`,
      [...values, req.params.id]
    );
    securityLog('Admin_Updated_Profile', { adminId: req.admin.id, targetUserId: req.params.id, updatedFields: allowedFields });

    res.json({ message: 'تم تعديل البيانات بنجاح' });
  } catch (err) {
    next(err);
  }
});

// حذف حساب نهائيًا - المشرف بس
app.delete('/api/admin/users/:id', requireAdmin, csrfProtection, async (req, res, next) => {
  try {
    await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
    securityLog('Admin_Deleted_User', { adminId: req.admin.id, targetUserId: req.params.id });
    res.json({ message: 'تم حذف الحساب نهائيًا' });
  } catch (err) {
    next(err);
  }
});

// توليد بيانات تجريبية (200 بروفايل معتمد) لاختبار الفلاتر - محمي بحساب المشرف
// ملحوظة أداء: بيستخدم إدخال مجمّع (Bulk Insert) بدل استعلام منفصل لكل بروفايل
// عشان يتجنب أي timeout من السيرفر مع أعداد كبيرة
app.post('/api/admin/seed-test-data', requireAdmin, csrfProtection, async (req, res, next) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ error: 'غير مسموح بإنشاء بيانات تجريبية في بيئة الإنتاج' });
  }
  try {
    await ensureRecentColumns();

    const requestedCount = Number(req.body.count);
    const count = Math.max(1, Math.min(Number.isFinite(requestedCount) ? Math.floor(requestedCount) : 200, 500));

    const governorates = ['القاهرة','الجيزة','الإسكندرية','الدقهلية','الشرقية','المنوفية','القليوبية','الغربية','أسيوط','سوهاج','المنيا','بني سويف','الفيوم','البحيرة','كفر الشيخ','دمياط','بورسعيد','الإسماعيلية','السويس','أسوان','الأقصر'];
    const skinColors = ['فاتح','قمحي','أسمر','أبيض'];
    const educations = ['أقل من الثانوية','ثانوية عامة','دبلوم (متوسط)','بكالوريوس/ليسانس (عالي)','دراسات عليا (ماجستير/دكتوراه)'];
    const jobs = ['مهندس','محاسب','مدرس','طبيب','موظف حكومي','تاجر','صاحب مشروع','فني','ممرض'];
    const maritalOptions = ['single','divorced','widowed'];
    const yesNo = ['yes','no'];
    const rand = arr => arr[Math.floor(Math.random() * arr.length)];
    const randInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

    // باسورد واحد مشفّر يتشارك فيه كل الحسابات التجريبية (توفير وقت التشفير)
    const sharedPasswordHash = await bcrypt.hash('test123456', 10);

    const userRows = [];
    const profileDataList = [];

    for (let i = 0; i < count; i++) {
      const gender = i % 2 === 0 ? 'male' : 'female';
      // رقم هاتف وهمي واضح (يبدأ بـ 0000 - مستحيل يتكرر مع رقم مصري حقيقي) عشان نعرف نحذفهم بعدين من غير أي عمود إضافي
      const phone = `0000${String(i).padStart(6, '0')}`;
      userRows.push([phone, sharedPasswordHash, gender, 'approved']);

      const marital = rand(maritalOptions);
      const hasChildren = marital !== 'single' ? rand(yesNo) : 'no';

      profileDataList.push({
        age: randInt(20, 55), weight: randInt(50, 100), height: randInt(155, 190),
        skin_color: rand(skinColors), has_beard: gender === 'male' ? rand(yesNo) : null,
        exercises: rand(yesNo), health_issues: 'لا يوجد',
        education: rand(educations), job: rand(jobs),
        job_type: rand(['government','private','business_owner']),
        income_level: rand(['normal','medium','welloff','high']),
        marital_status: marital, has_children: hasChildren,
        children_count: hasChildren === 'yes' ? randInt(1,4) : null,
        children_ages: hasChildren === 'yes' ? `${randInt(1,15)}` : null,
        custody: hasChildren === 'yes' ? rand(['الأم','الأب']) : null,
        previously_engaged: rand(yesNo),
        previously_engaged_details: 'بيانات تجريبية',
        widow_duration: marital === 'widowed' ? `${randInt(1,5)} سنوات` : null,
        last_divorce_date: marital === 'divorced' ? `202${randInt(0,4)}-0${randInt(1,9)}-15` : null,
        divorce_count: marital === 'divorced' ? randInt(1,2) : null,
        current_wives_count: marital === 'married' ? randInt(1,2) : null,
        wants_polygamy: gender === 'male' ? rand(yesNo) : null,
        polygamy_with_first_wife_knowledge: null,
        wants_more_children: rand(['yes','no','maybe']),
        father_job: rand(jobs), mother_job: rand(['ربة منزل', ...jobs]),
        siblings_count: randInt(0,6), siblings_education: rand(educations),
        governorate: rand(governorates), area: 'حي تجريبي',
        area_type: rand(['popular','medium','upscale']),
        marital_home_location: rand(governorates), marital_home_area: rand(['حي تجريبي 1','حي تجريبي 2','وسط البلد','حي راقي']),
        housing_type: rand(['owned','fixed_rent','open_rent','family_house']),
        family_house_living: rand(['separate','with_family']),
        religiosity_level: rand(['ملتزم جدًا','ملتزم','متوسط']),
        prays_regularly: rand(yesNo), smoker: rand(yesNo),
        quran_memorization: rand(['جزء عم','5 أجزاء','10 أجزاء','القرآن كامل','لا يوجد']),
        watches_series: rand(yesNo), listens_music: rand(yesNo),
        religious_scholars_followed: 'غير محدد',
        studied_sharia: rand(['yes','no','planning']),
        form_filled_by: 'self', relative_relation: null, filled_with_knowledge: 'yes',
        about_me: 'بيانات تجريبية لاختبار نظام الفلاتر.',
        partner_general_specs: 'صفات عامة تجريبية', partner_age_min: randInt(20,30), partner_age_max: randInt(31,45),
        partner_skin_color_preference: rand(skinColors),
        partner_marital_status_accepted: 'آنسة، مطلقة',
        accepts_with_children: rand(['yes','no','indifferent']),
        accepts_children_with_father_custody: rand(['yes','no','indifferent']),
        accepted_governorates: rand(governorates),
        hijab_preference: rand(['hijab','niqab','either']),
        partner_education_preference: rand(['high','medium','either']),
        partner_work_preference: rand(['works','not_working','either']),
        wants_publish_social: rand(yesNo), contacted_before: 'no', notes: ''
      });
    }

    // نستخدم Transaction عشان لو أي خطوة فشلت، يترجع كل حاجة زي ما كانت
    // من غير ما يفضل حساب "شبح" من غير بيانات استمارة.
    // لا نعتمد على أن أرقام الـ IDs متتالية؛ بعض إعدادات MySQL لا تضمن ذلك.
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // كل مرة نبدأ بدفعة نظيفة، ليظل زر التوليد قابلاً للاستخدام أكثر من مرة.
      await conn.query("DELETE FROM users WHERE phone LIKE '0000%'");

      await conn.query(
        'INSERT INTO users (phone, password_hash, gender, status) VALUES ?',
        [userRows]
      );

      const [createdUsers] = await conn.query(
        'SELECT id, phone FROM users WHERE phone LIKE \'0000%\''
      );
      const userIdsByPhone = new Map(createdUsers.map(user => [user.phone, user.id]));
      if (userIdsByPhone.size !== count) {
        throw new Error('تعذر التحقق من الحسابات التجريبية التي تم إنشاؤها');
      }

      const cols = ANSWER_FIELDS;
      const profileRows = profileDataList.map((vals, idx) => [
        userIdsByPhone.get(userRows[idx][0]),
        ...cols.map(c => (vals[c] !== undefined ? vals[c] : null))
      ]);

      await conn.query(
        `INSERT INTO profile_answers (user_id, ${cols.join(',')}) VALUES ?`,
        [profileRows]
      );

      await conn.commit();
    } catch (innerErr) {
      await conn.rollback();
      throw innerErr;
    } finally {
      conn.release();
    }

    res.json({ message: `تم توليد ${count} بروفايل تجريبي معتمد` });
  } catch (err) {
    next(err);
  }
});

// حذف كل الحسابات التجريبية دفعة واحدة - محمي بحساب المشرف
app.delete('/api/admin/test-data', requireAdmin, csrfProtection, async (req, res, next) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ error: 'غير مسموح بحذف البيانات في بيئة الإنتاج' });
  }
  try {
    const [result] = await pool.query("DELETE FROM users WHERE phone LIKE '0000%'");
    res.json({ message: `تم حذف ${result.affectedRows} حساب تجريبي` });
  } catch (err) {
    next(err);
  }
});

// Global Error Handler
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'الجلسة غير صالحة أو الرمز الأمني مفقود. يرجى تحديث الصفحة.' });
  }
  securityLog('System_Error', { message: err.message, stack: process.env.NODE_ENV === 'production' ? null : err.stack });
  res.status(500).json({ error: 'حدث خطأ في النظام. يرجى المحاولة لاحقاً.' });
});

initSchema()
  .then(() => {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

    // نبضة قلب كل 10 دقايق - استعلام بسيط جدًا يمنع Aiven من اعتبار الداتابيز خاملة وإيقافها تلقائيًا
    setInterval(async () => {
      try {
        await pool.query('SELECT 1');
        console.log('Heartbeat: DB connection alive');
      } catch (err) {
        console.error('Heartbeat failed:', err.message);
      }
    }, 10 * 60 * 1000);
  })
  .catch(err => {
    console.error('Failed to init DB schema:', err);
    process.exit(1);
  });
