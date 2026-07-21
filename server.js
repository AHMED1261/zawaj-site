// server.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { pool, initSchema } = require('./db');
const { signToken, requireAuth, requireAdmin } = require('./auth');
const { configured: emailConfigured, sendVerificationCode, sendAccountNotification } = require('./email');

const app = express();
const PORT = process.env.PORT || 3000;

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; base-uri 'self'; frame-ancestors 'none'");
  next();
});
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const loginAttempts = new Map();
function limitAttempts(key, maxAttempts = 8, windowMs = 15 * 60 * 1000) {
  return (req, res, next) => {
    const now = Date.now();
    const entry = loginAttempts.get(`${key}:${req.ip}`) || { count: 0, startedAt: now };
    if (now - entry.startedAt > windowMs) { entry.count = 0; entry.startedAt = now; }
    entry.count += 1;
    loginAttempts.set(`${key}:${req.ip}`, entry);
    if (entry.count > maxAttempts) return res.status(429).json({ error: 'محاولات كثيرة، حاول مرة أخرى بعد قليل' });
    next();
  };
}

async function requireApprovedUser(req, res, next) {
  try {
    const [rows] = await pool.query('SELECT id, gender, status FROM users WHERE id = ?', [req.user.id]);
    if (!rows.length || rows[0].status !== 'approved') {
      return res.status(403).json({ error: 'هذه الخدمة متاحة للحسابات المعتمدة فقط' });
    }
    req.account = rows[0];
    next();
  } catch (err) {
    next(err);
  }
}

function validId(value) {
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function normalizePhone(value) {
  return String(value || '').replace(/\s|-/g, '');
}

function cleanText(value) {
  return typeof value === 'string' ? value.trim() : value;
}

function makeCode() {
  return String(crypto.randomInt(100000, 1000000));
}

async function createAndSendCode(phone, email, purpose) {
  const code = makeCode();
  const hash = await bcrypt.hash(code, 10);
  await pool.query('UPDATE verification_codes SET consumed_at = CURRENT_TIMESTAMP WHERE phone = ? AND purpose = ? AND consumed_at IS NULL', [phone, purpose]);
  await pool.query(
    'INSERT INTO verification_codes (phone, purpose, code_hash, expires_at) VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))',
    [phone, purpose, hash]
  );
  const result = await sendVerificationCode(email, code);
  // لا نطبع الرمز ولا نعيده للمتصفح.
  return result;
}

async function consumeCode(phone, purpose, code) {
  const [rows] = await pool.query(
    `SELECT * FROM verification_codes WHERE phone = ? AND purpose = ? AND consumed_at IS NULL
     AND expires_at > NOW() ORDER BY id DESC LIMIT 1`, [phone, purpose]
  );
  if (!rows.length || rows[0].attempts >= 5) return false;
  const record = rows[0];
  const matches = await bcrypt.compare(String(code || ''), record.code_hash);
  if (!matches) {
    await pool.query('UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ?', [record.id]);
    return false;
  }
  await pool.query('UPDATE verification_codes SET consumed_at = CURRENT_TIMESTAMP WHERE id = ?', [record.id]);
  return true;
}

async function notifyUser(userId, message) {
  if (!emailConfigured()) return;
  const [users] = await pool.query('SELECT email FROM users WHERE id = ?', [userId]);
  if (users.length && users[0].email) sendAccountNotification(users[0].email, message).catch(err => console.error('Email notification failed:', err.message));
}

function profileInvalidFields(data) {
  const errors = [];
  const numberRanges = { age:[18,90], weight:[30,250], height:[120,230], siblings_count:[0,30], children_count:[0,20], divorce_count:[1,10], current_wives_count:[1,4], partner_age_min:[18,80], partner_age_max:[18,80] };
  for (const [field, [min,max]] of Object.entries(numberRanges)) {
    if (data[field] !== undefined && data[field] !== null && data[field] !== '' && (!Number.isInteger(Number(data[field])) || Number(data[field]) < min || Number(data[field]) > max)) errors.push(field);
  }
  if (Number(data.partner_age_min) > Number(data.partner_age_max)) errors.push('partner_age_range');
  const enums = { has_beard:['yes','no'], exercises:['yes','no','sometimes'], job_type:['government','private','business_owner'], income_level:['normal','medium','welloff','high'], marital_status:['single','married','divorced','widowed','separated'], has_children:['yes','no'], wants_more_children:['yes','no','maybe'], area_type:['popular','medium','upscale'], housing_type:['owned','fixed_rent','open_rent','family_house'], prays_regularly:['yes','no'], smoker:['yes','no'], watches_series:['yes','no','sometimes'], listens_music:['yes','no','sometimes'], studied_sharia:['yes','no','planning'], form_filled_by:['self','relative'], wants_publish_social:['yes','no'], contacted_before:['yes','no'] };
  for (const [field, allowed] of Object.entries(enums)) if (data[field] && !allowed.includes(data[field])) errors.push(field);
  return [...new Set(errors)];
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
  ,'reference_name','reference_relation','reference_whatsapp'
];

const PUBLIC_PROFILE_FIELDS = [
  'age', 'height', 'skin_color', 'education', 'job', 'job_type', 'income_level',
  'marital_status', 'has_children', 'governorate', 'marital_home_location',
  'religiosity_level', 'smoker', 'prays_regularly', 'exercises', 'housing_type',
  'has_beard', 'wants_polygamy', 'wants_more_children', 'about_me',
  'partner_age_min', 'partner_age_max', 'partner_marital_status_accepted',
  'accepted_governorates', 'hijab_preference', 'partner_education_preference',
  'partner_work_preference'
];

function profileMissingFields(data, gender) {
  const optional = new Set([
    'children_count', 'children_ages', 'custody', 'widow_duration', 'last_divorce_date',
    'divorce_count', 'current_wives_count', 'wants_polygamy',
    'polygamy_with_first_wife_knowledge', 'relative_relation', 'filled_with_knowledge',
    'family_house_living', 'previously_engaged_details', 'accepts_with_children',
    'accepts_children_with_father_custody', 'has_beard', 'hijab_preference', 'notes'
  ]);
  const missing = ANSWER_FIELDS.filter(field => !optional.has(field) && (data[field] === undefined || data[field] === null || data[field] === ''));
  const requireWhen = (condition, fields) => {
    if (condition) fields.forEach(field => {
      if (data[field] === undefined || data[field] === null || data[field] === '') missing.push(field);
    });
  };
  requireWhen(gender === 'male', ['has_beard', 'hijab_preference']);
  requireWhen(data.has_children === 'yes', ['children_count', 'children_ages', 'custody']);
  requireWhen(data.previously_engaged === 'yes', ['previously_engaged_details']);
  requireWhen(data.marital_status === 'widowed', ['widow_duration']);
  requireWhen(data.marital_status === 'divorced', ['last_divorce_date', 'divorce_count']);
  requireWhen(data.marital_status === 'married' && gender === 'male', ['current_wives_count', 'wants_polygamy', 'polygamy_with_first_wife_knowledge']);
  requireWhen(data.housing_type === 'family_house', ['family_house_living']);
  requireWhen(data.form_filled_by === 'relative', ['relative_relation', 'filled_with_knowledge']);
  requireWhen(true, ['reference_name', 'reference_relation', 'reference_whatsapp']);
  const acceptsPreviouslyMarried = String(data.partner_marital_status_accepted || '').includes('مطلق') || String(data.partner_marital_status_accepted || '').includes('أرمل');
  requireWhen(acceptsPreviouslyMarried, ['accepts_with_children', 'accepts_children_with_father_custody']);
  return [...new Set(missing)];
}

// ---------- تحقق البريد الإلكتروني، تسجيل، واسترجاع الحساب ----------
app.post('/api/auth/request-code', limitAttempts('email-code', 3, 15 * 60 * 1000), async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const email = String(req.body.email || '').trim().toLowerCase();
    const purpose = req.body.purpose;
    if (!/^01[0125]\d{8}$/.test(phone) || !/^\S+@\S+\.\S+$/.test(email) || !['register', 'reset_password'].includes(purpose)) {
      return res.status(400).json({ error: 'أدخل رقم هاتف مصري صحيح واختر الغرض بصورة صحيحة' });
    }
    if (!emailConfigured()) return res.status(503).json({ error: 'خدمة البريد الإلكتروني غير مُعدّة بعد. راجع إعدادات الإرسال.' });
    const [users] = await pool.query('SELECT id, email FROM users WHERE phone = ?', [phone]);
    if (purpose === 'register' && users.length) return res.status(409).json({ error: 'هذا الرقم مسجل بالفعل، استخدم استرجاع الحساب.' });
    if (purpose === 'reset_password' && !users.length) return res.status(404).json({ error: 'لا يوجد حساب بهذا الرقم.' });
    if (purpose === 'reset_password' && users[0].email !== email) return res.status(400).json({ error: 'البريد الإلكتروني لا يطابق الحساب المسجل.' });
    await createAndSendCode(phone, email, purpose);
    res.json({ message: 'تم إرسال رمز التحقق إلى بريدك الإلكتروني. الرمز صالح لمدة 10 دقائق.' });
  } catch (err) {
    console.error('Email verification error:', err.message);
    res.status(503).json({ error: 'تعذر إرسال رمز البريد الإلكتروني الآن. حاول لاحقاً.' });
  }
});

// ---------- تسجيل حساب جديد (بعد إثبات ملكية البريد) ----------
app.post('/api/register', limitAttempts('register', 5), async (req, res) => {
  try {
    const { password, gender, code, termsAccepted } = req.body;
    const phone = normalizePhone(req.body.phone);
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!phone || !email || !password || !gender) {
      return res.status(400).json({ error: 'من فضلك املأ رقم الهاتف وكلمة المرور والنوع' });
    }
    if (!/^01[0125]\d{8}$/.test(phone)) {
      return res.status(400).json({ error: 'اكتب رقم هاتف مصري صحيح من 11 رقماً' });
    }
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'اكتب بريدًا إلكترونيًا صحيحًا.' });
    if (password.length < 8) {
      return res.status(400).json({ error: 'كلمة المرور لازم تكون 8 أحرف على الأقل' });
    }
    if (!['male', 'female'].includes(gender)) {
      return res.status(400).json({ error: 'اختر نوع الحساب بصورة صحيحة' });
    }
    if (termsAccepted !== 'yes') return res.status(400).json({ error: 'يجب الموافقة على سياسة الخصوصية وشروط الاستخدام.' });
    if (!(await consumeCode(phone, 'register', code))) {
      return res.status(400).json({ error: 'رمز التحقق غير صحيح أو انتهت صلاحيته. اطلب رمزاً جديداً.' });
    }
    const password_hash = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (phone, email, password_hash, gender, terms_accepted_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)',
      [phone, email, password_hash, gender]
    );
    const token = signToken({ id: result.insertId, phone, role: 'user' });
    res.status(201).json({ token, message: 'تم إنشاء الحساب، كمّل استمارة البيانات دلوقتي' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'رقم الهاتف ده مسجل قبل كده' });
    }
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

app.post('/api/auth/reset-password', limitAttempts('reset-password', 5), async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const { code, password } = req.body;
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!/^01[0125]\d{8}$/.test(phone) || !/^\S+@\S+\.\S+$/.test(email) || typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'أدخل رقم هاتف صحيح وكلمة مرور من 8 أحرف على الأقل.' });
    }
    if (!(await consumeCode(phone, 'reset_password', code))) {
      return res.status(400).json({ error: 'رمز التحقق غير صحيح أو انتهت صلاحيته.' });
    }
    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.query('UPDATE users SET password_hash = ? WHERE phone = ? AND email = ?', [hash, phone, email]);
    if (!result.affectedRows) return res.status(404).json({ error: 'الحساب غير موجود.' });
    res.json({ message: 'تم تغيير كلمة المرور. يمكنك تسجيل الدخول الآن.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'تعذر تغيير كلمة المرور.' });
  }
});

// ---------- تسجيل الدخول ----------
app.post('/api/login', limitAttempts('user-login'), async (req, res) => {
  try {
    const { password } = req.body;
    const phone = normalizePhone(req.body.phone);
    const [rows] = await pool.query('SELECT * FROM users WHERE phone = ?', [phone]);
    if (!rows.length) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });

    const token = signToken({ id: user.id, phone: user.phone, role: 'user' });
    res.json({ token, status: user.status, gender: user.gender });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

// ---------- تعبئة/تحديث استمارة البيانات (كل الحقول إلزامية) ----------
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT u.id, u.gender, u.status, u.admin_notes, u.created_at, u.updated_at,
              CASE WHEN p.user_id IS NULL THEN 0 ELSE 1 END AS has_profile
       FROM users u LEFT JOIN profile_answers p ON p.user_id = u.id WHERE u.id = ?`,
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'الحساب مش موجود' });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

app.get('/api/profile/draft', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM profile_answers WHERE user_id = ?', [req.user.id]);
    res.json(rows[0] || {});
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

app.post('/api/profile/draft', requireAuth, async (req, res) => {
  try {
    const [userRows] = await pool.query('SELECT status, gender FROM users WHERE id = ?', [req.user.id]);
    if (!userRows.length) return res.status(404).json({ error: 'الحساب مش موجود' });
    if (userRows[0].status !== 'incomplete') return res.status(403).json({ error: 'لا يمكن تعديل المسودة بعد إرسالها للمراجعة' });
    const values = ANSWER_FIELDS.map(field => {
      const value = cleanText(req.body[field]);
      return value === '' || value === undefined ? null : value;
    });
    const placeholders = ANSWER_FIELDS.map(() => '?').join(',');
    const updateClause = ANSWER_FIELDS.map(field => `${field}=VALUES(${field})`).join(',');
    await pool.query(
      `INSERT INTO profile_answers (user_id, ${ANSWER_FIELDS.join(',')}) VALUES (?, ${placeholders})
       ON DUPLICATE KEY UPDATE ${updateClause}`,
      [req.user.id, ...values]
    );
    res.json({ message: 'تم حفظ المسودة، تقدر تكملها في أي وقت' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'تعذر حفظ المسودة' });
  }
});

app.post('/api/profile/submit', requireAuth, async (req, res) => {
  try {
    const data = req.body;

    // بعد أول إرسال، المستخدم نفسه مايقدرش يعدّل الاستمارة تاني - التعديل بقى صلاحية المشرف بس
    const [userRows] = await pool.query('SELECT status FROM users WHERE id = ?', [req.user.id]);
    if (!userRows.length) return res.status(404).json({ error: 'الحساب مش موجود' });
    if (userRows[0].status !== 'incomplete') {
      return res.status(403).json({ error: 'تم إرسال بياناتك من قبل، مش ممكن تعديلها بنفسك. لو محتاج تصحيح أي بيانات، تواصل مع الإدارة.' });
    }

    // تحقق: كل الحقول إلزامية
    const missing = profileMissingFields(data, userRows[0].gender);
    const invalid = profileInvalidFields(data);
    if (invalid.length) return res.status(400).json({ error: 'بعض البيانات غير صحيحة', fields: invalid });
    // بعض الحقول شرطية (مش لازم تتملى لو السؤال مبيتسألش أصلاً) - بنسمح فراغها لو منطقيًا مش مطلوبة
    const conditionallyOptional = new Set([
      'children_count','children_ages','custody','widow_duration','last_divorce_date','divorce_count',
      'current_wives_count','wants_polygamy','polygamy_with_first_wife_knowledge','relative_relation',
      'family_house_living','filled_with_knowledge','has_beard','hijab_preference',
      'previously_engaged_details','accepts_with_children','accepts_children_with_father_custody','notes'
    ]);
    const trulyMissing = missing;
    if (trulyMissing.length) {
      return res.status(400).json({ error: 'في حقول إلزامية ناقصة', fields: trulyMissing });
    }
    if (Number(data.partner_age_min) > Number(data.partner_age_max)) {
      return res.status(400).json({ error: 'أقل سن للشريك يجب أن يكون أصغر من أو يساوي أكبر سن' });
    }

    const columns = ANSWER_FIELDS;
    const values = columns.map(f => {
      const value = cleanText(data[f]);
      return value === '' || value === undefined ? null : value;
    });
    const placeholders = columns.map(() => '?').join(',');
    const updateClause = columns.map(c => `${c}=VALUES(${c})`).join(',');

    await pool.query(
      `INSERT INTO profile_answers (user_id, ${columns.join(',')})
       VALUES (?, ${placeholders})
       ON DUPLICATE KEY UPDATE ${updateClause}`,
      [req.user.id, ...values]
    );

    await pool.query('UPDATE users SET status = ? WHERE id = ?', ['pending', req.user.id]);

    res.json({ message: 'تم إرسال بياناتك للمراجعة، هيتم إشعارك بعد اعتماد الحساب' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

// ---------- عرض البروفايلات المعتمدة فقط + فلاتر (كتابة واختيار) ----------
app.get('/api/profiles', requireAuth, requireApprovedUser, async (req, res) => {
  try {
    await ensureRecentColumns();

    const {
      gender, minAge, maxAge, governorate, maritalHomeLocation, maritalStatus, wantsChildren,
      education, job, religiosityLevel, smoker, jobType, incomeLevel,
      praysRegularly, exercises, housingType, areaType, hasBeard,
      wantsPolygamy, minHeight, maxHeight,
      minWeight, maxWeight, page = 1, limit = 12
    } = req.query;

    // بيحول القيمة لمصفوفة سواء جت قيمة واحدة أو أكتر (اختيار متعدد)
    const toArray = v => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

    const where = ["u.status = 'approved'", 'u.id <> ?'];
    const params = [req.user.id];

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

    if (wantsChildren) { where.push('p.wants_more_children = ?'); params.push(wantsChildren); }
    if (job) { where.push('p.job LIKE ?'); params.push(`%${job}%`); }
    if (religiosityLevel) { where.push('p.religiosity_level LIKE ?'); params.push(`%${religiosityLevel}%`); }
    if (smoker) { where.push('p.smoker = ?'); params.push(smoker); }
    if (jobType) { where.push('p.job_type = ?'); params.push(jobType); }
    if (incomeLevel) { where.push('p.income_level = ?'); params.push(incomeLevel); }
    if (praysRegularly) { where.push('p.prays_regularly = ?'); params.push(praysRegularly); }
    if (exercises) { where.push('p.exercises = ?'); params.push(exercises); }
    if (housingType) { where.push('p.housing_type = ?'); params.push(housingType); }
    if (areaType) { where.push('p.area_type = ?'); params.push(areaType); }
    // فلاتر خاصة بالعريس بس - لو اتبعتت لفلترة عروسة هتطلع فاضية طبيعي لأن الحقل مش موجود لها
    if (hasBeard) { where.push('p.has_beard = ?'); params.push(hasBeard); }
    if (wantsPolygamy) { where.push('p.wants_polygamy = ?'); params.push(wantsPolygamy); }

    const whereSql = `WHERE ${where.join(' AND ')}`;
    const safeLimit = Math.min(Math.max(Number(limit) || 12, 1), 24);
    const safePage = Math.max(Number(page) || 1, 1);
    const offset = (safePage - 1) * safeLimit;

    const [rows] = await pool.query(
      `SELECT u.id, u.gender, p.age, p.height, p.skin_color, p.education, p.job,
              p.job_type, p.income_level, p.marital_status, p.governorate, p.marital_home_location,
              p.religiosity_level, p.smoker, p.prays_regularly, p.exercises, p.housing_type,
              p.has_beard, p.wants_polygamy, p.about_me, p.wants_more_children
       FROM users u JOIN profile_answers p ON p.user_id = u.id
       ${whereSql}
       ORDER BY u.updated_at DESC
       LIMIT ? OFFSET ?`,
      [...params, safeLimit, offset]
    );

    const [countRows] = await pool.query(
      `SELECT COUNT(*) as total FROM users u JOIN profile_answers p ON p.user_id = u.id ${whereSql}`,
      params
    );

    res.json({ data: rows, total: countRows[0].total, page: safePage, limit: safeLimit });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

app.get('/api/profiles/:id', requireAuth, requireApprovedUser, async (req, res) => {
  try {
    await ensureRecentColumns();
    const profileId = validId(req.params.id);
    if (!profileId) return res.status(400).json({ error: 'رقم البروفايل غير صحيح' });

    const [rows] = await pool.query(
      `SELECT u.id, u.gender, ${PUBLIC_PROFILE_FIELDS.map(field => `p.${field}`).join(', ')}
       FROM users u JOIN profile_answers p ON p.user_id = u.id
       WHERE u.id = ? AND u.id <> ? AND u.status = 'approved'`,
      [profileId, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'البروفايل مش موجود' });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

// ============ طلبات التعارف والمراسلات عبر الإدارة ============
app.post('/api/requests/:recipientId', requireAuth, requireApprovedUser, async (req, res) => {
  try {
    const recipientId = validId(req.params.recipientId);
    if (!recipientId || recipientId === req.user.id) return res.status(400).json({ error: 'لا يمكن إرسال طلب لهذا البروفايل' });
    const [recipients] = await pool.query(
      `SELECT u.id FROM users u JOIN profile_answers p ON p.user_id = u.id
       WHERE u.id = ? AND u.status = 'approved'`, [recipientId]
    );
    if (!recipients.length) return res.status(404).json({ error: 'هذا البروفايل غير متاح' });

    const [existing] = await pool.query(
      `SELECT * FROM interest_requests
       WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
       ORDER BY id DESC LIMIT 1`,
      [req.user.id, recipientId, recipientId, req.user.id]
    );
    if (existing.length && ['pending', 'matched'].includes(existing[0].status)) {
      return res.status(409).json({ error: 'يوجد طلب تعارف قائم بالفعل بينكما' });
    }
    if (existing.length && existing[0].sender_id === req.user.id) {
      await pool.query(
        `UPDATE interest_requests SET status = 'pending', responded_at = NULL
         WHERE id = ?`, [existing[0].id]
      );
    } else {
      await pool.query('INSERT INTO interest_requests (sender_id, recipient_id) VALUES (?, ?)', [req.user.id, recipientId]);
    }
    notifyUser(recipientId, 'لديك طلب تعارف جديد. افتح حسابك لمراجعته.');
    res.status(201).json({ message: 'تم إرسال طلب التعارف، وسيظهر للطرف الآخر للموافقة أو الرفض' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'تعذر إرسال الطلب' });
  }
});

app.get('/api/requests', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT r.id, r.sender_id, r.recipient_id, r.status, r.created_at, r.updated_at, r.responded_at,
              CASE WHEN r.sender_id = ? THEN 'sent' ELSE 'received' END AS direction,
              u.id AS profile_id, u.gender, p.age, p.governorate, p.education, p.job, p.marital_status, p.about_me
       FROM interest_requests r
       JOIN users u ON u.id = CASE WHEN r.sender_id = ? THEN r.recipient_id ELSE r.sender_id END
       JOIN profile_answers p ON p.user_id = u.id
       WHERE r.sender_id = ? OR r.recipient_id = ?
       ORDER BY r.updated_at DESC`,
      [req.user.id, req.user.id, req.user.id, req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'تعذر تحميل الطلبات' });
  }
});

app.post('/api/requests/:id/accept', requireAuth, requireApprovedUser, async (req, res) => {
  const requestId = validId(req.params.id);
  if (!requestId) return res.status(400).json({ error: 'رقم الطلب غير صحيح' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [requests] = await conn.query(
      `SELECT * FROM interest_requests WHERE id = ? AND recipient_id = ? AND status = 'pending' FOR UPDATE`,
      [requestId, req.user.id]
    );
    if (!requests.length) {
      await conn.rollback();
      return res.status(409).json({ error: 'هذا الطلب غير متاح للموافقة' });
    }
    const request = requests[0];
    await conn.query(`UPDATE interest_requests SET status = 'matched', responded_at = CURRENT_TIMESTAMP WHERE id = ?`, [requestId]);
    await conn.query(
      'INSERT INTO conversations (request_id, user_one_id, user_two_id) VALUES (?, ?, ?)',
      [requestId, request.sender_id, request.recipient_id]
    );
    await conn.commit();
    notifyUser(request.sender_id, 'تمت الموافقة على طلب التعارف. ستتابع الإدارة ترتيب المراسلات.');
    res.json({ message: 'تمت الموافقة. أصبح الطلب لدى الإدارة لترتيب ونقل المراسلات بينكما.' });
  } catch (err) {
    await conn.rollback();
    console.error(err);
    res.status(500).json({ error: 'تعذر اعتماد الموافقة' });
  } finally {
    conn.release();
  }
});

app.post('/api/requests/:id/decline', requireAuth, requireApprovedUser, async (req, res) => {
  try {
    const requestId = validId(req.params.id);
    const [result] = await pool.query(
      `UPDATE interest_requests SET status = 'declined', responded_at = CURRENT_TIMESTAMP
       WHERE id = ? AND recipient_id = ? AND status = 'pending'`, [requestId, req.user.id]
    );
    if (!result.affectedRows) return res.status(409).json({ error: 'هذا الطلب غير متاح للرفض' });
    res.json({ message: 'تم رفض الطلب' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'تعذر رفض الطلب' });
  }
});

app.post('/api/requests/:id/withdraw', requireAuth, async (req, res) => {
  try {
    const requestId = validId(req.params.id);
    const [result] = await pool.query(
      `UPDATE interest_requests SET status = 'withdrawn'
       WHERE id = ? AND sender_id = ? AND status = 'pending'`, [requestId, req.user.id]
    );
    if (!result.affectedRows) return res.status(409).json({ error: 'هذا الطلب غير متاح للإلغاء' });
    res.json({ message: 'تم إلغاء الطلب' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'تعذر إلغاء الطلب' });
  }
});

app.get('/api/conversations', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT c.id, c.status, c.created_at, c.updated_at,
              CASE WHEN c.user_one_id = ? THEN c.user_two_id ELSE c.user_one_id END AS other_user_id,
              u.gender, p.age, p.governorate, p.education, p.job, p.marital_status
       FROM conversations c
       JOIN users u ON u.id = CASE WHEN c.user_one_id = ? THEN c.user_two_id ELSE c.user_one_id END
       JOIN profile_answers p ON p.user_id = u.id
       WHERE c.user_one_id = ? OR c.user_two_id = ? ORDER BY c.updated_at DESC`,
      [req.user.id, req.user.id, req.user.id, req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'تعذر تحميل المراسلات' });
  }
});

async function userConversation(conversationId, userId) {
  const [rows] = await pool.query(
    `SELECT * FROM conversations WHERE id = ? AND (user_one_id = ? OR user_two_id = ?)`,
    [conversationId, userId, userId]
  );
  return rows[0];
}

app.get('/api/conversations/:id/messages', requireAuth, async (req, res) => {
  try {
    const conversationId = validId(req.params.id);
    if (!conversationId || !(await userConversation(conversationId, req.user.id))) return res.status(404).json({ error: 'المراسلة غير متاحة' });
    const [rows] = await pool.query(
      `SELECT id, sender_role, sender_user_id, recipient_user_id, body, created_at
       FROM conversation_messages
       WHERE conversation_id = ? AND (sender_user_id = ? OR recipient_user_id = ?)
       ORDER BY created_at ASC`, [conversationId, req.user.id, req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'تعذر تحميل الرسائل' });
  }
});

app.post('/api/conversations/:id/messages', requireAuth, requireApprovedUser, async (req, res) => {
  try {
    const conversationId = validId(req.params.id);
    const body = cleanText(req.body.body);
    if (!conversationId || !body || body.length > 1000) return res.status(400).json({ error: 'اكتب رسالة لا تزيد عن 1000 حرف' });
    const conversation = await userConversation(conversationId, req.user.id);
    if (!conversation || conversation.status !== 'active') return res.status(404).json({ error: 'المراسلة غير متاحة' });
    await pool.query(
      `INSERT INTO conversation_messages (conversation_id, sender_role, sender_user_id, body)
      VALUES (?, 'user', ?, ?)`, [conversationId, req.user.id, body]
    );
    res.status(201).json({ message: 'تم إرسال رسالتك للإدارة لنقلها للطرف الآخر' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'تعذر إرسال الرسالة' });
  }
});

// ============ لوحة المشرف ============

app.post('/api/admin/login', limitAttempts('admin-login', 5), async (req, res) => {
  try {
    const { username, password } = req.body;
    const [rows] = await pool.query('SELECT * FROM admins WHERE username = ?', [username]);
    if (!rows.length) return res.status(401).json({ error: 'بيانات دخول غير صحيحة' });
    const match = await bcrypt.compare(password, rows[0].password_hash);
    if (!match) return res.status(401).json({ error: 'بيانات دخول غير صحيحة' });
    const token = signToken({ id: rows[0].id, username, role: 'admin' }, '2d');
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const status = req.query.status || 'pending';
    const [rows] = await pool.query(
      `SELECT u.id, u.phone, u.gender, u.status, u.created_at, p.*
       FROM users u LEFT JOIN profile_answers p ON p.user_id = u.id
       WHERE u.status = ? ORDER BY u.created_at ASC`,
      [status]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

app.get('/api/admin/conversations', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT c.id, c.status, c.created_at, c.updated_at, r.id AS request_id,
              u1.id AS user_one_id, u1.gender AS user_one_gender, p1.age AS user_one_age, p1.governorate AS user_one_governorate, p1.job AS user_one_job,
              u2.id AS user_two_id, u2.gender AS user_two_gender, p2.age AS user_two_age, p2.governorate AS user_two_governorate, p2.job AS user_two_job,
              (SELECT COUNT(*) FROM conversation_messages m WHERE m.conversation_id = c.id AND m.sender_role = 'user') AS user_messages_count
       FROM conversations c
       JOIN interest_requests r ON r.id = c.request_id
       JOIN users u1 ON u1.id = c.user_one_id JOIN profile_answers p1 ON p1.user_id = u1.id
       JOIN users u2 ON u2.id = c.user_two_id JOIN profile_answers p2 ON p2.user_id = u2.id
       ORDER BY c.updated_at DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'تعذر تحميل التوافقات' });
  }
});

app.get('/api/admin/conversations/:id/messages', requireAdmin, async (req, res) => {
  try {
    const conversationId = validId(req.params.id);
    if (!conversationId) return res.status(400).json({ error: 'رقم المراسلة غير صحيح' });
    const [rows] = await pool.query(
      `SELECT id, sender_role, sender_user_id, recipient_user_id, body, created_at
       FROM conversation_messages WHERE conversation_id = ? ORDER BY created_at ASC`, [conversationId]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'تعذر تحميل الرسائل' });
  }
});

app.post('/api/admin/conversations/:id/messages', requireAdmin, async (req, res) => {
  try {
    const conversationId = validId(req.params.id);
    const recipientId = validId(req.body.recipientId);
    const body = cleanText(req.body.body);
    if (!conversationId || !recipientId || !body || body.length > 1000) {
      return res.status(400).json({ error: 'بيانات الرسالة غير صحيحة' });
    }
    const [conversations] = await pool.query('SELECT * FROM conversations WHERE id = ? AND status = \'active\'', [conversationId]);
    const conversation = conversations[0];
    if (!conversation || ![conversation.user_one_id, conversation.user_two_id].includes(recipientId)) {
      return res.status(404).json({ error: 'المراسلة أو المستلم غير متاح' });
    }
    await pool.query(
      `INSERT INTO conversation_messages (conversation_id, sender_role, recipient_user_id, body)
       VALUES (?, 'admin', ?, ?)`, [conversationId, recipientId, body]
    );
    notifyUser(recipientId, 'لديك رسالة جديدة من الإدارة. افتح حسابك لقراءتها.');
    res.status(201).json({ message: 'تم إرسال الرسالة للطرف المختار' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'تعذر إرسال الرسالة' });
  }
});

app.post('/api/admin/conversations/:id/close', requireAdmin, async (req, res) => {
  try {
    const conversationId = validId(req.params.id);
    const [result] = await pool.query("UPDATE conversations SET status = 'closed' WHERE id = ?", [conversationId]);
    if (!result.affectedRows) return res.status(404).json({ error: 'المراسلة غير موجودة' });
    res.json({ message: 'تم إغلاق المراسلة' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'تعذر إغلاق المراسلة' });
  }
});

app.post('/api/admin/users/:id/approve', requireAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.id);
    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({ error: 'رقم الحساب غير صحيح' });
    }

    // لا نعتمد إلا حساباً أرسل الاستمارة بالفعل وما زال في انتظار المراجعة.
    const [result] = await pool.query(
      `UPDATE users u
       INNER JOIN profile_answers p ON p.user_id = u.id
       SET u.status = 'approved'
       WHERE u.id = ? AND u.status = 'pending'`,
      [userId]
    );
    if (!result.affectedRows) {
      return res.status(409).json({ error: 'لا يمكن اعتماد هذا الحساب. تأكد أنه أرسل الاستمارة وما زال قيد المراجعة.' });
    }
    notifyUser(userId, 'تم اعتماد حسابك. يمكنك الآن تصفح الملفات المعتمدة.');
    res.json({ message: 'تم اعتماد الحساب' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

app.post('/api/admin/users/:id/reject', requireAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    await pool.query("UPDATE users SET status = 'rejected', admin_notes = ? WHERE id = ?", [reason || null, req.params.id]);
    notifyUser(req.params.id, `تمت مراجعة حسابك. ${reason ? `ملاحظة الإدارة: ${reason}` : 'يرجى مراجعة لوحة حسابك.'}`);
    res.json({ message: 'تم رفض الحساب' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

app.post('/api/admin/users/:id/suspend', requireAdmin, async (req, res) => {
  try {
    await pool.query("UPDATE users SET status = 'suspended' WHERE id = ?", [req.params.id]);
    res.json({ message: 'تم إيقاف الحساب' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

// تعديل بيانات الاستمارة - المشرف بس يقدر يعمل كده
app.patch('/api/admin/users/:id/profile', requireAdmin, async (req, res) => {
  try {
    const updates = req.body;
    const allowedFields = ANSWER_FIELDS.filter(f => updates[f] !== undefined);
    if (!allowedFields.length) return res.status(400).json({ error: 'مفيش بيانات للتعديل' });

    const setClause = allowedFields.map(f => `${f} = ?`).join(', ');
    const values = allowedFields.map(f => (updates[f] === '' ? null : updates[f]));

    await pool.query(
      `UPDATE profile_answers SET ${setClause} WHERE user_id = ?`,
      [...values, req.params.id]
    );

    res.json({ message: 'تم تعديل البيانات بنجاح' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

// حذف حساب نهائيًا - المشرف بس
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
    res.json({ message: 'تم حذف الحساب نهائيًا' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

// توليد بيانات تجريبية (200 بروفايل معتمد) لاختبار الفلاتر - محمي بحساب المشرف
// ملحوظة أداء: بيستخدم إدخال مجمّع (Bulk Insert) بدل استعلام منفصل لكل بروفايل
// عشان يتجنب أي timeout من السيرفر مع أعداد كبيرة
app.post('/api/admin/seed-test-data', requireAdmin, async (req, res) => {
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
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في توليد البيانات التجريبية', detail: err.message });
  }
});

// حذف كل الحسابات التجريبية دفعة واحدة - محمي بحساب المشرف
app.delete('/api/admin/test-data', requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.query("DELETE FROM users WHERE phone LIKE '0000%'");
    res.json({ message: `تم حذف ${result.affectedRows} حساب تجريبي` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في حذف البيانات التجريبية', detail: err.message });
  }
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
