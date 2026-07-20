// server.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const { pool, initSchema } = require('./db');
const { signToken, requireAuth, requireAdmin } = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// كل الأعمدة القابلة للتعبئة في الاستمارة (بيوصل من الفرونت اند)
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
  'accepts_other_governorate','accepted_governorates','hijab_preference',
  'partner_education_preference','partner_work_preference',
  'wants_publish_social','contacted_before','notes'
];

// ---------- تسجيل حساب جديد (هاتف + باسورد) ----------
app.post('/api/register', async (req, res) => {
  try {
    const { phone, password, gender } = req.body;
    if (!phone || !password || !gender) {
      return res.status(400).json({ error: 'من فضلك املأ رقم الهاتف وكلمة المرور والنوع' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'كلمة المرور لازم تكون 6 أحرف على الأقل' });
    }
    const password_hash = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (phone, password_hash, gender) VALUES (?, ?, ?)',
      [phone, password_hash, gender]
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

// ---------- تسجيل الدخول ----------
app.post('/api/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
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
    const missing = ANSWER_FIELDS.filter(f => data[f] === undefined || data[f] === null || data[f] === '');
    // بعض الحقول شرطية (مش لازم تتملى لو السؤال مبيتسألش أصلاً) - بنسمح فراغها لو منطقيًا مش مطلوبة
    const conditionallyOptional = new Set([
      'children_count','children_ages','custody','widow_duration','last_divorce_date','divorce_count',
      'current_wives_count','wants_polygamy','polygamy_with_first_wife_knowledge','relative_relation',
      'family_house_living','filled_with_knowledge','accepted_governorates','has_beard','hijab_preference',
      'previously_engaged_details','accepts_with_children','accepts_children_with_father_custody'
    ]);
    const trulyMissing = missing.filter(f => !conditionallyOptional.has(f));
    if (trulyMissing.length) {
      return res.status(400).json({ error: 'في حقول إلزامية ناقصة', fields: trulyMissing });
    }

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

    res.json({ message: 'تم إرسال بياناتك للمراجعة، هيتم إشعارك بعد اعتماد الحساب' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

// ---------- عرض البروفايلات المعتمدة فقط + فلاتر (كتابة واختيار) ----------
app.get('/api/profiles', async (req, res) => {
  try {
    const {
      gender, minAge, maxAge, governorate, maritalHomeLocation, maritalStatus, wantsChildren,
      education, job, religiosityLevel, smoker, jobType, incomeLevel,
      praysRegularly, exercises, housingType, areaType, hasBeard,
      wantsPolygamy, acceptsOtherGovernorate, minHeight, maxHeight,
      minWeight, maxWeight, page = 1, limit = 12
    } = req.query;

    // بيحول القيمة لمصفوفة سواء جت قيمة واحدة أو أكتر (اختيار متعدد)
    const toArray = v => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

    const where = ['u.status = "approved"'];
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
    if (acceptsOtherGovernorate) { where.push('p.accepts_other_governorate = ?'); params.push(acceptsOtherGovernorate); }
    // فلاتر خاصة بالعريس بس - لو اتبعتت لفلترة عروسة هتطلع فاضية طبيعي لأن الحقل مش موجود لها
    if (hasBeard) { where.push('p.has_beard = ?'); params.push(hasBeard); }
    if (wantsPolygamy) { where.push('p.wants_polygamy = ?'); params.push(wantsPolygamy); }

    const whereSql = `WHERE ${where.join(' AND ')}`;
    const offset = (Number(page) - 1) * Number(limit);

    const [rows] = await pool.query(
      `SELECT u.id, u.gender, p.age, p.weight, p.height, p.skin_color, p.education, p.job,
              p.job_type, p.income_level, p.marital_status, p.governorate, p.marital_home_location, p.marital_home_area,
              p.religiosity_level, p.smoker, p.prays_regularly, p.exercises, p.housing_type, p.area_type,
              p.has_beard, p.wants_polygamy, p.about_me, p.wants_more_children
       FROM users u JOIN profile_answers p ON p.user_id = u.id
       ${whereSql}
       ORDER BY u.updated_at DESC
       LIMIT ? OFFSET ?`,
      [...params, Number(limit), offset]
    );

    const [countRows] = await pool.query(
      `SELECT COUNT(*) as total FROM users u JOIN profile_answers p ON p.user_id = u.id ${whereSql}`,
      params
    );

    res.json({ data: rows, total: countRows[0].total, page: Number(page), limit: Number(limit) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

app.get('/api/profiles/:id', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT u.id, u.gender, p.* FROM users u JOIN profile_answers p ON p.user_id = u.id
       WHERE u.id = ? AND u.status = "approved"`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'البروفايل مش موجود' });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

// ============ لوحة المشرف ============

app.post('/api/admin/login', async (req, res) => {
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

app.post('/api/admin/users/:id/approve', requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE users SET status = "approved" WHERE id = ?', [req.params.id]);
    res.json({ message: 'تم اعتماد الحساب' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

app.post('/api/admin/users/:id/reject', requireAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    await pool.query('UPDATE users SET status = "rejected", admin_notes = ? WHERE id = ?', [reason || null, req.params.id]);
    res.json({ message: 'تم رفض الحساب' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

app.post('/api/admin/users/:id/suspend', requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE users SET status = "suspended" WHERE id = ?', [req.params.id]);
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
    // تصحيح تلقائي: نتأكد إن العمود موجود لحظة الاستخدام، مش هنعتمد بس على مايجرشن بدء التشغيل
    try { await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_test_data TINYINT(1) DEFAULT 0`); } catch (e) { console.log('ensure is_test_data:', e.message); }
    try { await pool.query(`ALTER TABLE profile_answers ADD COLUMN IF NOT EXISTS marital_home_area VARCHAR(150)`); } catch (e) { console.log('ensure marital_home_area:', e.message); }
    try { await pool.query(`ALTER TABLE profile_answers ADD COLUMN IF NOT EXISTS previously_engaged_details TEXT`); } catch (e) { console.log('ensure previously_engaged_details:', e.message); }

    const count = Math.min(Number(req.body.count) || 200, 500);
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
      const phone = `01${randInt(0,2)}${String(randInt(10000000, 99999999)).padStart(8,'0')}${i}`.slice(0, 20);
      userRows.push([phone, sharedPasswordHash, gender, 'approved', 1]);

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
        accepts_other_governorate: rand(yesNo), accepted_governorates: rand(governorates),
        hijab_preference: rand(['hijab','niqab','either']),
        partner_education_preference: rand(['high','medium','either']),
        partner_work_preference: rand(['works','not_working','either']),
        wants_publish_social: rand(yesNo), contacted_before: 'no', notes: ''
      });
    }

    // إدخال كل المستخدمين التجريبيين في استعلام واحد
    const [userResult] = await pool.query(
      'INSERT INTO users (phone, password_hash, gender, status, is_test_data) VALUES ?',
      [userRows]
    );
    const firstId = userResult.insertId; // أول id في الدفعة - باقي المعرفات متتالية بعده

    const cols = ANSWER_FIELDS;
    const profileRows = profileDataList.map((vals, idx) => [
      firstId + idx,
      ...cols.map(c => (vals[c] !== undefined ? vals[c] : null))
    ]);

    // إدخال كل الاستمارات في استعلام واحد كمان
    await pool.query(
      `INSERT INTO profile_answers (user_id, ${cols.join(',')}) VALUES ?`,
      [profileRows]
    );

    res.json({ message: `تم توليد ${count} بروفايل تجريبي معتمد` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في توليد البيانات التجريبية', detail: err.message });
  }
});

// حذف كل الحسابات التجريبية دفعة واحدة - محمي بحساب المشرف
app.delete('/api/admin/test-data', requireAdmin, async (req, res) => {
  try {
    try { await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_test_data TINYINT(1) DEFAULT 0`); } catch (e) { /* ignore */ }
    const [result] = await pool.query('DELETE FROM users WHERE is_test_data = 1');
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
