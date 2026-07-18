// server.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const { pool, initSchema } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- تسجيل مستخدم جديد ----------
app.post('/api/register', async (req, res) => {
  try {
    const {
      name, email, password, gender, age,
      governorate, maritalStatus, wantsChildren,
      religion, education, job, bio
    } = req.body;

    // تحقق أساسي من البيانات
    if (!name || !email || !password || !gender || !age || !maritalStatus || !wantsChildren) {
      return res.status(400).json({ error: 'من فضلك املأ كل الحقول المطلوبة' });
    }
    if (age < 18 || age > 90) {
      return res.status(400).json({ error: 'السن غير منطقي' });
    }

    const password_hash = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      `INSERT INTO profiles
       (name, email, password_hash, gender, age, governorate, marital_status, wants_children, religion, education, job, bio)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      [name, email, password_hash, gender, age, governorate || null, maritalStatus, wantsChildren, religion || null, education || null, job || null, bio || null]
    );

    res.status(201).json({ id: result.insertId, message: 'تم التسجيل بنجاح' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'الإيميل ده مسجل قبل كده' });
    }
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

// ---------- عرض البروفايلات مع الفلاتر ----------
app.get('/api/profiles', async (req, res) => {
  try {
    const {
      minAge, maxAge, gender, maritalStatus,
      wantsChildren, governorate, religion, page = 1, limit = 12
    } = req.query;

    const where = ['is_active = 1'];
    const params = [];

    if (minAge) { where.push('age >= ?'); params.push(Number(minAge)); }
    if (maxAge) { where.push('age <= ?'); params.push(Number(maxAge)); }
    if (gender) { where.push('gender = ?'); params.push(gender); }
    if (maritalStatus) { where.push('marital_status = ?'); params.push(maritalStatus); }
    if (wantsChildren) { where.push('wants_children = ?'); params.push(wantsChildren); }
    if (governorate) { where.push('governorate = ?'); params.push(governorate); }
    if (religion) { where.push('religion = ?'); params.push(religion); }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const offset = (Number(page) - 1) * Number(limit);

    const [rows] = await pool.query(
      `SELECT id, name, gender, age, governorate, marital_status, wants_children,
              religion, education, job, bio, photo_url, created_at
       FROM profiles
       ${whereSql}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...params, Number(limit), offset]
    );

    const [countRows] = await pool.query(
      `SELECT COUNT(*) as total FROM profiles ${whereSql}`,
      params
    );

    res.json({
      data: rows,
      total: countRows[0].total,
      page: Number(page),
      limit: Number(limit)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

// ---------- بروفايل واحد بالتفصيل ----------
app.get('/api/profiles/:id', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, name, gender, age, governorate, marital_status, wants_children,
              religion, education, job, bio, photo_url, created_at
       FROM profiles WHERE id = ? AND is_active = 1`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'البروفايل مش موجود' });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حصل خطأ في السيرفر' });
  }
});

initSchema()
  .then(() => {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch(err => {
    console.error('Failed to init DB schema:', err);
    process.exit(1);
  });
