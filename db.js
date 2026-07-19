// db.js - MySQL connection pool + schema
require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined
});

async function initSchema() {
  const conn = await pool.getConnection();
  try {
    // المستخدمين - تسجيل الدخول برقم الهاتف وباسورد
    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        phone VARCHAR(20) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        gender ENUM('male','female') NOT NULL,
        national_id_partial VARCHAR(10),
        national_id_hash VARCHAR(255) DEFAULT NULL,
        status ENUM('incomplete','pending','approved','rejected','suspended') DEFAULT 'incomplete',
        admin_notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // استمارة البيانات الكاملة (57 سؤال) - مرتبطة بمستخدم واحد
    await conn.query(`
      CREATE TABLE IF NOT EXISTS profile_answers (
        user_id INT PRIMARY KEY,

        age INT,
        weight INT,
        height INT,
        skin_color VARCHAR(50),
        has_beard ENUM('yes','no'),
        exercises ENUM('yes','no','sometimes'),
        health_issues TEXT,

        education VARCHAR(150),
        job VARCHAR(150),
        job_type ENUM('government','private','business_owner'),
        income_level ENUM('normal','medium','welloff','high'),

        marital_status ENUM('single','married','divorced','widowed','separated'),
        has_children ENUM('yes','no'),
        children_count INT,
        children_ages VARCHAR(255),
        custody VARCHAR(100),
        previously_engaged ENUM('yes','no'),
        previously_engaged_details TEXT,
        widow_duration VARCHAR(100),
        last_divorce_date DATE,
        divorce_count INT,
        current_wives_count INT,
        wants_polygamy ENUM('yes','no'),
        polygamy_with_first_wife_knowledge ENUM('yes','no'),
        wants_more_children ENUM('yes','no','maybe'),

        father_job VARCHAR(150),
        mother_job VARCHAR(150),
        siblings_count INT,
        siblings_education VARCHAR(255),

        governorate VARCHAR(100),
        area VARCHAR(150),
        area_type ENUM('popular','medium','upscale'),
        marital_home_location VARCHAR(150),
        housing_type ENUM('owned','fixed_rent','open_rent','family_house'),
        family_house_living ENUM('separate','with_family'),

        religiosity_level VARCHAR(100),
        prays_regularly ENUM('yes','no'),
        smoker ENUM('yes','no'),
        quran_memorization VARCHAR(100),
        watches_series ENUM('yes','no','sometimes'),
        listens_music ENUM('yes','no','sometimes'),
        religious_scholars_followed TEXT,
        studied_sharia ENUM('yes','no','planning'),
        form_filled_by ENUM('self','relative'),
        relative_relation VARCHAR(100),
        filled_with_knowledge ENUM('yes','no'),
        about_me TEXT,

        partner_general_specs TEXT,
        partner_age_min INT,
        partner_age_max INT,
        partner_skin_color_preference VARCHAR(100),
        partner_marital_status_accepted VARCHAR(150),
        accepts_with_children ENUM('yes','no','indifferent'),
        accepts_children_with_father_custody ENUM('yes','no','indifferent'),
        accepts_other_governorate ENUM('yes','no'),
        accepted_governorates TEXT,
        hijab_preference ENUM('hijab','niqab','either'),
        partner_education_preference ENUM('high','medium','either'),
        partner_work_preference ENUM('works','not_working','either'),

        wants_publish_social ENUM('yes','no'),
        contacted_before ENUM('yes','no'),
        notes TEXT,

        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // تعديلات على جدول موجود بالفعل (Migration) - آمنة تتكرر أكتر من مرة
    const migrations = [
      `ALTER TABLE profile_answers ADD COLUMN IF NOT EXISTS previously_engaged_details TEXT`,
      `ALTER TABLE profile_answers MODIFY COLUMN exercises ENUM('yes','no','sometimes')`,
      `ALTER TABLE profile_answers MODIFY COLUMN watches_series ENUM('yes','no','sometimes')`,
      `ALTER TABLE profile_answers MODIFY COLUMN listens_music ENUM('yes','no','sometimes')`
    ];
    for (const sql of migrations) {
      try { await conn.query(sql); } catch (e) { console.log('Migration skip:', e.message); }
    }

    await conn.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
      const [existing] = await conn.query('SELECT id FROM admins WHERE username = ?', [process.env.ADMIN_USERNAME]);
      if (!existing.length) {
        const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
        await conn.query('INSERT INTO admins (username, password_hash) VALUES (?, ?)', [process.env.ADMIN_USERNAME, hash]);
        console.log(`تم إنشاء حساب المشرف: ${process.env.ADMIN_USERNAME}`);
      }
    }
  } finally {
    conn.release();
  }
}

module.exports = { pool, initSchema };
