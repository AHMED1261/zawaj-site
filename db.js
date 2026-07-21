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
  connectTimeout: 10000, // 10 ثواني بس - لو الداتابيز نايمة أو بطيئة، نفشل بسرعة بدل ما الصفحة تتعلق للأبد
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
        email VARCHAR(255) UNIQUE NULL,
        terms_accepted_at TIMESTAMP NULL DEFAULT NULL,
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

    await conn.query(`
      CREATE TABLE IF NOT EXISTS verification_codes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        phone VARCHAR(20) NOT NULL,
        purpose ENUM('register','reset_password') NOT NULL,
        code_hash VARCHAR(255) NOT NULL,
        attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
        expires_at DATETIME NOT NULL,
        consumed_at DATETIME NULL DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_verification_lookup (phone, purpose, expires_at)
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
        marital_home_area VARCHAR(150),
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
        reference_name VARCHAR(150),
        reference_relation VARCHAR(100),
        reference_whatsapp VARCHAR(20),

        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // تعديلات على جدول موجود بالفعل (Migration) - آمنة تتكرر أكتر من مرة
    // دالة تتأكد من وجود عمود قبل ما تضيفه - بديل أضمن من "ADD COLUMN IF NOT EXISTS"
    // اللي بعض إصدارات/إعدادات MySQL المُدارة (زي Aiven) مش دايمًا بتدعمها بشكل موثوق
    async function ensureColumn(table, column, definition) {
      const [rows] = await conn.query(
        `SELECT COUNT(*) as cnt FROM information_schema.columns
         WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?`,
        [table, column]
      );
      if (rows[0].cnt === 0) {
        await conn.query(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
        console.log(`تمت إضافة العمود ${column} إلى ${table}`);
      }
    }

    await ensureColumn('users', 'email', 'VARCHAR(255) NULL UNIQUE');
    await ensureColumn('users', 'terms_accepted_at', 'TIMESTAMP NULL DEFAULT NULL');
    await ensureColumn('profile_answers', 'reference_name', 'VARCHAR(150)');
    await ensureColumn('profile_answers', 'reference_relation', 'VARCHAR(100)');
    await ensureColumn('profile_answers', 'reference_whatsapp', 'VARCHAR(20)');
    await ensureColumn('profile_answers', 'previously_engaged_details', 'TEXT');
    await ensureColumn('profile_answers', 'marital_home_area', 'VARCHAR(150)');

    const migrations = [
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

    // طلبات التعارف: لا يتم كشف بيانات التواصل، بل يراجع الطلب الإداري بعد موافقة الطرف الآخر.
    await conn.query(`
      CREATE TABLE IF NOT EXISTS interest_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        sender_id INT NOT NULL,
        recipient_id INT NOT NULL,
        status ENUM('pending','matched','declined','withdrawn','closed') NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        responded_at TIMESTAMP NULL DEFAULT NULL,
        UNIQUE KEY unique_request_direction (sender_id, recipient_id),
        INDEX idx_requests_recipient_status (recipient_id, status),
        INDEX idx_requests_sender_status (sender_id, status),
        CONSTRAINT fk_request_sender FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
        CONSTRAINT fk_request_recipient FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS recovery_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        status ENUM('pending','approved','rejected','completed') NOT NULL DEFAULT 'pending',
        recovery_code_hash VARCHAR(255) NULL,
        expires_at DATETIME NULL,
        consumed_at DATETIME NULL,
        admin_notes TEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP NULL,
        INDEX idx_recovery_user_status (user_id, status),
        CONSTRAINT fk_recovery_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // تبدأ المراسلة بعد التوافق، وكل الرسائل تمر عبر الإدارة.
    await conn.query(`
      CREATE TABLE IF NOT EXISTS conversations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        request_id INT NOT NULL UNIQUE,
        user_one_id INT NOT NULL,
        user_two_id INT NOT NULL,
        status ENUM('active','closed') NOT NULL DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_conversations_users (user_one_id, user_two_id),
        CONSTRAINT fk_conversation_request FOREIGN KEY (request_id) REFERENCES interest_requests(id) ON DELETE CASCADE,
        CONSTRAINT fk_conversation_user_one FOREIGN KEY (user_one_id) REFERENCES users(id) ON DELETE CASCADE,
        CONSTRAINT fk_conversation_user_two FOREIGN KEY (user_two_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS conversation_messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        conversation_id INT NOT NULL,
        sender_role ENUM('user','admin') NOT NULL,
        sender_user_id INT NULL,
        recipient_user_id INT NULL,
        body TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_messages_conversation (conversation_id, created_at),
        INDEX idx_messages_recipient (recipient_user_id, created_at),
        CONSTRAINT fk_message_conversation FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
        CONSTRAINT fk_message_sender_user FOREIGN KEY (sender_user_id) REFERENCES users(id) ON DELETE SET NULL,
        CONSTRAINT fk_message_recipient_user FOREIGN KEY (recipient_user_id) REFERENCES users(id) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // فهارس لصفحة المراجعة والتصفح عند زيادة الحسابات.
    for (const sql of [
      'CREATE INDEX idx_users_status_updated ON users (status, updated_at)',
      'CREATE INDEX idx_profile_governorate ON profile_answers (governorate)',
      'CREATE INDEX idx_profile_age ON profile_answers (age)'
    ]) {
      try { await conn.query(sql); } catch (e) { if (e.code !== 'ER_DUP_KEYNAME') throw e; }
    }

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
