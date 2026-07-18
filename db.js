// db.js - MySQL connection pool
require('dotenv').config();
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  // ملحوظة: rejectUnauthorized:false بيسيب البيانات مشفرة في النقل، بس مبيتحققش من هوية شهادة السيرفر.
  // ده كافي لمشروع مبدئي على Aiven، ولو عايز أمان أعلى بعدين ممكن تضيف شهادة CA بتاعة Aiven بدل كده.
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined
});

async function initSchema() {
  const conn = await pool.getConnection();
  try {
    await conn.query(`
      CREATE TABLE IF NOT EXISTS profiles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(150) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        gender ENUM('male','female') NOT NULL,
        age INT NOT NULL,
        governorate VARCHAR(100),
        marital_status ENUM('single','divorced','widowed') NOT NULL,
        wants_children ENUM('yes','no','maybe') NOT NULL,
        religion VARCHAR(50),
        education VARCHAR(150),
        job VARCHAR(150),
        bio TEXT,
        photo_url VARCHAR(255),
        is_active TINYINT(1) DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);
  } finally {
    conn.release();
  }
}

module.exports = { pool, initSchema };
