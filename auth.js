// auth.js
const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  console.error("CRITICAL ERROR: JWT_SECRET is not set in environment variables.");
  process.exit(1);
}

function signToken(payload, expiresIn = '30d') {
  return jwt.sign(payload, SECRET, { expiresIn });
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'محتاج تسجيل دخول' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'الجلسة منتهية، سجّل دخول تاني' });
  }
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'محتاج تسجيل دخول كمشرف' });
  try {
    const decoded = jwt.verify(token, SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'مش مسموح' });
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'الجلسة منتهية، سجّل دخول تاني' });
  }
}

module.exports = { signToken, requireAuth, requireAdmin };
