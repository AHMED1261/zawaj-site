const https = require('https');

function configured() { return Boolean(process.env.RESEND_API_KEY && process.env.EMAIL_FROM); }

function postJson(data) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(data);
    const request = https.request('https://api.resend.com/emails', { method:'POST', headers:{ Authorization:`Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type':'application/json', 'Content-Length':Buffer.byteLength(body) } }, response => {
      let output = ''; response.on('data', chunk => { output += chunk; });
      response.on('end', () => response.statusCode >= 200 && response.statusCode < 300 ? resolve() : reject(new Error(`Email API returned ${response.statusCode}: ${output}`)));
    });
    request.on('error', reject); request.write(body); request.end();
  });
}
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, char => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[char])); }
async function sendEmail(to, subject, html) { if (!configured()) throw new Error('Email delivery is not configured'); return postJson({ from:process.env.EMAIL_FROM, to:[to], subject, html }); }
async function sendVerificationCode(to, code) { return sendEmail(to, 'رمز التحقق - منصة الزواج', `<div dir="rtl"><h2>رمز التحقق</h2><p>رمزك هو:</p><p style="font-size:28px;font-weight:bold;letter-spacing:5px">${code}</p><p>صالح لمدة 10 دقائق. لا تشاركه مع أي شخص.</p></div>`); }
async function sendAccountNotification(to, message) { return sendEmail(to, 'تحديث من منصة الزواج', `<div dir="rtl"><h2>منصة الزواج</h2><p>${escapeHtml(message)}</p><p>سجّل الدخول إلى حسابك لمتابعة التفاصيل.</p></div>`); }
module.exports = { configured, sendVerificationCode, sendAccountNotification };
