const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
require('dotenv').config({ path: 'C:/Users/13/Downloads/تحت التعديل من الجهاز جيمناي/zawaj-site-main/.env' });

const ANSWER_FIELDS = ['age','weight','height','skin_color','has_beard','exercises','health_issues','education','job','job_type','income_level','marital_status','has_children','children_count','children_ages','custody','children_details','widow_duration','last_divorce_date','divorce_count','past_marriage_details','current_wives_count','wants_polygamy','polygamy_with_first_wife_knowledge','wants_more_children','father_job','mother_job','siblings_count','siblings_education','family_background','governorate','area','area_type','marital_home_location','marital_home_area','housing_type','family_house_living','prays_regularly','smoker','quran_memorization','watches_series','listens_music','religious_scholars_followed','studied_sharia','form_filled_by','relative_relation','filled_with_knowledge','about_me','partner_general_specs','partner_age_min','partner_age_max','partner_skin_color_preference','partner_marital_status_accepted','accepts_with_children','accepts_children_with_father_custody','accepted_governorates','partner_education_preference','partner_work_preference','wants_publish_social','contacted_before','notes','dob','hijab_type','accepted_hijab_types','personal_photos','id_front','id_back','admin_phone','admin_whatsapp','education_specialization'];

const rand = (arr) => arr[Math.floor(Math.random() * arr.length)];
const randInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

const GOVERNORATES = ['القاهرة','الجيزة','الإسكندرية','الدقهلية','البحر الأحمر','البحيرة','الفيوم','الغربية','الإسماعيلية','المنوفية','المنيا','القليوبية','الوادي الجديد','السويس','أسوان','أسيوط','بني سويف','بورسعيد','دمياط','الشرقية','جنوب سيناء','كفر الشيخ','مطروح','الأقصر','قنا','شمال سيناء','سوهاج'];

async function main() {
  const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
  });

  try {
    console.log('Deleting old demo profiles...');
    await pool.query('DELETE FROM users WHERE phone LIKE "010000%"');

    console.log('Generating 2000 new demo profiles...');
    const passHash = await bcrypt.hash('123456', 10);
    
    for (let i = 1; i <= 2000; i++) {
      const phone = '010000' + i.toString().padStart(5, '0');
      const gender = rand(['male', 'female']);
      const maritalStatus = rand(['single', 'katb_ketab', 'divorced', 'widowed']);
      
      const [uRes] = await pool.query(
        'INSERT INTO users (phone, password_hash, gender, status) VALUES (?, ?, ?, "approved")',
        [phone, passHash, gender]
      );
      const userId = uRes.insertId;

      const profile = {
        age: randInt(20, 60),
        weight: randInt(50, 100),
        height: randInt(150, 190),
        skin_color: rand(['قمحي', 'أبيض', 'أسمر', 'فاتح']),
        exercises: rand(['yes', 'no', 'sometimes']),
        health_issues: 'لا يوجد',
        education: rand(['أقل من الثانوية','ثانوية عامة','دبلوم (متوسط)','بكالوريوس/ليسانس (عالي)','دراسات عليا (ماجستير/دكتوراه)']),
        job: 'موظف',
        job_type: rand(['government', 'private', 'business_owner']),
        income_level: rand(['normal', 'medium', 'welloff', 'high']),
        marital_status: maritalStatus,
        governorate: rand(GOVERNORATES),
        area: 'المنطقة',
        area_type: rand(['city', 'village']),
        marital_home_location: rand(GOVERNORATES),
        marital_home_area: 'المركز',
        housing_type: rand(['owned', 'fixed_rent', 'open_rent', 'family_house']),
        prays_regularly: rand(['all', 'most', 'sometimes', 'none']),
        smoker: rand(['yes', 'no']),
        quran_memorization: 'جزء عم',
        watches_series: rand(['yes', 'no', 'sometimes']),
        listens_music: rand(['yes', 'no', 'sometimes']),
        studied_sharia: rand(['yes', 'no', 'planning']),
        form_filled_by: 'myself',
        about_me: 'أبحث عن الاستقرار.',
        partner_general_specs: 'شخص محترم.',
        partner_age_min: randInt(20, 30),
        partner_age_max: randInt(35, 50),
        partner_skin_color_preference: 'لا يهم',
        wants_publish_social: 'yes',
        contacted_before: 'no',
        dob: (1990 + randInt(-10, 10)) + '-01-01',
        admin_phone: '0100000000',
        education_specialization: 'تجارة'
      };

      if (gender === 'male') {
        profile.has_beard = rand(['no_beard', 'short', 'medium', 'long']);
        profile.accepted_hijab_types = JSON.stringify(['hijab', 'khimar']);
      } else {
        profile.hijab_type = rand(['hijab', 'khimar', 'niqab']);
      }

      if (maritalStatus === 'divorced' || maritalStatus === 'widowed') {
        profile.has_children = rand(['yes', 'no']);
        if (profile.has_children === 'yes') {
          profile.children_count = randInt(1, 4);
          profile.custody = 'me';
        }
      }

      // Arrays for multi-selects
      profile.partner_marital_status_accepted = JSON.stringify(['أعزب', 'مطلق/ة']);
      profile.accepted_governorates = JSON.stringify([rand(GOVERNORATES)]);
      profile.partner_education_preference = JSON.stringify(['بكالوريوس/ليسانس (عالي)']);
      profile.partner_work_preference = JSON.stringify(['لا يهم']);

      // Convert to insert format
      const cols = [];
      const vals = [];
      const placeholders = [];
      for (const k of ANSWER_FIELDS) {
        if (profile[k] !== undefined) {
          cols.push(k);
          vals.push(profile[k]);
          placeholders.push('?');
        }
      }

      await pool.query(
        'INSERT INTO profile_answers (user_id, ' + cols.join(',') + ') VALUES (' + placeholders.join(',') + ')',
        [userId, ...vals]
      );
    }
    console.log('Successfully generated 2000 profiles!');
  } catch (err) {
    console.error(err);
  }
  pool.end();
}
main();
