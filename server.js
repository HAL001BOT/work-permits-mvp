const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const multer = require('multer');
const PDFDocument = require('pdfkit');
const { db, migrate } = require('./db');

migrate();

const app = express();
const PORT = process.env.PORT || 3000;

if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

const ROLES = {
  ADMIN: 'admin',
  SUPERVISOR: 'supervisor',
  REQUESTER: 'requester',
  VIEWER: 'viewer',
};

const PERMIT_TYPES = {
  GENERAL_WORK_SAFE: 'general_work_safe',
  HOT_WORK: 'hot_work',
  CONFINED_SPACE: 'confined_space',
  LOTO: 'loto',
  EXCAVATION: 'excavation',
  LINE_BREAK: 'line_break',
  WORKING_HEIGHTS: 'working_heights',
};

const SUPPLEMENTAL_PERMIT_TYPES = [
  PERMIT_TYPES.HOT_WORK,
  PERMIT_TYPES.CONFINED_SPACE,
  PERMIT_TYPES.LOTO,
  PERMIT_TYPES.EXCAVATION,
  PERMIT_TYPES.LINE_BREAK,
  PERMIT_TYPES.WORKING_HEIGHTS,
];

const PERMIT_TYPE_LABELS = {
  [PERMIT_TYPES.GENERAL_WORK_SAFE]: 'GSWP',
  [PERMIT_TYPES.HOT_WORK]: 'Hot Work Permit',
  [PERMIT_TYPES.CONFINED_SPACE]: 'Confined Space Permit',
  [PERMIT_TYPES.LOTO]: 'LOTO / Energy Isolation Permit',
  [PERMIT_TYPES.EXCAVATION]: 'Excavation Permit',
  [PERMIT_TYPES.LINE_BREAK]: 'First Break Permit',
  [PERMIT_TYPES.WORKING_HEIGHTS]: 'Working at Heights Permit',
};

const TEMPLATE_TEXT_BY_TYPE = {
  [PERMIT_TYPES.GENERAL_WORK_SAFE]: `Template: generalsafework.docx\n\nSection 1 – Additional Work Permits\n- Hot Work Permit (open flames, cutting, welding, grinding, drilling)\n- Confined Space Entry Permit (chemical vessels/tanks or confined areas)\n- Work at Height Permit (4 ft+ without guardrails)\n- Lockout/Tagout Permit (energy isolation)\n- First Break Permit (opening pipe, pumps, vessels)\n\nSection 2 – Work Description\nDescribe scope, location/building, equipment, contractor company, supervisor, shift, work order/project #.\n\nDaily Revalidation\nPermit is revalidated each day (up to 7 days max).`,
  [PERMIT_TYPES.HOT_WORK]: `Template: EHS&S RC Health & Safety HOT WORK PERMIT 12-14-2022.docx\n\nGeneral Information\n- General Work Permit No.\n- Work by: Sachem personnel or Contractors\n- Additional comments\n\nFire Watch Requirement\n- Fire watch required?\n- Work generates sparks/open flames (drilling/cutting/soldering/grinding/brazing/welding/torching)\n- Fire watch during work and minimum 1 hour after work\n\nHot Work Safety Requirements\n- Fire protection systems operable\n- O2/LEL monitor calibration current\n- 35 ft area clear of flammables/combustibles\n- Initial gas measurements recorded.`,
  [PERMIT_TYPES.CONFINED_SPACE]: `Template: EHS&S_RC HEALTH & SAFETY CONFINED SPACE PERMIT 08-27-2025.pdf\n\nCapture confined space entry details including:\n- Space identification and location\n- Entry purpose/scope\n- Entrants, attendant, and entry supervisor\n- Atmospheric testing (O2/LEL/toxics), frequency, and results\n- Isolation controls (LOTO, line blanking, ventilation)\n- Rescue plan and communication method\n- Entry start/end authorization signatures.`,
  [PERMIT_TYPES.LOTO]: `Templates: EHSS LOCKOUT TAG OUT PERMIT 03-20-2025.docx + Lockout Tag Out Form 06-26-2025.docx\n\nGeneral Information\n- LOTO date, expected final date (7 days max), permit linkage\n- Job scope and affected employees notified\n\nEnergy Isolation Verification\n- Electrical / Mechanical / Thermal / Chemical / Hydraulic-Pneumatic\n- Zero energy verification\n- Lock and tag IDs, isolation points, verification initials\n\nSpecial note\n- Include chemical washout verification where applicable.`,
  [PERMIT_TYPES.LINE_BREAK]: `Template: FORMS MAINTENANCE FIRST BREAK PERMIT 11-21-2022.docx\n\nPre-break checklist\n- Material last contained identified and hazard class confirmed\n- SDS reviewed\n- LOTO completed\n- Line identification confirmed by PM + Shift Supervisor + Contractor\n- Lines drained/vented, cooled, flushed, cleaned\n- Valves/pumps closed, locked, tagged\n\nAll checklist items must be signed/initialed before first break proceeds.`,
  [PERMIT_TYPES.WORKING_HEIGHTS]: `Template: EHSS_RC HEALTH & SAFETY WORK AT HEIGHT PERMIT 03-07-2025.docx\n\nWork-at-height scope\n- Fixed ladders 24 ft+, manlifts, or other >4 ft without guardrails\n\nInspection / authorization\n- Contractor vs Sachem path (inspection section routing)\n- Harness/lanyard inspection (tags readable, not expired, ANSI Z359, no damage/modification)\n- Work controls and approvals before start.`,
};

const PERMIT_FIELD_SCHEMAS = {
  [PERMIT_TYPES.GENERAL_WORK_SAFE]: [
    { key: 'general_permit_no', label: 'General Work Permit Number', type: 'text', readOnly: true, required: true, section: 'General Information' },
    { key: 'start_time', label: 'Start Time', type: 'time', required: true, section: 'General Information' },
    { key: 'start_date', label: 'Start Date', type: 'date', required: true, section: 'General Information' },
    { key: 'building_location', label: 'Building / Location', type: 'select', options: ['Manufacturing building', 'Production building', 'Tanks'], required: true, section: 'General Information' },
    { key: 'contractor_company', label: 'Contractor Company', type: 'text', required: true, section: 'General Information' },
    { key: 'shift', label: 'Shift', type: 'select', options: ['A', 'B', 'C', 'D'], required: true, section: 'General Information' },
    { key: 'equipment', label: 'Equipment Being Worked On', type: 'text', required: true, section: 'General Information' },
    { key: 'contractor_lead', label: 'Contractor Supervisor / Lead', type: 'text', required: true, section: 'General Information' },
    { key: 'shift_supervisor', label: 'Shift Supervisor / Equivalent Rep', type: 'text', required: true, section: 'General Information' },
    { key: 'work_order_number', label: 'Work Order Number', type: 'text', required: true, section: 'General Information' },
    { key: 'project_number', label: 'Project Number (if applicable)', type: 'text', required: true, section: 'General Information' },

    { key: 'confirm_no_other_permits', label: 'I confirm no other permits are needed', type: 'checkbox', required: true, section: 'Section 1 – Additional Work Permits' },

    { key: 'scope_of_work', label: 'Describe the work to be completed', type: 'textarea', required: true, section: 'Section 2a – Work Description' },
    { key: 'hard_hat', label: 'Hard Hat', type: 'checkbox', forcedTrue: true, section: 'Section 2b – PPE Required' },
    { key: 'full_sleeve_shirt', label: 'Full Sleeve Shirt', type: 'checkbox', forcedTrue: true, section: 'Section 2b – PPE Required' },
    { key: 'steel_toe_shoes', label: 'Steel Toe Shoes', type: 'checkbox', forcedTrue: true, section: 'Section 2b – PPE Required' },
    { key: 'safety_glasses', label: 'Safety Glasses', type: 'checkbox', forcedTrue: true, section: 'Section 2b – PPE Required' },
    { key: 'face_shield', label: 'Face shield', type: 'checkbox', section: 'Section 2b – PPE Required' },
    { key: 'welding_face_shield', label: 'Welding Face shield', type: 'checkbox', section: 'Section 2b – PPE Required' },
    { key: 'full_face_respirator', label: 'Full Face Respirator', type: 'checkbox', section: 'Section 2b – PPE Required' },
    { key: 'safety_leather_gloves', label: 'Safety/Leather Gloves', type: 'checkbox', section: 'Section 2b – PPE Required' },
    { key: 'ear_plugs', label: 'Ear Plugs', type: 'checkbox', section: 'Section 2b – PPE Required' },
    { key: 'chemical_rubber_boots', label: 'Chemical rubber boots', type: 'checkbox', section: 'Section 2b – PPE Required' },
    { key: 'fire_retardant_attire', label: 'Fire Retardant Attire', type: 'checkbox', section: 'Section 2b – PPE Required' },
    { key: 'chemical_frock', label: 'Chemical Frock', type: 'checkbox', section: 'Section 2b – PPE Required' },
    { key: 'safety_harness', label: 'Safety Harness', type: 'checkbox', section: 'Section 2b – PPE Required' },
    { key: 'chemical_gloves', label: 'Chemical Gloves', type: 'checkbox', section: 'Section 2b – PPE Required' },
    { key: 'chemical_apron', label: 'Chemical Apron', type: 'checkbox', section: 'Section 2b – PPE Required' },
    { key: 'dust_mask', label: 'Dust Mask', type: 'checkbox', section: 'Section 2b – PPE Required' },
    { key: 'other_text', label: 'Others', type: 'text', section: 'Section 2b – PPE Required' },

    { key: 'haz_low_visibility', label: 'Low visibility', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_chemical_exposure', label: 'Chemical Exposure', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_explosion_hazard', label: 'Explosion Hazard', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_noise_exposure', label: 'Noise Exposure', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_hot_cold_environment', label: 'Hot/cold Environment', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_slip_trip_fall', label: 'Slip, Trip & Fall', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_fall_from_height', label: 'Fall from height', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_falling_objects', label: 'Falling objects', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_mobile_equipment', label: 'Mobile Equipment', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_caught_between', label: 'Caught by/between', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_struck_against', label: 'Struck by/against', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_sharp_objects', label: 'Sharp Objects/pinch points', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_stored_energy', label: 'Stored Energy (pressure, Electric, etc.)', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_compressed_gas', label: 'Compressed gas', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_flammable_material', label: 'Flammable/combustible Material', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_spilled_chemical', label: 'Spilled chemical/potential', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_environmental_exposure', label: 'Environmental exposure (to soil, drain)', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'haz_confined_space', label: 'Confined Space', type: 'checkbox', section: 'Section 3 – Hazard Evaluation' },
    { key: 'hazards_other', label: 'List all other hazards', type: 'textarea', section: 'Section 3 – Hazard Evaluation' },
    { key: 'hazard_controls', label: '3a. Steps taken to mitigate hazards', type: 'textarea', section: 'Section 3 – Hazard Evaluation' },
    { key: 'mobile_equipment_cert_initials', label: 'Mobile Equipment Certification Initials', type: 'text', section: 'Section 3 – Hazard Evaluation' },

    { key: 'personnel_trained_protocols', label: 'Personnel trained in on-site safety protocols', type: 'select', options: ['Yes', 'No'], required: true, section: 'Section 4 – Hazard Communication & Worksite Safety' },
    { key: 'personnel_briefed_hazards', label: 'Personnel briefed on area hazards', type: 'select', options: ['Yes', 'No'], required: true, section: 'Section 4 – Hazard Communication & Worksite Safety' },
    { key: 'needs_shutdown', label: 'Equipment/process needs shutdown', type: 'select', options: ['Yes', 'No', 'N/A'], required: true, section: 'Section 4 – Hazard Communication & Worksite Safety' },
    { key: 'chemicals_cleared', label: 'Chemicals in work area cleared', type: 'select', options: ['Yes', 'No', 'N/A'], required: true, section: 'Section 4 – Hazard Communication & Worksite Safety' },

    { key: 'team_member_signoffs', label: '5a. Personnel sign-off names/dates', type: 'textarea', required: true, section: 'Section 5 – Approval & Closeout' },
    { key: 'team_leader_sign', label: 'Team leader sign / date', type: 'text', required: true, section: 'Section 5 – Approval & Closeout' },
    { key: 'closeout_completed', label: '5b. Work has been completed', type: 'checkbox', required: true, section: 'Section 5 – Approval & Closeout' },
    { key: 'closeout_not_completed', label: '5b. Work has NOT been completed', type: 'checkbox', required: true, section: 'Section 5 – Approval & Closeout' },
    { key: 'closeout_comments', label: 'Closeout comments', type: 'textarea', required: true, section: 'Section 5 – Approval & Closeout' },
    { key: 'area_owner_sign', label: 'Shift Supervisor / Area Owner sign / date', type: 'text', required: true, section: 'Section 5 – Approval & Closeout' },
  ],
  [PERMIT_TYPES.HOT_WORK]: [
    { key: 'work_by', label: 'Hot Work By (Sachem/Contractor)', type: 'text' },
    { key: 'additional_comments', label: 'Additional Comments', type: 'textarea' },
    { key: 'fire_watch_required', label: 'Fire Watch Required', type: 'checkbox' },
    { key: 'sparks_open_flame', label: 'Generates Sparks/Open Flame', type: 'checkbox' },
    { key: 'fire_watch_after_1h', label: 'Fire Watch for 1h After Work', type: 'checkbox' },
    { key: 'o2_lel_calibrated_on', label: 'O2/LEL Calibrated On', type: 'date' },
    { key: 'o2_lel_next_calibration', label: 'O2/LEL Next Calibration', type: 'date' },
    { key: 'initial_measurement', label: 'Initial Gas Measurement', type: 'text' },
  ],
  [PERMIT_TYPES.CONFINED_SPACE]: [
    { key: 'space_id', label: 'Confined Space ID / Name', type: 'text' },
    { key: 'entry_purpose', label: 'Entry Purpose', type: 'textarea' },
    { key: 'entrants', label: 'Entrants', type: 'text' },
    { key: 'attendant', label: 'Attendant', type: 'text' },
    { key: 'entry_supervisor', label: 'Entry Supervisor', type: 'text' },
    { key: 'atmospheric_tests', label: 'Atmospheric Test Results', type: 'textarea' },
    { key: 'ventilation_required', label: 'Ventilation Required', type: 'checkbox' },
    { key: 'rescue_plan', label: 'Rescue Plan', type: 'textarea' },
  ],
  [PERMIT_TYPES.LOTO]: [
    { key: 'loto_date', label: 'LOTO Date', type: 'date' },
    { key: 'expected_end_date', label: 'Expected Final Date', type: 'date' },
    { key: 'job_scope', label: 'Job Scope', type: 'textarea' },
    { key: 'electrical_isolated', label: 'Electrical Energy Isolated', type: 'checkbox' },
    { key: 'mechanical_isolated', label: 'Mechanical Energy Isolated', type: 'checkbox' },
    { key: 'thermal_isolated', label: 'Thermal Energy Isolated', type: 'checkbox' },
    { key: 'chemical_isolated', label: 'Chemical Energy Isolated', type: 'checkbox' },
    { key: 'hydraulic_pneumatic_isolated', label: 'Hydraulic/Pneumatic Isolated', type: 'checkbox' },
    { key: 'lock_tag_ids', label: 'Lock/Tag IDs', type: 'textarea' },
    { key: 'zero_energy_verified', label: 'Zero Energy Verified', type: 'checkbox' },
  ],
  [PERMIT_TYPES.LINE_BREAK]: [
    { key: 'line_last_contained', label: 'Line Last Contained', type: 'text' },
    { key: 'hazardous_material', label: 'Hazardous/Flammable Material', type: 'checkbox' },
    { key: 'sds_reviewed', label: 'SDS Reviewed', type: 'checkbox' },
    { key: 'loto_completed', label: 'LOTO Completed', type: 'checkbox' },
    { key: 'line_identified', label: 'Line Identified by PM/Supervisor/Contractor', type: 'checkbox' },
    { key: 'drained_vented', label: 'Lines Drained and Vented', type: 'checkbox' },
    { key: 'cooled', label: 'Equipment/Lines Cooled (<=100F)', type: 'checkbox' },
    { key: 'flushed_cleaned', label: 'Lines Flushed and Cleaned', type: 'checkbox' },
  ],
  [PERMIT_TYPES.WORKING_HEIGHTS]: [
    { key: 'work_height_type', label: 'Type of Work at Height', type: 'text' },
    { key: 'height_feet', label: 'Height (ft)', type: 'text' },
    { key: 'contractor_work', label: 'Contractor / Third-party Work', type: 'checkbox' },
    { key: 'harness_inspected_today', label: 'Harness/Lanyard Inspected Today', type: 'checkbox' },
    { key: 'biannual_inspection_current', label: 'Biannual Inspection Up To Date', type: 'checkbox' },
    { key: 'ansi_z359_tag', label: 'ANSI Z359 Tag Verified', type: 'checkbox' },
    { key: 'lanyard_not_expired', label: 'Harness/Lanyard Not Expired', type: 'checkbox' },
  ],
};

const FIELD_EDITABLE_STATUSES = new Set(['draft', 'submitted']);
const ALLOWED_UPLOAD_MIME = new Set([
  'application/pdf',
  'image/jpeg',
  'image/png',
  'image/gif',
  'text/plain',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/msword',
]);

const uploadsDir = path.join(__dirname, 'data', 'uploads');
fs.mkdirSync(uploadsDir, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadsDir),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname || '').slice(0, 10).replace(/[^a-zA-Z0-9.]/g, '');
      cb(null, `${Date.now()}-${crypto.randomUUID()}${ext ? `.${ext.replace(/^\./, '')}` : ''}`);
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    if (!ALLOWED_UPLOAD_MIME.has(file.mimetype)) return cb(new Error('File type not allowed'));
    cb(null, true);
  },
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(
  session({
    store: new SQLiteStore({ db: 'sessions.db', dir: path.join(__dirname, 'data') }),
    secret: process.env.SESSION_SECRET || 'change-me-in-prod',
    resave: false,
    saveUninitialized: false,
    proxy: process.env.NODE_ENV === 'production',
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 8,
    },
  })
);

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function hasAnyRole(user, roles) {
  return user && roles.includes(user.role);
}

function canCreatePermit(user) {
  return hasAnyRole(user, [ROLES.ADMIN, ROLES.SUPERVISOR, ROLES.REQUESTER]);
}

function permitTypeLabel(type) {
  return PERMIT_TYPE_LABELS[type] || type;
}

function templateTextForType(type) {
  return TEMPLATE_TEXT_BY_TYPE[type] || '';
}

function generateNextGswpTitle() {
  const rows = db
    .prepare(`SELECT permit_fields_json FROM permits WHERE permit_type = ?`)
    .all(PERMIT_TYPES.GENERAL_WORK_SAFE);

  let maxNum = -1;
  for (const row of rows) {
    const permitNo = parsePermitFieldsJson(row.permit_fields_json).general_permit_no || '';
    const m = String(permitNo).match(/^SACHEM-GSWP-(\d{5})$/);
    if (!m) continue;
    const n = Number(m[1]);
    if (Number.isInteger(n) && n > maxNum) maxNum = n;
  }
  const next = maxNum + 1;
  return `SACHEM-GSWP-${String(next).padStart(5, '0')}`;
}

function normalizeDuplicateGswpNumbers() {
  const rows = db
    .prepare(`SELECT id, permit_fields_json FROM permits WHERE permit_type = ? ORDER BY id ASC`)
    .all(PERMIT_TYPES.GENERAL_WORK_SAFE);

  const seen = new Set();
  let counter = 0;
  const tx = db.transaction(() => {
    for (const row of rows) {
      const fields = parsePermitFieldsJson(row.permit_fields_json);
      const existing = String(fields.general_permit_no || '');
      const isValid = /^SACHEM-GSWP-(\d{5})$/.test(existing) && !seen.has(existing);
      if (isValid) {
        seen.add(existing);
        const n = Number(existing.slice(-5));
        if (n >= counter) counter = n + 1;
        continue;
      }

      let next;
      do {
        next = `SACHEM-GSWP-${String(counter).padStart(5, '0')}`;
        counter += 1;
      } while (seen.has(next));

      fields.general_permit_no = next;
      db.prepare(`UPDATE permits SET permit_fields_json = ? WHERE id = ?`).run(JSON.stringify(fields), row.id);
      seen.add(next);
    }
  });

  tx();
}

function fieldSchemaForType(type) {
  return PERMIT_FIELD_SCHEMAS[type] || [];
}

function parsePermitFieldsJson(value) {
  if (!value) return {};
  try {
    const obj = JSON.parse(value);
    return obj && typeof obj === 'object' ? obj : {};
  } catch {
    return {};
  }
}

function extractPermitFieldsFromBody(body, permitType) {
  const schema = fieldSchemaForType(permitType);
  const fields = {};
  for (const f of schema) {
    const key = `pf__${f.key}`;
    if (f.type === 'checkbox') fields[f.key] = f.forcedTrue ? 1 : (body[key] ? 1 : 0);
    else fields[f.key] = String(body[key] || '').trim();
  }
  return fields;
}

function parseRequiredPermitsJson(value) {
  if (!value) return [];
  try {
    const arr = JSON.parse(value);
    if (!Array.isArray(arr)) return [];
    return arr.filter((x) => SUPPLEMENTAL_PERMIT_TYPES.includes(x));
  } catch {
    return [];
  }
}

function normalizeRequiredPermits(input) {
  const raw = Array.isArray(input) ? input : input ? [input] : [];
  return Array.from(new Set(raw.filter((x) => SUPPLEMENTAL_PERMIT_TYPES.includes(x))));
}

function validatePermitFields(permitType, permitFields) {
  if (permitType !== PERMIT_TYPES.GENERAL_WORK_SAFE) return null;

  const schema = fieldSchemaForType(permitType);
  for (const f of schema) {
    if (!f.required) continue;
    const val = permitFields[f.key];
    if (f.type === 'checkbox') {
      if (!Number(val)) return `${f.label} is required.`;
    } else if (!String(val || '').trim()) {
      return `${f.label} is required.`;
    }
  }

  const hazardKeys = [
    'haz_low_visibility', 'haz_chemical_exposure', 'haz_explosion_hazard', 'haz_noise_exposure', 'haz_hot_cold_environment',
    'haz_slip_trip_fall', 'haz_fall_from_height', 'haz_falling_objects', 'haz_mobile_equipment', 'haz_caught_between',
    'haz_struck_against', 'haz_sharp_objects', 'haz_stored_energy', 'haz_compressed_gas', 'haz_flammable_material',
    'haz_spilled_chemical', 'haz_environmental_exposure', 'haz_confined_space',
  ];
  const selectedHazards = hazardKeys.filter((k) => Number(permitFields[k]));
  if (!selectedHazards.length) return 'Section 3 requires at least one hazard selected.';

  return null;
}

function isGeneralPermit(permit) {
  return (permit.permit_type || PERMIT_TYPES.GENERAL_WORK_SAFE) === PERMIT_TYPES.GENERAL_WORK_SAFE;
}

normalizeDuplicateGswpNumbers();

function canEditFields(user, permit) {
  if (!user || permit.is_locked) return false;
  if (!FIELD_EDITABLE_STATUSES.has(permit.status)) return false;
  if (hasAnyRole(user, [ROLES.ADMIN, ROLES.SUPERVISOR])) return true;
  return user.role === ROLES.REQUESTER && permit.created_by === user.id;
}

function canDeletePermit(user) {
  return hasAnyRole(user, [ROLES.ADMIN]);
}

function requireAdmin(req, res, next) {
  if (!hasAnyRole(req.session.user, [ROLES.ADMIN])) return res.status(403).send('Forbidden');
  next();
}

function transitionActions(user, permit) {
  const actions = [];
  const isOwnerRequester = user.role === ROLES.REQUESTER && permit.created_by === user.id;
  if (permit.status === 'draft' && (isOwnerRequester || hasAnyRole(user, [ROLES.ADMIN, ROLES.SUPERVISOR]))) actions.push('submit');
  if (permit.status === 'submitted' && hasAnyRole(user, [ROLES.ADMIN, ROLES.SUPERVISOR])) actions.push('approve');
  if (permit.status === 'approved' && hasAnyRole(user, [ROLES.ADMIN, ROLES.SUPERVISOR])) actions.push('close', 'reopen');
  if (permit.status === 'closed' && hasAnyRole(user, [ROLES.ADMIN, ROLES.SUPERVISOR])) actions.push('reopen');
  return actions;
}

function canDeleteAttachment(user) {
  return hasAnyRole(user, [ROLES.ADMIN, ROLES.SUPERVISOR]);
}

function statusOptions() {
  return ['draft', 'submitted', 'approved', 'closed'];
}

function getFilterContext(query) {
  const { status = '', site = '', startDate = '', endDate = '' } = query;
  const clauses = [];
  const params = [];

  if (status) {
    clauses.push('p.status = ?');
    params.push(status);
  }
  if (site) {
    clauses.push('p.site LIKE ?');
    params.push(`%${site}%`);
  }
  if (startDate) {
    clauses.push('p.permit_date >= ?');
    params.push(startDate);
  }
  if (endDate) {
    clauses.push('p.permit_date <= ?');
    params.push(endDate);
  }

  return {
    filters: { status, site, startDate, endDate },
    where: clauses.length ? `WHERE ${clauses.join(' AND ')}` : '',
    params,
  };
}

function formatStatusLabel(status) {
  if (!status) return '';
  return status[0].toUpperCase() + status.slice(1);
}

const AUDIT_FIELD_LABELS = {
  title: 'Title',
  site: 'Site',
  permit_date: 'Permit Date',
  status: 'Status',
  description: 'Description',
  approved_at: 'Approved At',
  approver_name: 'Approver Name',
  signature_text: 'Digital Signature',
  is_locked: 'Locked',
  revision: 'Revision',
  id: 'ID',
};

function safeParseJson(value) {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

function formatDate(value) {
  if (!value) return '-';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString();
}

function toDisplayValue(field, value) {
  if (value === null || value === undefined || value === '') return '—';
  if (field === 'status') return formatStatusLabel(String(value));
  if (field === 'is_locked') return Number(value) ? 'Yes' : 'No';
  if (String(field).includes('date') || String(field).endsWith('_at')) return formatDate(value);
  return String(value);
}

function toFriendlyChanges(oldValues, newValues) {
  const oldObj = safeParseJson(oldValues) || {};
  const newObj = safeParseJson(newValues) || {};
  const keys = Array.from(new Set([...Object.keys(oldObj), ...Object.keys(newObj)]));

  return keys
    .filter((k) => String(oldObj[k] ?? '') !== String(newObj[k] ?? ''))
    .map((field) => ({
      field,
      label: AUDIT_FIELD_LABELS[field] || field.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
      oldValue: toDisplayValue(field, oldObj[field]),
      newValue: toDisplayValue(field, newObj[field]),
    }));
}

function logAudit(permitId, action, oldValues, newValues, changedBy) {
  db.prepare(
    `INSERT INTO permit_audit (permit_id, action, old_values, new_values, changed_by)
     VALUES (?, ?, ?, ?, ?)`
  ).run(permitId, action, oldValues ? JSON.stringify(oldValues) : null, newValues ? JSON.stringify(newValues) : null, changedBy);
}

function pickSnapshot(permit) {
  return {
    title: permit.title,
    description: permit.description,
    site: permit.site,
    status: permit.status,
    permit_date: permit.permit_date,
    permit_type: permit.permit_type,
    parent_permit_id: permit.parent_permit_id,
    required_permits: parseRequiredPermitsJson(permit.required_permits_json),
    permit_fields: parsePermitFieldsJson(permit.permit_fields_json),
    approved_at: permit.approved_at,
    approver_name: permit.approver_name,
    signature_text: permit.signature_text,
    is_locked: permit.is_locked,
    revision: permit.revision,
  };
}

function getPermitById(id) {
  return db
    .prepare(
      `SELECT p.*, c.username AS created_by_name, u.username AS updated_by_name
       FROM permits p
       JOIN users c ON c.id = p.created_by
       JOIN users u ON u.id = p.updated_by
       WHERE p.id = ?`
    )
    .get(id);
}

function getChildPermits(parentPermitId) {
  return db
    .prepare(
      `SELECT p.*, c.username AS created_by_name, u.username AS updated_by_name
       FROM permits p
       JOIN users c ON c.id = p.created_by
       JOIN users u ON u.id = p.updated_by
       WHERE p.parent_permit_id = ?
       ORDER BY p.id ASC`
    )
    .all(parentPermitId);
}

function syncRequiredChildPermits(parentPermit, requiredTypes, userId) {
  if (!isGeneralPermit(parentPermit)) return;
  const existing = getChildPermits(parentPermit.id);
  const existingByType = new Map(existing.map((p) => [p.permit_type, p]));

  for (const type of requiredTypes) {
    if (existingByType.has(type)) continue;
    const title = `${permitTypeLabel(type)} - for Permit #${parentPermit.id}`;
    db.prepare(
      `INSERT INTO permits (title, description, site, status, permit_date, created_by, updated_by, permit_type, parent_permit_id, required_permits_json, permit_fields_json)
       VALUES (?, ?, ?, 'draft', ?, ?, ?, ?, ?, '[]', ?)`
    ).run(title, templateTextForType(type), parentPermit.site, parentPermit.permit_date, userId, userId, type, parentPermit.id, JSON.stringify({}));
  }
}

function validateGeneralTransitionRequirements(permit, action) {
  if (!isGeneralPermit(permit)) return null;
  const requiredTypes = parseRequiredPermitsJson(permit.required_permits_json);
  if (!requiredTypes.length) return null;

  const childrenByType = new Map(getChildPermits(permit.id).map((p) => [p.permit_type, p]));
  const missing = requiredTypes.filter((t) => !childrenByType.has(t));
  if (missing.length) return `Missing required permits: ${missing.map((t) => permitTypeLabel(t)).join(', ')}`;

  if (action === 'submit') {
    const notSubmitted = requiredTypes.filter((t) => {
      const status = childrenByType.get(t)?.status;
      return !['submitted', 'approved', 'closed'].includes(status);
    });
    if (notSubmitted.length) return `Submit required permits first: ${notSubmitted.map((t) => permitTypeLabel(t)).join(', ')}`;
  }

  if (action === 'approve') {
    const notApproved = requiredTypes.filter((t) => {
      const status = childrenByType.get(t)?.status;
      return !['approved', 'closed'].includes(status);
    });
    if (notApproved.length) return `Approve required permits first: ${notApproved.map((t) => permitTypeLabel(t)).join(', ')}`;
  }

  return null;
}

const BRAND = {
  primary: '#0f766e',
  primaryDark: '#115e59',
  muted: '#475569',
  border: '#cbd5e1',
  bgSoft: '#f0fdfa',
};

const LOGO_CANDIDATES = [path.join(__dirname, 'public', 'img', 'sachem.png'), path.join(__dirname, 'public', 'img', 'sachem.gif')];

function resolveLogoPath() {
  for (const logoPath of LOGO_CANDIDATES) if (fs.existsSync(logoPath)) return logoPath;
  return null;
}

function drawFooter(_doc, _generatedAt) {
  // Footer intentionally disabled to avoid trailing blank-page artifacts.
}

function ensurePdfSpace(doc, needed = 40) {
  const bottom = doc.page.height - 60;
  if (doc.y + needed > bottom) doc.addPage();
}

function drawHeader(doc, subtitle) {
  const startY = 44;
  doc.save();
  doc.rect(0, 0, doc.page.width, 125).fill(BRAND.bgSoft);
  doc.rect(0, 118, doc.page.width, 7).fill(BRAND.primary);
  doc.restore();

  const logoPath = resolveLogoPath();
  if (logoPath) {
    try { doc.image(logoPath, 50, startY, { fit: [54, 54] }); } catch (_err) { }
  }

  const textX = 120;
  doc.fillColor(BRAND.primaryDark).font('Helvetica-Bold').fontSize(20).text('Sachem Work Permits', textX, startY + 2);
  doc.fillColor('#0f172a').font('Helvetica-Bold').fontSize(14).text(subtitle, textX, startY + 30);
  doc.fillColor(BRAND.muted).font('Helvetica').fontSize(9).text('Permit & Safety Documentation', textX, startY + 50);
  doc.y = 145;
}

function renderPermitFieldsPdf(doc, permit) {
  const schema = fieldSchemaForType(permit.permit_type || PERMIT_TYPES.GENERAL_WORK_SAFE);
  const values = parsePermitFieldsJson(permit.permit_fields_json);
  if (!schema.length) return;

  const grouped = schema.reduce((acc, f) => {
    const section = f.section || 'Form';
    if (!acc[section]) acc[section] = [];
    acc[section].push(f);
    return acc;
  }, {});

  Object.entries(grouped).forEach(([section, fields]) => {
    ensurePdfSpace(doc, 36);
    doc.moveDown(0.5);
    const sectionTop = doc.y;
    doc.roundedRect(50, sectionTop, 495, 24, 6).fill(BRAND.bgSoft);
    doc.fillColor(BRAND.primaryDark).font('Helvetica-Bold').fontSize(11).text(section, 60, sectionTop + 7);
    doc.y = sectionTop + 30;

    fields.forEach((f) => {
      if (section === 'Section 3 – Hazard Evaluation' && f.key === 'mobile_equipment_cert_initials' && !Number(values.haz_mobile_equipment)) return;
      let value = values[f.key];
      if (f.type === 'checkbox') value = Number(value) ? 'Yes' : 'No';
      if (value === undefined || value === null || String(value).trim() === '') value = '—';

      ensurePdfSpace(doc, 16);
      doc.font('Helvetica-Bold').fontSize(9).fillColor('#0f172a').text(`${f.label}:`, 60, doc.y, { continued: true });
      doc.font('Helvetica').fontSize(9).fillColor('#334155').text(` ${value}`);
    });

    if (section === 'Section 1 – Additional Work Permits') {
      const req = parseRequiredPermitsJson(permit.required_permits_json).map((t) => permitTypeLabel(t));
      ensurePdfSpace(doc, 16);
      doc.font('Helvetica-Bold').fontSize(9).fillColor('#0f172a').text('Selected additional permits:', 60, doc.y, { continued: true });
      doc.font('Helvetica').fontSize(9).fillColor('#334155').text(` ${req.length ? req.join(', ') : 'None'}`);
    }
  });
}

function generatePermitPdf(res, permit) {
  const doc = new PDFDocument({ margin: 50, size: 'A4' });
  const generatedAt = new Date().toLocaleString();
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="permit-${permit.id}.pdf"`);
  doc.pipe(res);

  drawHeader(doc, `Permit #${permit.id}`);
  doc.roundedRect(50, doc.y, 495, 64, 8).fillAndStroke('#ffffff', BRAND.border);
  const permitFields = parsePermitFieldsJson(permit.permit_fields_json);
  const permitNo = permitFields.general_permit_no || `Permit-${permit.id}`;

  doc.fillColor(BRAND.primaryDark).font('Helvetica-Bold').fontSize(18).text(permit.title || 'Untitled permit', 64, doc.y + 10, { width: 465 });
  doc.fillColor(BRAND.muted).font('Helvetica').fontSize(10).text(`Permit No: ${permitNo} • Status: ${formatStatusLabel(permit.status)} • Revision: ${permit.revision}`, 64, doc.y + 36);
  doc.y += 80;
  doc.font('Helvetica').fontSize(11).fillColor('#0f172a');
  doc.text(`Site: ${permit.site || '-'}`);
  doc.text(`Permit End Date: ${permit.permit_date || '-'}`);
  doc.text(`Created By: ${permit.created_by_name}`);
  doc.text(`Updated By: ${permit.updated_by_name}`);
  doc.text(`Locked: ${permit.is_locked ? 'Yes' : 'No'}`);
  if (permit.approver_name) doc.text(`Approved By: ${permit.approver_name} (${formatDate(permit.approved_at)})`);
  if (permit.signature_text) doc.text(`Signature: ${permit.signature_text}`);

  renderPermitFieldsPdf(doc, permit);

  drawFooter(doc, generatedAt);
  doc.end();
}

app.get('/', requireAuth, (_req, res) => res.redirect('/permits'));

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/permits');
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).render('login', { error: 'Invalid username or password.' });
  }
  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.redirect('/permits');
});

app.post('/logout', requireAuth, (req, res) => req.session.destroy(() => res.redirect('/login')));

app.get('/admin/users', requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare(`SELECT id, username, role, created_at FROM users ORDER BY created_at DESC`).all();
  const success = req.query.created ? 'User created successfully.' : null;
  res.render('admin-users', { users, error: null, success, roles: Object.values(ROLES) });
});

app.post('/admin/users', requireAuth, requireAdmin, (req, res) => {
  const { username = '', password = '', role = '' } = req.body;
  const cleanUsername = String(username).trim();
  const cleanRole = String(role).trim();

  const users = db.prepare(`SELECT id, username, role, created_at FROM users ORDER BY created_at DESC`).all();

  if (!cleanUsername || !password || !Object.values(ROLES).includes(cleanRole)) {
    return res.status(400).render('admin-users', { users, error: 'Username, password, and valid role are required.', success: null, roles: Object.values(ROLES) });
  }

  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(cleanUsername);
  if (exists) {
    return res.status(400).render('admin-users', { users, error: 'Username already exists.', success: null, roles: Object.values(ROLES) });
  }

  const hash = bcrypt.hashSync(password, 12);
  db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run(cleanUsername, hash, cleanRole);
  return res.redirect('/admin/users?created=1');
});

app.get('/permits', requireAuth, (req, res) => {
  const { filters, where, params } = getFilterContext(req.query);
  const permits = db
    .prepare(
      `SELECT p.*, c.username AS created_by_name, u.username AS updated_by_name
       FROM permits p
       JOIN users c ON c.id = p.created_by
       JOIN users u ON u.id = p.updated_by
       ${where}
       ORDER BY p.updated_at DESC`
    )
    .all(...params)
    .map((p) => {
      const fields = parsePermitFieldsJson(p.permit_fields_json);
      return {
        ...p,
        permit_number: fields.general_permit_no || '',
        actions: {
          canEdit: canEditFields(req.session.user, p),
          canDelete: canDeletePermit(req.session.user),
          canTransition: transitionActions(req.session.user, p),
        },
      };
    });

  const statusCounts = statusOptions().reduce((acc, status) => ({ ...acc, [status]: permits.filter((p) => p.status === status).length }), {});

  res.render('permits', {
    permits,
    filters,
    statusOptions: statusOptions(),
    permissions: {
      canCreate: canCreatePermit(req.session.user),
    },
    stats: { total: permits.length, statusCounts },
  });
});

app.get('/permits/new', requireAuth, (req, res) => {
  if (!canCreatePermit(req.session.user)) return res.status(403).send('Forbidden');
  res.render('permit-form', {
    permit: { title: 'General safe work permit', site: 'Cleburne', permit_type: PERMIT_TYPES.GENERAL_WORK_SAFE },
    action: '/permits',
    error: null,
    permitFieldSchema: fieldSchemaForType(PERMIT_TYPES.GENERAL_WORK_SAFE),
    permitFieldValues: { general_permit_no: generateNextGswpTitle() },
    supplementalPermitTypes: SUPPLEMENTAL_PERMIT_TYPES,
    permitTypeLabels: PERMIT_TYPE_LABELS,
  });
});

app.post('/permits', requireAuth, (req, res) => {
  if (!canCreatePermit(req.session.user)) return res.status(403).send('Forbidden');
  const { description = '', permit_date } = req.body;
  const title = 'General safe work permit';
  const site = 'Cleburne';
  const requiredPermits = normalizeRequiredPermits(req.body.required_permits);
  const permitFields = extractPermitFieldsFromBody(req.body, PERMIT_TYPES.GENERAL_WORK_SAFE);
  permitFields.general_permit_no = generateNextGswpTitle();
  const finalDescription = (description || '').trim() || templateTextForType(PERMIT_TYPES.GENERAL_WORK_SAFE);
  const startDate = permitFields.start_date || '';

  if (!permit_date) {
    return res.status(400).render('permit-form', {
      permit: { ...req.body, permit_type: PERMIT_TYPES.GENERAL_WORK_SAFE, required_permits_json: JSON.stringify(requiredPermits) },
      action: '/permits',
      error: 'Permit end date is required.',
      supplementalPermitTypes: SUPPLEMENTAL_PERMIT_TYPES,
      permitTypeLabels: PERMIT_TYPE_LABELS,
      permitFieldSchema: fieldSchemaForType(PERMIT_TYPES.GENERAL_WORK_SAFE),
      permitFieldValues: permitFields,
    });
  }

  if (startDate && startDate > permit_date) {
    return res.status(400).render('permit-form', {
      permit: { ...req.body, permit_type: PERMIT_TYPES.GENERAL_WORK_SAFE, required_permits_json: JSON.stringify(requiredPermits) },
      action: '/permits',
      error: 'Start date must be before or equal to permit end date.',
      supplementalPermitTypes: SUPPLEMENTAL_PERMIT_TYPES,
      permitTypeLabels: PERMIT_TYPE_LABELS,
      permitFieldSchema: fieldSchemaForType(PERMIT_TYPES.GENERAL_WORK_SAFE),
      permitFieldValues: permitFields,
    });
  }

  const gswpValidationError = validatePermitFields(PERMIT_TYPES.GENERAL_WORK_SAFE, permitFields);
  if (gswpValidationError) {
    return res.status(400).render('permit-form', {
      permit: { ...req.body, permit_type: PERMIT_TYPES.GENERAL_WORK_SAFE, required_permits_json: JSON.stringify(requiredPermits) },
      action: '/permits',
      error: gswpValidationError,
      supplementalPermitTypes: SUPPLEMENTAL_PERMIT_TYPES,
      permitTypeLabels: PERMIT_TYPE_LABELS,
      permitFieldSchema: fieldSchemaForType(PERMIT_TYPES.GENERAL_WORK_SAFE),
      permitFieldValues: permitFields,
    });
  }

  const result = db
    .prepare(
      `INSERT INTO permits (title, description, site, status, permit_date, created_by, updated_by, permit_type, required_permits_json, permit_fields_json)
       VALUES (?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?)`
    )
    .run(
      title,
      finalDescription,
      site,
      permit_date,
      req.session.user.id,
      req.session.user.id,
      PERMIT_TYPES.GENERAL_WORK_SAFE,
      JSON.stringify(requiredPermits),
      JSON.stringify(permitFields)
    );

  const parent = getPermitById(result.lastInsertRowid);
  syncRequiredChildPermits(parent, requiredPermits, req.session.user.id);

  logAudit(result.lastInsertRowid, 'create', null, { title, description: finalDescription, site, status: 'draft', permit_date, permit_type: PERMIT_TYPES.GENERAL_WORK_SAFE, required_permits: requiredPermits, revision: 1 }, req.session.user.id);
  res.redirect(`/permits/${result.lastInsertRowid}`);
});

app.get('/permits/:id(\\d+)/edit', requireAuth, (req, res) => {
  const permit = getPermitById(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');
  if (!canEditFields(req.session.user, permit)) return res.status(403).send('Forbidden');
  res.render('permit-form', {
    permit,
    action: `/permits/${permit.id}`,
    error: null,
    supplementalPermitTypes: SUPPLEMENTAL_PERMIT_TYPES,
    permitTypeLabels: PERMIT_TYPE_LABELS,
    permitFieldSchema: fieldSchemaForType(permit.permit_type || PERMIT_TYPES.GENERAL_WORK_SAFE),
    permitFieldValues: parsePermitFieldsJson(permit.permit_fields_json),
  });
});

app.post('/permits/:id(\\d+)', requireAuth, (req, res) => {
  const permit = getPermitById(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');
  if (!canEditFields(req.session.user, permit)) return res.status(403).send('Forbidden');

  const { description = '', permit_date } = req.body;
  const permitType = permit.permit_type || PERMIT_TYPES.GENERAL_WORK_SAFE;
  const title = permitType === PERMIT_TYPES.GENERAL_WORK_SAFE ? 'General safe work permit' : permit.title;
  const site = permitType === PERMIT_TYPES.GENERAL_WORK_SAFE ? 'Cleburne' : (req.body.site || permit.site);
  const requiredPermits = isGeneralPermit(permit) ? normalizeRequiredPermits(req.body.required_permits) : [];
  const permitFields = extractPermitFieldsFromBody(req.body, permitType);
  if (permitType === PERMIT_TYPES.GENERAL_WORK_SAFE) {
    const existingNumber = parsePermitFieldsJson(permit.permit_fields_json).general_permit_no;
    permitFields.general_permit_no = existingNumber || generateNextGswpTitle();
  }

  if (!permit_date) {
    return res.status(400).render('permit-form', {
      permit: { ...permit, ...req.body, required_permits_json: JSON.stringify(requiredPermits) },
      action: `/permits/${req.params.id}`,
      error: 'Permit end date is required.',
      supplementalPermitTypes: SUPPLEMENTAL_PERMIT_TYPES,
      permitTypeLabels: PERMIT_TYPE_LABELS,
      permitFieldSchema: fieldSchemaForType(permitType),
      permitFieldValues: permitFields,
    });
  }

  const startDate = permitFields.start_date || '';
  if (permitType === PERMIT_TYPES.GENERAL_WORK_SAFE && startDate && startDate > permit_date) {
    return res.status(400).render('permit-form', {
      permit: { ...permit, ...req.body, required_permits_json: JSON.stringify(requiredPermits) },
      action: `/permits/${req.params.id}`,
      error: 'Start date must be before or equal to permit end date.',
      supplementalPermitTypes: SUPPLEMENTAL_PERMIT_TYPES,
      permitTypeLabels: PERMIT_TYPE_LABELS,
      permitFieldSchema: fieldSchemaForType(permitType),
      permitFieldValues: permitFields,
    });
  }

  const gswpValidationError = validatePermitFields(permitType, permitFields);
  if (gswpValidationError) {
    return res.status(400).render('permit-form', {
      permit: { ...permit, ...req.body, required_permits_json: JSON.stringify(requiredPermits) },
      action: `/permits/${req.params.id}`,
      error: gswpValidationError,
      supplementalPermitTypes: SUPPLEMENTAL_PERMIT_TYPES,
      permitTypeLabels: PERMIT_TYPE_LABELS,
      permitFieldSchema: fieldSchemaForType(permitType),
      permitFieldValues: permitFields,
    });
  }

  db.prepare(
    `UPDATE permits
     SET title = ?, description = ?, site = ?, permit_date = ?, required_permits_json = ?, permit_fields_json = ?, updated_by = ?, updated_at = datetime('now')
     WHERE id = ?`
  ).run(title, description, site, permit_date, JSON.stringify(requiredPermits), JSON.stringify(permitFields), req.session.user.id, req.params.id);

  const updated = getPermitById(req.params.id);
  syncRequiredChildPermits(updated, requiredPermits, req.session.user.id);

  logAudit(req.params.id, 'update', pickSnapshot(permit), pickSnapshot(updated), req.session.user.id);
  res.redirect(`/permits/${req.params.id}`);
});

app.post('/permits/:id(\\d+)/populate-template', requireAuth, (req, res) => {
  const permit = getPermitById(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');
  if (!canEditFields(req.session.user, permit)) return res.status(403).send('Forbidden');

  const templateDescription = templateTextForType(permit.permit_type || PERMIT_TYPES.GENERAL_WORK_SAFE);
  if (!templateDescription) return res.redirect(`/permits/${req.params.id}`);

  db.prepare(`UPDATE permits SET description = ?, updated_by = ?, updated_at = datetime('now') WHERE id = ?`).run(
    templateDescription,
    req.session.user.id,
    req.params.id
  );

  const updated = getPermitById(req.params.id);
  logAudit(req.params.id, 'populate_template', pickSnapshot(permit), pickSnapshot(updated), req.session.user.id);
  res.redirect(`/permits/${req.params.id}`);
});

app.post('/permits/:id(\\d+)/transition', requireAuth, (req, res) => {
  const permit = getPermitById(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');

  const action = (req.body.action || '').trim();
  const allowed = transitionActions(req.session.user, permit);
  if (!allowed.includes(action)) return res.status(403).send('Transition not allowed');

  const transitionRequirementError = validateGeneralTransitionRequirements(permit, action);
  if (transitionRequirementError) return res.status(400).send(transitionRequirementError);

  const tx = db.transaction(() => {
    if (action === 'submit') {
      db.prepare(`UPDATE permits SET status = 'submitted', updated_by = ?, updated_at = datetime('now') WHERE id = ?`).run(req.session.user.id, permit.id);
    } else if (action === 'approve') {
      const signature = (req.body.signature_text || '').trim();
      if (!signature) throw new Error('Signature is required to approve');
      const approverName = req.session.user.username;
      db.prepare(
        `UPDATE permits
         SET status = 'approved', approved_by = ?, approved_at = datetime('now'), approver_name = ?, signature_text = ?, is_locked = 1,
             updated_by = ?, updated_at = datetime('now')
         WHERE id = ?`
      ).run(req.session.user.id, approverName, signature, req.session.user.id, permit.id);
    } else if (action === 'close') {
      db.prepare(`UPDATE permits SET status = 'closed', is_locked = 1, updated_by = ?, updated_at = datetime('now') WHERE id = ?`).run(req.session.user.id, permit.id);
    } else if (action === 'reopen') {
      db.prepare(
        `UPDATE permits
         SET status = 'draft', is_locked = 0, revision = revision + 1,
             approved_by = NULL, approved_at = NULL, approver_name = NULL, signature_text = NULL,
             updated_by = ?, updated_at = datetime('now')
         WHERE id = ?`
      ).run(req.session.user.id, permit.id);
    }

    const updated = getPermitById(permit.id);
    logAudit(permit.id, `transition_${action}`, pickSnapshot(permit), pickSnapshot(updated), req.session.user.id);
  });

  try {
    tx();
    res.redirect(`/permits/${permit.id}`);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.post('/permits/:id(\\d+)/delete', requireAuth, (req, res) => {
  if (!canDeletePermit(req.session.user)) return res.status(403).send('Forbidden');
  const permit = getPermitById(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');

  const attachmentRows = db.prepare('SELECT * FROM permit_attachments WHERE permit_id = ?').all(permit.id);
  for (const a of attachmentRows) {
    const fullPath = path.join(uploadsDir, a.stored_name);
    if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
  }
  db.prepare('DELETE FROM permit_attachments WHERE permit_id = ?').run(permit.id);
  db.prepare('DELETE FROM permits WHERE id = ?').run(permit.id);
  logAudit(permit.id, 'delete', pickSnapshot(permit), null, req.session.user.id);
  res.redirect('/permits');
});

app.get('/permits/:id(\\d+)', requireAuth, (req, res) => {
  const permit = getPermitById(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');

  const recentAudit = db
    .prepare(
      `SELECT a.changed_at, a.action, u.username FROM permit_audit a JOIN users u ON u.id = a.changed_by WHERE a.permit_id = ? ORDER BY a.changed_at DESC LIMIT 7`
    )
    .all(req.params.id);

  const attachments = db
    .prepare(
      `SELECT pa.*, u.username AS uploaded_by_name FROM permit_attachments pa JOIN users u ON u.id = pa.uploaded_by WHERE pa.permit_id = ? ORDER BY pa.created_at DESC`
    )
    .all(req.params.id);

  const requiredPermitTypes = parseRequiredPermitsJson(permit.required_permits_json);
  const childPermits = getChildPermits(permit.id);
  const permitFieldSchema = fieldSchemaForType(permit.permit_type || PERMIT_TYPES.GENERAL_WORK_SAFE);
  const permitFieldValues = parsePermitFieldsJson(permit.permit_fields_json);

  res.render('permit-detail', {
    permit,
    recentAudit,
    attachments,
    permitTypeLabels: PERMIT_TYPE_LABELS,
    requiredPermitTypes,
    childPermits,
    permitFieldSchema,
    permitFieldValues,
    permissions: {
      canEdit: canEditFields(req.session.user, permit),
      canDeletePermit: canDeletePermit(req.session.user),
      canUpload: canEditFields(req.session.user, permit) || hasAnyRole(req.session.user, [ROLES.ADMIN, ROLES.SUPERVISOR]),
      canDeleteAttachment: canDeleteAttachment(req.session.user),
      transitions: transitionActions(req.session.user, permit),
    },
  });
});

app.post('/permits/:id(\\d+)/attachments', requireAuth, upload.single('attachment'), (req, res) => {
  const permit = getPermitById(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');
  const canUpload = canEditFields(req.session.user, permit) || hasAnyRole(req.session.user, [ROLES.ADMIN, ROLES.SUPERVISOR]);
  if (!canUpload) return res.status(403).send('Forbidden');
  if (!req.file) return res.status(400).send('No file uploaded');

  const originalName = path.basename(req.file.originalname).replace(/[^a-zA-Z0-9._ -]/g, '_').slice(0, 140);
  db.prepare(
    `INSERT INTO permit_attachments (permit_id, original_name, stored_name, mime_type, size_bytes, uploaded_by)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(permit.id, originalName, req.file.filename, req.file.mimetype, req.file.size, req.session.user.id);

  db.prepare(`UPDATE permits SET updated_by = ?, updated_at = datetime('now') WHERE id = ?`).run(req.session.user.id, permit.id);
  logAudit(permit.id, 'attachment_upload', null, { original_name: originalName, size_bytes: req.file.size, mime_type: req.file.mimetype }, req.session.user.id);
  res.redirect(`/permits/${permit.id}`);
});

app.get('/permits/:id(\\d+)/attachments/:attachmentId(\\d+)', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM permit_attachments WHERE id = ? AND permit_id = ?').get(req.params.attachmentId, req.params.id);
  if (!row) return res.status(404).send('Attachment not found');
  const fullPath = path.join(uploadsDir, row.stored_name);
  if (!fs.existsSync(fullPath)) return res.status(404).send('File missing on server');
  res.download(fullPath, row.original_name);
});

app.post('/permits/:id(\\d+)/attachments/:attachmentId(\\d+)/delete', requireAuth, (req, res) => {
  if (!canDeleteAttachment(req.session.user)) return res.status(403).send('Forbidden');
  const row = db.prepare('SELECT * FROM permit_attachments WHERE id = ? AND permit_id = ?').get(req.params.attachmentId, req.params.id);
  if (!row) return res.status(404).send('Attachment not found');

  db.prepare('DELETE FROM permit_attachments WHERE id = ?').run(row.id);
  const fullPath = path.join(uploadsDir, row.stored_name);
  if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);

  db.prepare(`UPDATE permits SET updated_by = ?, updated_at = datetime('now') WHERE id = ?`).run(req.session.user.id, req.params.id);
  logAudit(req.params.id, 'attachment_delete', { original_name: row.original_name, size_bytes: row.size_bytes }, null, req.session.user.id);
  res.redirect(`/permits/${req.params.id}`);
});

app.get('/permits/:id(\\d+)/audit', requireAuth, (req, res) => {
  const permit = db.prepare('SELECT id FROM permits WHERE id = ?').get(req.params.id);
  const auditRows = db
    .prepare(`SELECT a.*, u.username FROM permit_audit a JOIN users u ON u.id = a.changed_by WHERE a.permit_id = ? ORDER BY a.changed_at DESC`)
    .all(req.params.id)
    .map((row) => ({
      ...row,
      changedAtPretty: formatDate(row.changed_at),
      actionLabel: formatStatusLabel(row.action),
      changes: toFriendlyChanges(row.old_values, row.new_values),
      oldRaw: row.old_values,
      newRaw: row.new_values,
    }));

  if (!permit && auditRows.length === 0) return res.status(404).send('Permit not found');
  res.render('audit', { permitId: req.params.id, auditRows });
});

app.get('/permits/:id(\\d+)/export.pdf', requireAuth, (req, res) => {
  const permit = getPermitById(req.params.id);
  if (!permit) return res.status(404).send('Permit not found');
  generatePermitPdf(res, permit);
});

app.get('/permits/export.csv', requireAuth, (req, res) => {
  const { where, params } = getFilterContext(req.query);
  const whereNoAlias = where.replace(/p\./g, '');
  const rows = db
    .prepare(`SELECT id,title,description,site,status,permit_type,parent_permit_id,required_permits_json,permit_date,revision,is_locked,approver_name,approved_at,created_at,updated_at FROM permits ${whereNoAlias} ORDER BY updated_at DESC`)
    .all(...params);

  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const header = ['id', 'title', 'description', 'site', 'status', 'permit_type', 'parent_permit_id', 'required_permits_json', 'permit_date', 'revision', 'is_locked', 'approver_name', 'approved_at', 'created_at', 'updated_at'];
  const csv = [header.join(',')].concat(rows.map((row) => header.map((h) => esc(row[h])).join(','))).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="permits.csv"');
  res.send(csv);
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError || err.message === 'File type not allowed') {
    return res.status(400).send(`Upload failed: ${err.message}`);
  }
  return res.status(500).send('Unexpected server error');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Work permits app running on http://0.0.0.0:${PORT}`);
});
