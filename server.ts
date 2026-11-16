import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import fs from 'fs';
import dotenv from 'dotenv';
import { initializeApp, getApps } from 'firebase/app';
import {
  getFirestore,
  doc,
  getDoc,
  setDoc,
  updateDoc,
  collection,
  query,
  where,
  getDocs,
  runTransaction,
} from 'firebase/firestore';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '2mb' }));

// Session token signing secret (HMAC-SHA256)
const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.createHash('sha256').update(`sdlr-sangurur-${process.cwd()}`).digest('hex');

const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

interface SessionPayload {
  sub: string;
  role: 'learner';
  digitalId: string;
  iat: number;
  exp: number;
}

interface TeacherSessionPayload {
  sub: string;
  role: 'teacher' | 'admin' | 'super_admin';
  username: string;
  iat: number;
  exp: number;
}

function createSessionToken(learnerDocId: string, digitalId: string): { token: string; expiresAt: number } {
  const now = Date.now();
  const expiresAt = now + SESSION_TTL_MS;
  const payload: SessionPayload = {
    sub: learnerDocId,
    role: 'learner',
    digitalId,
    iat: now,
    exp: expiresAt,
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf-8').toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
  return { token: `${encoded}.${sig}`, expiresAt };
}

function verifySessionToken(token: string): SessionPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [encoded, sig] = parts;
    const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
    const sigBuf = Buffer.from(sig);
    const expectedBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
      return null;
    }
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf-8')) as SessionPayload;
    if (!payload.sub || payload.role !== 'learner' || !payload.exp || Date.now() > payload.exp) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

function createTeacherSessionToken(
  teacherUid: string,
  username: string,
  role: 'teacher' | 'admin' | 'super_admin'
): { token: string; expiresAt: number } {
  const now = Date.now();
  const expiresAt = now + SESSION_TTL_MS;
  const payload: TeacherSessionPayload = {
    sub: teacherUid,
    role,
    username,
    iat: now,
    exp: expiresAt,
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf-8').toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
  return { token: `${encoded}.${sig}`, expiresAt };
}

function verifyTeacherSessionToken(token: string): TeacherSessionPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [encoded, sig] = parts;
    const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
    const sigBuf = Buffer.from(sig);
    const expectedBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
      return null;
    }
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf-8')) as TeacherSessionPayload;
    if (
      !payload.sub ||
      !['teacher', 'admin', 'super_admin'].includes(payload.role) ||
      !payload.exp ||
      Date.now() > payload.exp
    ) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

// Initialize server-side Firebase
let db: any = null;
try {
  const configRaw = fs.readFileSync(path.resolve(__dirname, 'firebase-applet-config.json'), 'utf-8');
  const firebaseConfig = JSON.parse(configRaw);
  const fbApp = getApps().length === 0 ? initializeApp(firebaseConfig, 'SERVER_APP') : getApps()[0];
  db = getFirestore(fbApp, firebaseConfig.firestoreDatabaseId);
  console.log('Server Firestore initialized with DB:', firebaseConfig.firestoreDatabaseId);
} catch (e) {
  console.warn('Could not initialize server Firestore from config:', e);
}

// Helpers for secure password hashing
function generateSalt(): string {
  return crypto.randomBytes(16).toString('hex');
}

function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
}

// Current Nairobi local date string YYYY-MM-DD
function getNairobiDateString(): string {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Africa/Nairobi',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).formatToParts(new Date());

  const year = parts.find((p) => p.type === 'year')?.value;
  const month = parts.find((p) => p.type === 'month')?.value;
  const day = parts.find((p) => p.type === 'day')?.value;
  return `${year}-${month}-${day}`;
}

const DEFAULT_INITIAL_PASSWORD = '123456789';
const DEFAULT_TEACHER_UID = 'teacher_default_staff';
const DEFAULT_TEACHER_USERNAME = 'Teacher';
const DEFAULT_TEACHER_PASSWORD = process.env.DEFAULT_TEACHER_PASSWORD || 'Sangurur@2026';

let defaultTeacherEnsured = false;

async function ensureDefaultTeacherAccount(): Promise<void> {
  if (!db || defaultTeacherEnsured) return;
  try {
    const now = new Date().toISOString();
    const teacherRef = doc(db, 'teachers', DEFAULT_TEACHER_UID);
    const teacherSnap = await getDoc(teacherRef);
    if (!teacherSnap.exists()) {
      await setDoc(teacherRef, {
        uid: DEFAULT_TEACHER_UID,
        username: DEFAULT_TEACHER_USERNAME,
        email: 'teacher@sangururschool.edu.ke',
        fullName: 'Sangurur Staff Teacher',
        role: 'teacher',
        active: true,
        createdAt: now,
        updatedAt: now,
      });
    }

    const credRef = doc(db, 'teacherCredentials', DEFAULT_TEACHER_UID);
    const credSnap = await getDoc(credRef);
    if (!credSnap.exists()) {
      const salt = generateSalt();
      const passwordHash = hashPassword(DEFAULT_TEACHER_PASSWORD, salt);
      await setDoc(credRef, {
        id: DEFAULT_TEACHER_UID,
        username: DEFAULT_TEACHER_USERNAME,
        teacherUid: DEFAULT_TEACHER_UID,
        passwordHash,
        salt,
        active: true,
        createdAt: now,
        updatedAt: now,
      });
    }
    defaultTeacherEnsured = true;
  } catch (err) {
    console.warn('Default teacher bootstrap notice:', err);
  }
}

void ensureDefaultTeacherAccount();

// Atomic, transaction-safe sequential Digital ID allocation: SG-LRN-2026-001
async function allocateDigitalIds(count: number): Promise<string[]> {
  if (!db) {
    return Array.from({ length: count }, (_, idx) => `SG-LRN-2026-${String(idx + 1).padStart(3, '0')}`);
  }

  const counterRef = doc(db, 'counters', 'learner_digital_id_2026');

  // Bootstrap max existing sequence if counter doc does not exist yet
  let bootstrapMax = 0;
  const preSnap = await getDoc(counterRef);
  if (!preSnap.exists()) {
    const learnersSnap = await getDocs(collection(db, 'learners'));
    learnersSnap.forEach((d: any) => {
      const data = d.data();
      const idStr = String(data.digitalId || data.learnerId || data.username || '');
      const match = idStr.match(/^SG-LRN-2026-(\d+)$/i) || idStr.match(/(\d+)$/);
      if (match) {
        const num = parseInt(match[1], 10);
        if (!isNaN(num) && num > bootstrapMax) {
          bootstrapMax = num;
        }
      }
    });
  }

  const startSeq = await runTransaction(db, async (transaction) => {
    const counterDoc = await transaction.get(counterRef);
    const currentSeq = counterDoc.exists()
      ? Math.max(Number(counterDoc.data().lastSeq) || 0, bootstrapMax)
      : bootstrapMax;
    const nextLast = currentSeq + count;
    transaction.set(counterRef, {
      lastSeq: nextLast,
      updatedAt: new Date().toISOString(),
    });
    return currentSeq + 1;
  });

  return Array.from({ length: count }, (_, i) => `SG-LRN-2026-${String(startSeq + i).padStart(3, '0')}`);
}

async function writeAuditLog(entry: {
  actorId: string;
  actorName: string;
  actorRole: string;
  action: string;
  targetEntity: string;
  targetId: string;
  details: string;
}) {
  if (!db) return;
  try {
    const logId = `log_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    await setDoc(doc(db, 'auditLogs', logId), {
      id: logId,
      ...entry,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.warn('Audit log write notice:', err);
  }
}

interface AuthenticatedLearnerRequest extends Request {
  authLearner?: any;
}

async function requireLearnerAuth(req: AuthenticatedLearnerRequest, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    if (!token) {
      return res.status(401).json({ error: 'Authentication required. Please sign in again.' });
    }
    const payload = verifySessionToken(token);
    if (!payload) {
      return res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
    }
    if (!db) {
      return res.status(503).json({ error: 'Database service unavailable' });
    }
    const snap = await getDoc(doc(db, 'learners', payload.sub));
    if (!snap.exists()) {
      return res.status(401).json({ error: 'Learner account no longer exists.' });
    }
    const data = snap.data();
    if (data.status === 'INACTIVE' || data.active === false) {
      return res.status(403).json({ error: 'Learner account is inactive. Please contact your school administrator.' });
    }
    req.authLearner = {
      id: snap.id,
      digitalId: data.digitalId || data.learnerId,
      learnerId: data.digitalId || data.learnerId,
      fullName: data.fullName,
      username: data.username || data.digitalId || data.learnerId,
      assignedCohortIds: data.assignedCohortIds || [],
      mustChangePassword: data.mustChangePassword ?? data.isFirstLogin ?? true,
      isFirstLogin: data.mustChangePassword ?? data.isFirstLogin ?? true,
      status: data.status || 'ACTIVE',
      gender: data.gender,
      age: data.age,
      passwordHash: data.passwordHash,
      salt: data.salt,
    };
    next();
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Session validation error' });
  }
}

// ---------------- API ROUTES ----------------

// Health Check
app.get('/api/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    app: 'Sangurur Digital Learner Register (SDLR)',
    school: 'Sangurur Comprehensive School',
    motto: 'THINK, CODE, CHANGE THE WORLD',
    timezone: 'Africa/Nairobi',
    serverTimeEAT: new Date().toLocaleString('en-KE', { timeZone: 'Africa/Nairobi' }),
  });
});

// Teacher Authentication: Username + Password Login
app.post('/api/auth/teacher-login', async (req: Request, res: Response) => {
  try {
    const username = req.body.username;
    const password = req.body.password;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }

    if (!db) {
      return res.status(503).json({ error: 'Database service unavailable' });
    }

    await ensureDefaultTeacherAccount();

    const cleanUsername = String(username).trim();
    const credDocId =
      cleanUsername.toLowerCase() === DEFAULT_TEACHER_USERNAME.toLowerCase()
        ? DEFAULT_TEACHER_UID
        : `teacher_${cleanUsername.toLowerCase().replace(/[^a-z0-9_-]/g, '_')}`;

    const credSnap = await getDoc(doc(db, 'teacherCredentials', credDocId));
    if (!credSnap.exists()) {
      return res.status(401).json({ error: 'Invalid teacher username or password.' });
    }

    const credData = credSnap.data();
    if (credData.active === false) {
      return res.status(403).json({ error: 'Teacher account is inactive. Please contact the school administrator.' });
    }

    const expectedUsername = String(credData.username || DEFAULT_TEACHER_USERNAME);
    if (cleanUsername.toLowerCase() !== expectedUsername.toLowerCase()) {
      return res.status(401).json({ error: 'Invalid teacher username or password.' });
    }

    const computedHash = hashPassword(String(password), String(credData.salt || ''));
    const computedBuf = Buffer.from(computedHash, 'utf8');
    const storedBuf = Buffer.from(String(credData.passwordHash || ''), 'utf8');
    const isPasswordValid =
      computedBuf.length > 0 &&
      computedBuf.length === storedBuf.length &&
      crypto.timingSafeEqual(computedBuf, storedBuf);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid teacher username or password.' });
    }

    const teacherUid = String(credData.teacherUid || DEFAULT_TEACHER_UID);
    const teacherSnap = await getDoc(doc(db, 'teachers', teacherUid));
    const teacherData = teacherSnap.exists() ? teacherSnap.data() : null;

    if (teacherData && teacherData.active === false) {
      return res.status(403).json({ error: 'Teacher profile is inactive. Please contact the school administrator.' });
    }

    const teacherRole: 'teacher' | 'admin' | 'super_admin' =
      teacherData?.role === 'admin' || teacherData?.role === 'super_admin'
        ? teacherData.role
        : 'teacher';

    const teacherProfile = {
      uid: teacherUid,
      username: expectedUsername,
      email: teacherData?.email || 'teacher@sangururschool.edu.ke',
      fullName: teacherData?.fullName || 'Sangurur Staff Teacher',
      role: teacherRole,
      phone: teacherData?.phone,
      active: teacherData?.active ?? true,
      createdAt: teacherData?.createdAt || new Date().toISOString(),
      updatedAt: teacherData?.updatedAt,
    };

    const { token, expiresAt } = createTeacherSessionToken(teacherUid, expectedUsername, teacherRole);

    await writeAuditLog({
      actorId: teacherProfile.uid,
      actorName: teacherProfile.fullName,
      actorRole: teacherRole,
      action: 'TEACHER_LOGIN',
      targetEntity: 'teacher',
      targetId: teacherProfile.uid,
      details: `Staff teacher authenticated with username '${expectedUsername}'.`,
    });

    return res.json({
      success: true,
      teacher: teacherProfile,
      token,
      expiresAt,
    });
  } catch (err: any) {
    console.error('Teacher login error:', err);
    return res.status(500).json({ error: err.message || 'Internal teacher login error' });
  }
});

// Validate and refresh active teacher credential session against Firestore
app.get('/api/auth/teacher-session', async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    if (!token) {
      return res.status(401).json({ error: 'Teacher authentication required.' });
    }

    const payload = verifyTeacherSessionToken(token);
    if (!payload) {
      return res.status(401).json({ error: 'Teacher session expired or invalid. Please sign in again.' });
    }

    if (!db) {
      return res.status(503).json({ error: 'Database service unavailable' });
    }

    const teacherSnap = await getDoc(doc(db, 'teachers', payload.sub));
    if (!teacherSnap.exists()) {
      return res.status(401).json({ error: 'Teacher account no longer exists.' });
    }

    const teacherData = teacherSnap.data();
    if (teacherData.active === false) {
      return res.status(403).json({ error: 'Teacher account is inactive.' });
    }

    return res.json({
      success: true,
      teacher: {
        uid: teacherSnap.id,
        username: teacherData.username || payload.username,
        email: teacherData.email || 'teacher@sangururschool.edu.ke',
        fullName: teacherData.fullName || 'Sangurur Staff Teacher',
        role: teacherData.role || 'teacher',
        phone: teacherData.phone,
        active: teacherData.active ?? true,
        createdAt: teacherData.createdAt || new Date().toISOString(),
        updatedAt: teacherData.updatedAt,
      },
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Teacher session validation error' });
  }
});

// Learner Authentication: Digital ID (Username) + Password Login
app.post('/api/auth/learner-login', async (req: Request, res: Response) => {
  try {
    const username = req.body.username || req.body.digitalId;
    const password = req.body.password;
    if (!username || !password) {
      return res.status(400).json({ error: 'Digital ID / Username and password are required' });
    }

    if (!db) {
      return res.status(503).json({ error: 'Database service unavailable' });
    }

    const cleanUsername = String(username).trim();
    const cleanUpper = cleanUsername.toUpperCase();
    const cleanLower = cleanUsername.toLowerCase();
    const learnersRef = collection(db, 'learners');

    let snap = await getDocs(query(learnersRef, where('username', '==', cleanUsername)));
    if (snap.empty) {
      snap = await getDocs(query(learnersRef, where('username', '==', cleanUpper)));
    }
    if (snap.empty) {
      snap = await getDocs(query(learnersRef, where('username', '==', cleanLower)));
    }
    if (snap.empty) {
      snap = await getDocs(query(learnersRef, where('digitalId', '==', cleanUpper)));
    }
    if (snap.empty) {
      snap = await getDocs(query(learnersRef, where('learnerId', '==', cleanUpper)));
    }

    if (snap.empty) {
      return res.status(401).json({ error: 'Invalid Digital ID or password. Please verify with your teacher.' });
    }

    const learnerDoc = snap.docs[0];
    const learnerData = learnerDoc.data();

    if (learnerData.status === 'INACTIVE' || learnerData.active === false) {
      return res.status(403).json({ error: 'Learner account is inactive. Please contact your school administrator.' });
    }

    // Verify password securely against salt and hash
    let isValid = false;
    if (learnerData.passwordHash && learnerData.salt) {
      const computedHash = hashPassword(String(password), learnerData.salt);
      isValid = computedHash === learnerData.passwordHash;
    } else {
      isValid = String(password) === DEFAULT_INITIAL_PASSWORD;
    }

    if (!isValid) {
      return res.status(401).json({ error: 'Invalid Digital ID or password. Please check your access slip.' });
    }

    const mustChangePassword = learnerData.mustChangePassword ?? learnerData.isFirstLogin ?? true;
    const digitalId = learnerData.digitalId || learnerData.learnerId;

    const learnerProfile = {
      id: learnerDoc.id,
      digitalId,
      learnerId: digitalId,
      fullName: learnerData.fullName,
      username: learnerData.username || digitalId,
      assignedCohortIds: learnerData.assignedCohortIds || [],
      mustChangePassword,
      isFirstLogin: mustChangePassword,
      status: learnerData.status || 'ACTIVE',
      gender: learnerData.gender,
      age: learnerData.age,
      schoolName: learnerData.schoolName || 'Sangurur Comprehensive School',
      grade: learnerData.grade || null,
    };

    const { token, expiresAt } = createSessionToken(learnerDoc.id, digitalId);

    return res.json({
      success: true,
      learner: learnerProfile,
      mustChangePassword,
      token,
      expiresAt,
    });
  } catch (err: any) {
    console.error('Login error:', err);
    return res.status(500).json({ error: err.message || 'Internal login error' });
  }
});

// Validate and refresh active learner session against Firestore
app.get('/api/auth/learner-session', requireLearnerAuth, (req: AuthenticatedLearnerRequest, res: Response) => {
  const { passwordHash, salt, ...safeProfile } = req.authLearner;
  return res.json({
    success: true,
    learner: safeProfile,
  });
});

// Learner Password Change (Mandatory on first login, or voluntary with currentPassword)
app.post('/api/auth/learner-change-password', requireLearnerAuth, async (req: AuthenticatedLearnerRequest, res: Response) => {
  try {
    const authLearner = req.authLearner;
    const { learnerId, currentPassword, newPassword } = req.body;

    if (learnerId && learnerId !== authLearner.id) {
      return res.status(403).json({ error: 'Cannot change password for another learner account.' });
    }

    if (!newPassword || typeof newPassword !== 'string') {
      return res.status(400).json({ error: 'New password is required' });
    }

    if (newPassword === DEFAULT_INITIAL_PASSWORD) {
      return res.status(400).json({
        error: 'Your new password cannot be the default password (123456789). Please choose a private secure password.',
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters long' });
    }

    // Require current password verification when changing voluntarily after first login
    if (!authLearner.mustChangePassword) {
      if (!currentPassword) {
        return res.status(400).json({ error: 'Current password is required to update your password.' });
      }
      const computedCurrent = authLearner.salt
        ? hashPassword(String(currentPassword), authLearner.salt)
        : null;
      if (!computedCurrent || computedCurrent !== authLearner.passwordHash) {
        return res.status(401).json({ error: 'Current password is incorrect.' });
      }
    }

    // Generate fresh salt and new hash (Default password becomes invalid immediately)
    const newSalt = generateSalt();
    const newHash = hashPassword(newPassword, newSalt);

    await updateDoc(doc(db, 'learners', authLearner.id), {
      passwordHash: newHash,
      salt: newSalt,
      mustChangePassword: false,
      isFirstLogin: false,
      status: 'ACTIVE',
      updatedAt: new Date().toISOString(),
    });

    await writeAuditLog({
      actorId: authLearner.id,
      actorName: authLearner.fullName,
      actorRole: 'learner',
      action: 'LEARNER_PASSWORD_CHANGED',
      targetEntity: 'learner',
      targetId: authLearner.id,
      details: `Learner ${authLearner.fullName} (${authLearner.digitalId}) updated their password; default credentials invalidated.`,
    });

    return res.json({
      success: true,
      message: 'Password changed successfully. Default password is now invalidated.',
    });
  } catch (err: any) {
    console.error('Password change error:', err);
    return res.status(500).json({ error: err.message || 'Error updating password' });
  }
});

// Scoped Learner Endpoints (Strictly enforces assigned cohorts)
app.get('/api/learner/cohorts', requireLearnerAuth, async (req: AuthenticatedLearnerRequest, res: Response) => {
  try {
    const assignedIds: string[] = req.authLearner.assignedCohortIds || [];
    if (assignedIds.length === 0) {
      return res.json({ success: true, cohorts: [] });
    }
    const snap = await getDocs(collection(db, 'cohorts'));
    const cohorts = snap.docs
      .map((d: any) => ({ ...d.data(), id: d.id }))
      .filter((c: any) => assignedIds.includes(c.id) || assignedIds.includes(c.code));
    return res.json({ success: true, cohorts });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to load assigned cohorts' });
  }
});

app.get('/api/learner/registers', requireLearnerAuth, async (req: AuthenticatedLearnerRequest, res: Response) => {
  try {
    const cohortId = req.query.cohortId ? String(req.query.cohortId) : undefined;
    const assignedIds: string[] = req.authLearner.assignedCohortIds || [];

    if (cohortId) {
      let isMember = assignedIds.includes(cohortId);
      if (!isMember) {
        const cohortSnap = await getDoc(doc(db, 'cohorts', cohortId));
        if (cohortSnap.exists()) {
          const cohortCode = cohortSnap.data()?.code;
          if (cohortCode && assignedIds.includes(cohortCode)) {
            isMember = true;
          }
        }
      }
      if (!isMember) {
        return res.status(403).json({ error: 'Access denied: you are not assigned to this cohort.' });
      }
    }

    let q = query(collection(db, 'dailyRegisters'), where('learnerDocId', '==', req.authLearner.id));
    if (cohortId) {
      q = query(q, where('cohortId', '==', cohortId));
    }
    const snap = await getDocs(q);
    const registers = snap.docs
      .map((d: any) => ({ ...d.data(), id: d.id }))
      .sort((a: any, b: any) => String(b.timestamp || '').localeCompare(String(a.timestamp || '')));
    return res.json({ success: true, registers });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to load learner registers' });
  }
});

app.get('/api/learner/feedback', requireLearnerAuth, async (req: AuthenticatedLearnerRequest, res: Response) => {
  try {
    const q = query(collection(db, 'teacherFeedback'), where('learnerDocId', '==', req.authLearner.id));
    const snap = await getDocs(q);
    const feedback = snap.docs
      .map((d: any) => ({ ...d.data(), id: d.id }))
      .sort((a: any, b: any) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
    return res.json({ success: true, feedback });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to load teacher feedback' });
  }
});

// Create Single Learner (By Teacher)
app.post('/api/learners/create', async (req: Request, res: Response) => {
  try {
    const {
      fullName,
      cohortId,
      gender,
      age,
      schoolName,
      grade,
      guardianContact,
      customDigitalId,
      teacherId,
      teacherName,
    } = req.body;

    if (!fullName || !String(fullName).trim() || !cohortId) {
      return res.status(400).json({ error: 'Full name and cohort assignment are required' });
    }

    if (!db) {
      return res.status(503).json({ error: 'Database service unavailable' });
    }

    // Verify target cohort exists
    const cohortSnap = await getDoc(doc(db, 'cohorts', String(cohortId)));
    if (!cohortSnap.exists()) {
      return res.status(404).json({ error: 'Selected cohort was not found.' });
    }

    let digitalId = '';
    if (customDigitalId && String(customDigitalId).trim()) {
      digitalId = String(customDigitalId).trim().toUpperCase();
      const dupSnap = await getDocs(query(collection(db, 'learners'), where('digitalId', '==', digitalId)));
      if (!dupSnap.empty) {
        return res.status(409).json({ error: `Digital ID ${digitalId} is already assigned to another learner.` });
      }
    } else {
      [digitalId] = await allocateDigitalIds(1);
    }

    const username = digitalId;
    const learnerId = digitalId;

    const initialPassword = DEFAULT_INITIAL_PASSWORD;
    const salt = generateSalt();
    const passwordHash = hashPassword(initialPassword, salt);

    const normalizedSchool =
      schoolName && String(schoolName).trim()
        ? String(schoolName).trim().slice(0, 128)
        : 'Sangurur Comprehensive School';
    const normalizedGrade =
      grade && String(grade).trim() ? String(grade).trim().slice(0, 64) : null;

    const docId = `learner_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const newLearner = {
      id: docId,
      fullName: String(fullName).trim(),
      digitalId,
      learnerId,
      username,
      gender: gender || null,
      age: age ? Number(age) : null,
      schoolName: normalizedSchool,
      grade: normalizedGrade,
      guardianContact: guardianContact || null,
      assignedCohortIds: [cohortId],
      mustChangePassword: true,
      isFirstLogin: true,
      status: 'ACTIVE',
      active: true,
      passwordHash,
      salt,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    await setDoc(doc(db, 'learners', docId), newLearner);

    const memberId = `mem_${cohortId}_${docId}`;
    await setDoc(doc(db, 'cohortMembers', memberId), {
      id: memberId,
      cohortId,
      learnerId: docId,
      learnerName: newLearner.fullName,
      learnerCode: digitalId,
      joinedAt: new Date().toISOString(),
      status: 'active',
    });

    await writeAuditLog({
      actorId: teacherId || 'teacher_staff',
      actorName: teacherName || 'Staff Teacher',
      actorRole: 'teacher',
      action: 'CREATE_LEARNER',
      targetEntity: 'learner',
      targetId: docId,
      details: `Registered learner ${newLearner.fullName} with Digital ID ${digitalId} in cohort ${cohortId}.`,
    });

    return res.json({
      success: true,
      learner: {
        ...newLearner,
        passwordHash: undefined,
        salt: undefined,
        initialPassword: DEFAULT_INITIAL_PASSWORD,
      },
    });
  } catch (err: any) {
    console.error('Create learner error:', err);
    return res.status(500).json({ error: err.message || 'Error creating learner' });
  }
});

// Bulk Import Learners (By Teacher)
app.post('/api/learners/bulk-import', async (req: Request, res: Response) => {
  try {
    const { cohortId, learners, teacherId, teacherName } = req.body;
    if (!cohortId || !Array.isArray(learners) || learners.length === 0) {
      return res.status(400).json({ error: 'Cohort ID and a list of learners are required' });
    }

    if (!db) {
      return res.status(503).json({ error: 'Database service unavailable' });
    }

    const cohortSnap = await getDoc(doc(db, 'cohorts', String(cohortId)));
    if (!cohortSnap.exists()) {
      return res.status(404).json({ error: 'Selected cohort was not found.' });
    }

    const validItems = learners.filter((item: any) => String(item?.fullName || '').trim().length > 0);
    if (validItems.length === 0) {
      return res.status(400).json({ error: 'No valid learner rows found in upload.' });
    }

    // Atomically allocate sequential SG-LRN-2026-XXX Digital IDs for the entire batch
    const allocatedIds = await allocateDigitalIds(validItems.length);

    const createdList: any[] = [];
    const errors: string[] = [];

    for (let i = 0; i < validItems.length; i++) {
      const item = validItems[i];
      try {
        const fullName = String(item.fullName).trim();
        const digitalId = allocatedIds[i];
        const username = digitalId;
        const learnerId = digitalId;

        const salt = generateSalt();
        const passwordHash = hashPassword(DEFAULT_INITIAL_PASSWORD, salt);

        const docId = `learner_${Date.now()}_${i}_${crypto.randomBytes(3).toString('hex')}`;
        const normalizedSchool =
          item.schoolName && String(item.schoolName).trim()
            ? String(item.schoolName).trim().slice(0, 128)
            : 'Sangurur Comprehensive School';
        const normalizedGrade =
          item.grade && String(item.grade).trim()
            ? String(item.grade).trim().slice(0, 64)
            : null;

        const newLearner = {
          id: docId,
          fullName,
          digitalId,
          learnerId,
          username,
          gender: item.gender || null,
          age: item.age ? Number(item.age) : null,
          schoolName: normalizedSchool,
          grade: normalizedGrade,
          guardianContact: item.guardianContact || null,
          assignedCohortIds: [cohortId],
          mustChangePassword: true,
          isFirstLogin: true,
          status: 'ACTIVE',
          active: true,
          passwordHash,
          salt,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };

        await setDoc(doc(db, 'learners', docId), newLearner);

        const memberId = `mem_${cohortId}_${docId}`;
        await setDoc(doc(db, 'cohortMembers', memberId), {
          id: memberId,
          cohortId,
          learnerId: docId,
          learnerName: fullName,
          learnerCode: digitalId,
          joinedAt: new Date().toISOString(),
          status: 'active',
        });

        createdList.push({
          ...newLearner,
          passwordHash: undefined,
          salt: undefined,
          initialPassword: DEFAULT_INITIAL_PASSWORD,
        });
      } catch (err: any) {
        errors.push(`Error registering ${item.fullName}: ${err.message}`);
      }
    }

    await writeAuditLog({
      actorId: teacherId || 'teacher_staff',
      actorName: teacherName || 'Staff Teacher',
      actorRole: 'teacher',
      action: 'BULK_IMPORT_LEARNERS',
      targetEntity: 'cohort',
      targetId: cohortId,
      details: `Bulk imported ${createdList.length} learners into cohort ${cohortId} (${allocatedIds[0]} to ${allocatedIds[allocatedIds.length - 1]}).`,
    });

    return res.json({
      success: true,
      createdCount: createdList.length,
      learners: createdList,
      errors,
    });
  } catch (err: any) {
    console.error('Bulk import error:', err);
    return res.status(500).json({ error: err.message || 'Error processing bulk import' });
  }
});

// Teacher Resets Learner Password to Default Password
app.post('/api/learners/reset-password', async (req: Request, res: Response) => {
  try {
    const { learnerId, teacherId, teacherName } = req.body;
    if (!learnerId) return res.status(400).json({ error: 'Learner ID is required' });

    const learnerRef = doc(db, 'learners', learnerId);
    const snap = await getDoc(learnerRef);

    if (!snap.exists()) {
      return res.status(404).json({ error: 'Learner account not found' });
    }

    const learnerData = snap.data();

    const salt = generateSalt();
    const passwordHash = hashPassword(DEFAULT_INITIAL_PASSWORD, salt);

    await updateDoc(learnerRef, {
      passwordHash,
      salt,
      mustChangePassword: true,
      isFirstLogin: true,
      status: 'ACTIVE',
      active: true,
      updatedAt: new Date().toISOString(),
    });

    await writeAuditLog({
      actorId: teacherId || 'teacher_staff',
      actorName: teacherName || 'Staff Teacher',
      actorRole: 'teacher',
      action: 'RESET_LEARNER_PASSWORD',
      targetEntity: 'learner',
      targetId: learnerId,
      details: `Authorised password reset to default '123456789' with mustChangePassword=true for ${learnerData.fullName} (Digital ID: ${learnerData.digitalId || learnerData.learnerId})`,
    });

    return res.json({
      success: true,
      digitalId: learnerData.digitalId || learnerData.learnerId,
      learnerName: learnerData.fullName,
      initialPassword: DEFAULT_INITIAL_PASSWORD,
      message: 'Password reset to default 123456789. Audit log entry recorded.',
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Error resetting password' });
  }
});

// Daily Register Submission (Strictly authenticated, membership-verified, transaction-atomic duplicate prevention)
app.post('/api/attendance/submit', requireLearnerAuth, async (req: AuthenticatedLearnerRequest, res: Response) => {
  try {
    const authLearner = req.authLearner;
    if (authLearner.mustChangePassword) {
      return res.status(403).json({ error: 'You must complete your mandatory password change before submitting a register.' });
    }

    const {
      cohortId,
      cohortCode,
      learnerDocId,
      date: requestedDate,
      status,
      didStudy = true,
      nonStudyReason,
      topicId,
      topicTitle,
      topicDescription,
      learningAreaId,
      learningAreaTitle,
      moduleId,
      moduleTitle,
      understandingLevel,
      reflectionLearned,
      reflectionActivity,
      reflectionDifficult,
      reflectionTeacherExplain,
    } = req.body;

    if (!cohortId || !status) {
      return res.status(400).json({ error: 'Cohort and attendance status are required' });
    }

    if (learnerDocId && learnerDocId !== authLearner.id) {
      return res.status(403).json({ error: 'Cannot submit attendance for another learner.' });
    }

    const nairobiToday = getNairobiDateString();
    const targetDate = requestedDate ? String(requestedDate).trim() : nairobiToday;

    if (!/^\d{4}-\d{2}-\d{2}$/.test(targetDate)) {
      return res.status(400).json({ error: 'Invalid date format. Expected YYYY-MM-DD.' });
    }
    const [yy, mm, dd] = targetDate.split('-').map(Number);
    const calCheck = new Date(Date.UTC(yy, mm - 1, dd));
    if (
      calCheck.getUTCFullYear() !== yy ||
      calCheck.getUTCMonth() !== mm - 1 ||
      calCheck.getUTCDate() !== dd
    ) {
      return res.status(400).json({ error: `Invalid calendar date: ${targetDate}` });
    }
    if (targetDate > nairobiToday) {
      return res.status(400).json({ error: `Cannot submit register for a future date (${targetDate}).` });
    }
    if (targetDate < '2020-01-01') {
      return res.status(400).json({ error: 'Selected date is out of valid range.' });
    }

    const isPreviousDay = targetDate < nairobiToday;

    // Verify cohort exists, is active, and learner is enrolled
    const cohortSnap = await getDoc(doc(db, 'cohorts', String(cohortId)));
    if (!cohortSnap.exists()) {
      return res.status(404).json({ error: 'Cohort not found.' });
    }
    const cohortData = cohortSnap.data();
    if (cohortData.status !== 'active') {
      return res.status(403).json({ error: 'Attendance cannot be submitted to an archived or inactive cohort.' });
    }

    const assignedIds: string[] = authLearner.assignedCohortIds || [];
    if (!assignedIds.includes(cohortId) && !assignedIds.includes(cohortData.code)) {
      return res.status(403).json({ error: 'Access denied: you are not assigned to this cohort.' });
    }

    if (!['present', 'late'].includes(status)) {
      return res.status(400).json({ error: 'Learners can only submit Present or Late attendance' });
    }

    const studied = didStudy !== false;
    const cleanNonStudyReason = !studied
      ? String(nonStudyReason || '').trim().slice(0, 256)
      : null;

    if (!studied && !cleanNonStudyReason) {
      return res.status(400).json({
        error: 'Please select or enter a reason explaining why you did not study (e.g., Power blackout).',
      });
    }

    const validUnderstanding = studied
      ? ['excellent', 'good', 'fair', 'needs_support'].includes(understandingLevel)
        ? understandingLevel
        : 'good'
      : null;

    // Check schoolSettings for reflection policy
    let allowReflections = true;
    try {
      const settSnap = await getDoc(doc(db, 'schoolSettings', 'school_config'));
      if (settSnap.exists() && settSnap.data().allowLearnerReflections === false) {
        allowReflections = false;
      }
    } catch {
      // default true
    }

    const docId = `reg_${cohortId}_${authLearner.id}_${targetDate}`;
    const registerRef = doc(db, 'dailyRegisters', docId);

    const payload: any = {
      id: docId,
      cohortId,
      cohortCode: cohortCode || cohortData.code || 'COHORT',
      learnerDocId: authLearner.id,
      learnerId: authLearner.digitalId || authLearner.learnerId,
      learnerName: authLearner.fullName,
      date: targetDate,
      timestamp: new Date().toISOString(),
      status,
      didStudy: studied,
      nonStudyReason: cleanNonStudyReason,
      verificationStatus: 'pending_verification',
      learningAreaId: studied && learningAreaId ? String(learningAreaId).slice(0, 128) : null,
      learningAreaTitle: studied && learningAreaTitle ? String(learningAreaTitle).slice(0, 128) : null,
      moduleId: studied && moduleId ? String(moduleId).slice(0, 128) : null,
      moduleTitle: studied && moduleTitle ? String(moduleTitle).slice(0, 128) : null,
      topicId: studied && topicId ? String(topicId).slice(0, 128) : null,
      topicTitle: studied && topicTitle ? String(topicTitle).slice(0, 128) : null,
      topicDescription: studied && topicDescription ? String(topicDescription).slice(0, 512) : null,
      understandingLevel: validUnderstanding,
      reflectionLearned: allowReflections && reflectionLearned ? String(reflectionLearned).slice(0, 1024) : null,
      reflectionActivity: allowReflections && reflectionActivity ? String(reflectionActivity).slice(0, 1024) : null,
      reflectionDifficult: allowReflections && reflectionDifficult ? String(reflectionDifficult).slice(0, 1024) : null,
      reflectionTeacherExplain:
        allowReflections && reflectionTeacherExplain ? String(reflectionTeacherExplain).slice(0, 1024) : null,
      correctionHistory: [],
    };

    const txResult = await runTransaction(db, async (transaction) => {
      const existingSnap = await transaction.get(registerRef);
      if (existingSnap.exists()) {
        const existingData = existingSnap.data();
        if (!isPreviousDay) {
          return { conflict: existingData, blocked: false, updated: false, saved: null };
        }
        if (['absent', 'excused'].includes(existingData.status)) {
          return { conflict: existingData, blocked: true, updated: false, saved: null };
        }
        const mergedPrevious = {
          ...existingData,
          status: existingData.verificationStatus === 'corrected' ? existingData.status : status,
          didStudy: studied,
          nonStudyReason: cleanNonStudyReason,
          learningAreaId: payload.learningAreaId,
          learningAreaTitle: payload.learningAreaTitle,
          moduleId: payload.moduleId,
          moduleTitle: payload.moduleTitle,
          topicId: payload.topicId,
          topicTitle: payload.topicTitle,
          topicDescription: payload.topicDescription,
          understandingLevel: validUnderstanding,
          reflectionLearned: payload.reflectionLearned ?? existingData.reflectionLearned ?? null,
          reflectionActivity: payload.reflectionActivity ?? existingData.reflectionActivity ?? null,
          reflectionDifficult: payload.reflectionDifficult ?? existingData.reflectionDifficult ?? null,
          reflectionTeacherExplain:
            payload.reflectionTeacherExplain ?? existingData.reflectionTeacherExplain ?? null,
          timestamp: existingData.timestamp || new Date().toISOString(),
        };
        transaction.set(registerRef, mergedPrevious);
        return { conflict: null, blocked: false, updated: true, saved: mergedPrevious };
      }

      transaction.set(registerRef, payload);
      return { conflict: null, blocked: false, updated: false, saved: payload };
    });

    if (txResult.blocked) {
      return res.status(403).json({
        error: `A teacher marked you ${txResult.conflict?.status?.toUpperCase()} on ${targetDate}. Please contact your teacher to correct attendance.`,
      });
    }

    if (txResult.conflict) {
      return res.status(409).json({
        error: 'Your register for today has already been submitted.',
        alreadySubmitted: true,
        submission: txResult.conflict,
      });
    }

    if (isPreviousDay) {
      await writeAuditLog({
        actorId: authLearner.id,
        actorName: authLearner.fullName,
        actorRole: 'learner',
        action: txResult.updated ? 'LEARNER_UPDATE_PREVIOUS_DAY_REGISTER' : 'LEARNER_SUBMIT_PREVIOUS_DAY_REGISTER',
        targetEntity: 'dailyRegister',
        targetId: docId,
        details: `${txResult.updated ? 'Updated' : 'Submitted'} register for ${targetDate}: status=${txResult.saved.status}, didStudy=${studied}${
          cleanNonStudyReason ? `, reason=${cleanNonStudyReason}` : `, area=${payload.learningAreaTitle || 'General'}, topic=${payload.topicTitle || 'N/A'}, understanding=${validUnderstanding}`
        }.`,
      });
    }

    return res.json({
      success: true,
      updated: txResult.updated,
      message: isPreviousDay
        ? txResult.updated
          ? `Previous day (${targetDate}) learning record updated successfully!`
          : `Previous day (${targetDate}) register submitted successfully!`
        : 'Daily register submitted successfully!',
      register: txResult.saved,
    });
  } catch (err: any) {
    console.error('Attendance submit error:', err);
    return res.status(500).json({ error: err.message || 'Failed to submit daily register' });
  }
});

// Bulk Upload Historical / Previous Dates Attendance Register (By Teacher)
app.post('/api/attendance/bulk-upload', async (req: Request, res: Response) => {
  try {
    const {
      cohortId,
      entries,
      conflictMode = 'skip',
      sessionLabel,
      teacherId,
      teacherName,
    } = req.body;

    if (!Array.isArray(entries) || entries.length === 0) {
      return res.status(400).json({ error: 'At least one attendance entry is required for upload.' });
    }

    if (!db) {
      return res.status(503).json({ error: 'Database service unavailable' });
    }

    const [cohortsSnap, learnersSnap] = await Promise.all([
      getDocs(collection(db, 'cohorts')),
      getDocs(collection(db, 'learners')),
    ]);

    const cohortsById = new Map<string, any>();
    const cohortsByCode = new Map<string, any>();
    cohortsSnap.docs.forEach((d: any) => {
      const c = { ...d.data(), id: d.id };
      cohortsById.set(d.id, c);
      if (c.code) cohortsByCode.set(String(c.code).trim().toUpperCase(), c);
    });

    const defaultCohort = cohortId ? cohortsById.get(String(cohortId)) : null;
    if (cohortId && !defaultCohort) {
      return res.status(404).json({ error: 'Selected target cohort was not found.' });
    }

    const learnersList = learnersSnap.docs.map((d: any) => ({ ...d.data(), id: d.id }));
    const learnersByDigitalId = new Map<string, any>();
    learnersList.forEach((l: any) => {
      const keys = [l.digitalId, l.learnerId, l.username, l.id].filter(Boolean);
      keys.forEach((k) => learnersByDigitalId.set(String(k).trim().toUpperCase(), l));
    });

    const nairobiToday = getNairobiDateString();
    const cleanSessionLabel = sessionLabel ? String(sessionLabel).trim().slice(0, 120) : '';
    const mode: 'skip' | 'overwrite' = conflictMode === 'overwrite' ? 'overwrite' : 'skip';

    let createdCount = 0;
    let updatedCount = 0;
    let skippedCount = 0;
    const errors: string[] = [];
    const skipped: string[] = [];
    const uploadedDates = new Set<string>();

    for (let i = 0; i < entries.length; i++) {
      const item = entries[i];
      const rowNum = item?.rowNumber || i + 1;

      const dateStr = String(item?.date || '').trim();
      if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
        errors.push(`Row ${rowNum}: Invalid date "${dateStr}". Expected YYYY-MM-DD.`);
        continue;
      }

      const [yy, mm, dd] = dateStr.split('-').map(Number);
      const checkDate = new Date(Date.UTC(yy, mm - 1, dd));
      if (
        checkDate.getUTCFullYear() !== yy ||
        checkDate.getUTCMonth() !== mm - 1 ||
        checkDate.getUTCDate() !== dd
      ) {
        errors.push(`Row ${rowNum}: Non-existent calendar date "${dateStr}".`);
        continue;
      }

      if (dateStr > nairobiToday) {
        errors.push(`Row ${rowNum}: Date ${dateStr} is in the future (today is ${nairobiToday}).`);
        continue;
      }

      const status = String(item?.status || '').trim().toLowerCase();
      if (!['present', 'late', 'absent', 'excused'].includes(status)) {
        errors.push(`Row ${rowNum}: Invalid status "${item?.status}".`);
        continue;
      }

      // Resolve cohort
      let targetCohort = defaultCohort;
      if (item?.cohortCode) {
        const byCode = cohortsByCode.get(String(item.cohortCode).trim().toUpperCase());
        if (byCode) {
          targetCohort = byCode;
        } else if (!targetCohort) {
          errors.push(`Row ${rowNum}: Cohort code "${item.cohortCode}" was not found.`);
          continue;
        }
      }
      if (!targetCohort) {
        errors.push(`Row ${rowNum}: No target cohort specified.`);
        continue;
      }

      // Resolve learner by Digital ID first, then by exact name
      const rawId = item?.learnerId ? String(item.learnerId).trim().toUpperCase() : '';
      const rawName = item?.learnerName ? String(item.learnerName).trim().toLowerCase() : '';

      let matchedLearner = rawId ? learnersByDigitalId.get(rawId) : undefined;
      if (!matchedLearner && rawName) {
        matchedLearner =
          learnersList.find(
            (l: any) =>
              String(l.fullName || '').trim().toLowerCase() === rawName &&
              Array.isArray(l.assignedCohortIds) &&
              (l.assignedCohortIds.includes(targetCohort.id) || l.assignedCohortIds.includes(targetCohort.code))
          ) ||
          learnersList.find((l: any) => String(l.fullName || '').trim().toLowerCase() === rawName);
      }

      if (!matchedLearner) {
        errors.push(
          `Row ${rowNum}: Learner "${item?.learnerId || item?.learnerName || 'Unknown'}" was not found in registered learners.`
        );
        continue;
      }

      const docId = `reg_${targetCohort.id}_${matchedLearner.id}_${dateStr}`;
      const registerRef = doc(db, 'dailyRegisters', docId);
      const existingSnap = await getDoc(registerRef);

      const learnerDigitalId = matchedLearner.digitalId || matchedLearner.learnerId;
      const validUnderstanding = ['excellent', 'good', 'fair', 'needs_support'].includes(
        String(item?.understandingLevel || '').trim()
      )
        ? String(item.understandingLevel).trim()
        : null;
      const noteText = item?.teacherNote
        ? String(item.teacherNote).trim().slice(0, 1024)
        : cleanSessionLabel
        ? `Historical Excel Upload (${cleanSessionLabel})`
        : 'Historical Excel Register Upload';
      const topicText = item?.topicTitle
        ? String(item.topicTitle).trim().slice(0, 128)
        : cleanSessionLabel || null;

      if (existingSnap.exists()) {
        if (mode === 'skip') {
          skippedCount++;
          skipped.push(`Row ${rowNum}: ${matchedLearner.fullName} (${dateStr}) already exists`);
          continue;
        }

        const existingData = existingSnap.data();
        const prevHistory = Array.isArray(existingData.correctionHistory) ? existingData.correctionHistory : [];
        const correctionEntry = {
          correctedBy: teacherId || 'teacher_staff',
          correctedByName: teacherName || 'Staff Teacher',
          timestamp: new Date().toISOString(),
          previousStatus: existingData.status,
          newStatus: status,
          reason: noteText,
        };

        await updateDoc(registerRef, {
          cohortId: targetCohort.id,
          cohortCode: targetCohort.code || 'COHORT',
          learnerDocId: matchedLearner.id,
          learnerId: learnerDigitalId,
          learnerName: matchedLearner.fullName,
          date: dateStr,
          status,
          verificationStatus: 'corrected',
          topicTitle: topicText ?? existingData.topicTitle ?? null,
          understandingLevel: validUnderstanding ?? existingData.understandingLevel ?? null,
          teacherNote: noteText,
          reviewedBy: teacherId || 'teacher_staff',
          reviewedAt: new Date().toISOString(),
          correctionHistory: [...prevHistory, correctionEntry],
        });

        updatedCount++;
        uploadedDates.add(dateStr);
      } else {
        await setDoc(registerRef, {
          id: docId,
          cohortId: targetCohort.id,
          cohortCode: targetCohort.code || 'COHORT',
          learnerDocId: matchedLearner.id,
          learnerId: learnerDigitalId,
          learnerName: matchedLearner.fullName,
          date: dateStr,
          timestamp: `${dateStr}T08:00:00+03:00`,
          status,
          verificationStatus: 'verified',
          topicTitle: topicText,
          understandingLevel: validUnderstanding,
          teacherNote: noteText,
          reviewedBy: teacherId || 'teacher_staff',
          reviewedAt: new Date().toISOString(),
          correctionHistory: [],
        });

        createdCount++;
        uploadedDates.add(dateStr);
      }
    }

    const sortedDates = Array.from(uploadedDates).sort();
    const dateSpan =
      sortedDates.length > 0
        ? sortedDates.length === 1
          ? sortedDates[0]
          : `${sortedDates[0]} to ${sortedDates[sortedDates.length - 1]}`
        : 'none';

    if (createdCount > 0 || updatedCount > 0) {
      await writeAuditLog({
        actorId: teacherId || 'teacher_staff',
        actorName: teacherName || 'Staff Teacher',
        actorRole: 'teacher',
        action: 'BULK_UPLOAD_HISTORICAL_REGISTER',
        targetEntity: 'dailyRegister',
        targetId: defaultCohort?.id || 'multi_cohort',
        details: `Uploaded previous dates Excel register${cleanSessionLabel ? ` (${cleanSessionLabel})` : ''}: ${createdCount} created, ${updatedCount} updated, ${skippedCount} skipped. Dates: ${dateSpan}.`,
      });
    }

    return res.json({
      success: true,
      createdCount,
      updatedCount,
      skippedCount,
      failedCount: errors.length,
      errors,
      skipped,
      uploadedDates: sortedDates,
    });
  } catch (err: any) {
    console.error('Historical attendance upload error:', err);
    return res.status(500).json({ error: err.message || 'Failed to upload historical attendance register' });
  }
});

// Configure Vite middleware in development or static in production
async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Sangurur Digital Learner Register running at http://0.0.0.0:${PORT}`);
  });
}

startServer();
