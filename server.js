require('dotenv').config();

const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { z } = require('zod');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || 12);
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000);
const RATE_LIMIT_MAX_REQUESTS = Number(process.env.RATE_LIMIT_MAX_REQUESTS || 200);
const RESET_TOKEN_TTL_MS = 1000 * 60 * 30;

if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required in production');
}

const DEFAULT_FAMILY_STATE = {
  children: [],
  tasks: [],
  completions: [],
  rewards: [],
  streaks: {},
  points: {},
  rewardUnlocks: [],
  familyGoal: {
    title: 'Cel rodzinny',
    target: 500,
    mode: 'points',
  },
  auditLogs: [],
  dayPointGrants: {},
  weekBonusGrants: {},
};

const passwordResetTokens = new Map();

const parseAllowedOrigins = () => {
  const raw = process.env.CORS_ORIGINS;
  if (!raw || raw.trim() === '*') {
    return '*';
  }
  return raw
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
};

const allowedOrigins = parseAllowedOrigins();

const corsOptions =
  allowedOrigins === '*'
    ? { origin: true, credentials: true }
    : {
        origin: (origin, callback) => {
          if (!origin) {
            callback(null, true);
            return;
          }
          if (allowedOrigins.includes(origin)) {
            callback(null, true);
            return;
          }
          callback(new Error(`CORS blocked origin: ${origin}`));
        },
        credentials: true,
      };

app.set('trust proxy', 1);

app.use(
  helmet({
    // Frontend uses inline scripts + CDN in index.html.
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  }),
);
app.use(cors(corsOptions));
app.use(express.json({ limit: '1mb' }));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

app.use(
  '/api',
  rateLimit({
    windowMs: RATE_LIMIT_WINDOW_MS,
    max: RATE_LIMIT_MAX_REQUESTS,
    standardHeaders: true,
    legacyHeaders: false,
  }),
);

const isObjectRecord = (value) =>
  Boolean(value) && typeof value === 'object' && !Array.isArray(value);

const signAuthToken = (user) =>
  jwt.sign(
    {
      sub: user.id,
      familyId: user.familyId,
      role: user.role,
      tokenType: 'USER',
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN },
  );

const signChildToken = ({ familyId, childId, childName }) =>
  jwt.sign(
    {
      sub: `child:${childId}`,
      familyId,
      role: 'CHILD',
      tokenType: 'CHILD',
      childId,
      childName,
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN },
  );

const toPublicUser = (user) => ({
  id: user.id,
  email: user.email,
  role: user.role,
  pinCode: user.pinCode,
  familyId: user.familyId,
});

const readBearerToken = (req) => {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    return null;
  }
  return header.slice('Bearer '.length);
};

const authMiddleware = async (req, res, next) => {
  try {
    const token = readBearerToken(req);
    if (!token) {
      res.status(401).json({ error: 'Brak tokenu autoryzacji' });
      return;
    }

    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.tokenType === 'CHILD') {
      const state = await getOrCreateState(payload.familyId);
      const data = isObjectRecord(state.data) ? state.data : {};
      const children = Array.isArray(data.children) ? data.children : [];
      const child = children.find((c) => c.id === payload.childId && !c.archived);
      if (!child) {
        res.status(401).json({ error: 'Sesja dziecka jest niewazna' });
        return;
      }
      req.auth = {
        user: {
          id: payload.sub,
          email: null,
          role: 'CHILD',
          pinCode: null,
          familyId: payload.familyId,
          active: true,
          childId: payload.childId,
          childName: child.name,
        },
      };
      next();
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id: payload.sub },
      select: {
        id: true,
        email: true,
        role: true,
        pinCode: true,
        familyId: true,
        active: true,
      },
    });

    if (!user || !user.active) {
      res.status(401).json({ error: 'Sesja jest nieważna' });
      return;
    }

    req.auth = { user };
    next();
  } catch (error) {
    res.status(401).json({ error: 'Nieprawidłowy token' });
  }
};

const requireParent = (req, res, next) => {
  if (!req.auth?.user || req.auth.user.role !== 'PARENT') {
    res.status(403).json({ error: 'Brak uprawnień do tej operacji' });
    return;
  }
  next();
};

const getOrCreateState = async (familyId) => {
  const existing = await prisma.familyState.findUnique({ where: { familyId } });
  if (existing) {
    return existing;
  }
  return prisma.familyState.create({
    data: {
      familyId,
      data: DEFAULT_FAMILY_STATE,
    },
  });
};

const isValidStorageKey = (key) => /^[a-zA-Z0-9:_-]{1,80}$/.test(key);

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  familyName: z.string().trim().max(120).optional(),
  pinCode: z.string().regex(/^\d{4}$/),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const childLoginSchema = z.object({
  accessCode: z.string().regex(/^\d{4}$/),
});

const forgotPasswordSchema = z.object({
  email: z.string().email(),
});

const resetPasswordByTokenSchema = z.object({
  token: z.string().min(10),
  newPassword: z.string().min(8),
});

const changePinSchema = z.object({
  pinCode: z.string().regex(/^\d{4}$/),
});

const createParentSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  pinCode: z.string().regex(/^\d{4}$/).optional(),
});

const toggleParentSchema = z.object({
  active: z.boolean(),
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8),
});

const resetPasswordSchema = z.object({
  userId: z.string().uuid(),
  newPassword: z.string().min(8),
});

const childSchema = z.object({
  name: z.string().trim().min(1).max(120),
  avatar: z.string().trim().min(1).max(16),
  activeDays: z.array(z.number().int().min(1).max(7)).min(1).max(7),
  accessCode: z.string().regex(/^\d{4}$/).optional(),
});

const updateChildSchema = childSchema.partial();

const taskSchema = z.object({
  childId: z.string().min(1),
  title: z.string().trim().min(1).max(160),
  tier: z.enum(['MIN', 'PLUS', 'WEEKLY']),
  points: z.number().int().min(0).max(10000).default(0),
  description: z.string().trim().max(500).optional().nullable(),
  daysOfWeek: z.array(z.number().int().min(1).max(7)).min(1).max(7).optional(),
  active: z.boolean().optional(),
});

const updateTaskSchema = taskSchema.partial();

const completionSchema = z.object({
  taskId: z.string().min(1),
  childId: z.string().min(1),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  doneByChild: z.boolean().default(true),
});

const bulkApproveSchema = z.object({
  childId: z.string().min(1).optional(),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
});

const rewardSchema = z.object({
  title: z.string().trim().min(1).max(160),
  description: z.string().trim().max(500).optional().nullable(),
  requiredPoints: z.number().int().min(0).optional().nullable(),
  requiredStreak: z.number().int().min(0).optional().nullable(),
  requiredIdealWeeks: z.number().int().min(0).optional().nullable(),
  active: z.boolean().optional(),
});

const familyGoalSchema = z.object({
  title: z.string().trim().min(1).max(120),
  target: z.number().int().min(1),
  mode: z.enum(['points', 'passedDays']),
});

const rewardUnlockSchema = z.object({
  childId: z.string().min(1),
});

const TASK_TEMPLATES = [
  { id: 'tpl-bed', title: 'Pościel łóżko', tier: 'MIN', points: 2, description: 'Rano po wstaniu' },
  { id: 'tpl-teeth', title: 'Umyj zęby', tier: 'MIN', points: 1, description: 'Rano i wieczorem' },
  { id: 'tpl-homework', title: 'Odrób lekcje', tier: 'MIN', points: 4, description: 'Po szkole' },
  { id: 'tpl-room', title: 'Posprzątaj pokój', tier: 'PLUS', points: 5, description: '15 minut porządków' },
  { id: 'tpl-reading', title: 'Czytanie 20 minut', tier: 'PLUS', points: 4, description: 'Dowolna książka' },
  { id: 'tpl-weekly-sport', title: 'Trening tygodniowy', tier: 'WEEKLY', points: 12, description: 'Co najmniej 1 trening' },
];

const createEntityId = (prefix) =>
  `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

const normalizeActiveDays = (days) =>
  [...new Set((Array.isArray(days) ? days : []).map((x) => Number(x)).filter((x) => x >= 1 && x <= 7))].sort(
    (a, b) => a - b,
  );
const normalizeTaskDaysOfWeek = (days) => normalizeActiveDays(days);

const normalizeStateData = (value) => {
  const input = isObjectRecord(value) ? value : {};
  return {
    children: Array.isArray(input.children) ? input.children : [],
    tasks: Array.isArray(input.tasks) ? input.tasks : [],
    completions: Array.isArray(input.completions) ? input.completions : [],
    rewards: Array.isArray(input.rewards) ? input.rewards : [],
    streaks: isObjectRecord(input.streaks) ? input.streaks : {},
    points: isObjectRecord(input.points) ? input.points : {},
    rewardUnlocks: Array.isArray(input.rewardUnlocks) ? input.rewardUnlocks : [],
    familyGoal: isObjectRecord(input.familyGoal)
      ? input.familyGoal
      : { title: 'Cel rodzinny', target: 500, mode: 'points' },
    auditLogs: Array.isArray(input.auditLogs) ? input.auditLogs : [],
    dayPointGrants: isObjectRecord(input.dayPointGrants) ? input.dayPointGrants : {},
    weekBonusGrants: isObjectRecord(input.weekBonusGrants) ? input.weekBonusGrants : {},
  };
};

const loadStateData = async (familyId) => {
  const state = await getOrCreateState(familyId);
  return {
    state,
    data: normalizeStateData(state.data),
  };
};

const saveStateData = async (stateId, data) =>
  prisma.familyState.update({
    where: { id: stateId },
    data: { data },
  });

const addAuditLogEntry = (data, actorUserId, action, entityType, entityId, details = {}) => {
  const entry = {
    id: createEntityId('audit'),
    userId: actorUserId || null,
    action,
    entityType,
    entityId,
    details,
    createdAt: new Date().toISOString(),
  };
  return [entry, ...data.auditLogs].slice(0, 500);
};

const ensureUniqueChildAccessCode = (children, preferredCode = null, excludeChildId = null) => {
  const usedCodes = new Set(
    children
      .filter((child) => !child.archived && child.id !== excludeChildId)
      .map((child) => child.accessCode)
      .filter((code) => typeof code === 'string' && /^\d{4}$/.test(code)),
  );

  const prefer = preferredCode && /^\d{4}$/.test(preferredCode) ? preferredCode : null;
  if (prefer && !usedCodes.has(prefer)) {
    return prefer;
  }

  for (let i = 0; i < 10000; i += 1) {
    const code = String(i).padStart(4, '0');
    if (!usedCodes.has(code)) {
      return code;
    }
  }

  return null;
};

const hasChildAccess = (req, childId) =>
  req.auth.user.role === 'PARENT' || req.auth.user.childId === childId;

app.get('/health', async (req, res) => {
  let db = 'ok';
  try {
    await prisma.$queryRaw`SELECT 1`;
  } catch (error) {
    db = 'error';
  }
  res.json({
    status: db === 'ok' ? 'ok' : 'degraded',
    db,
    timestamp: new Date().toISOString(),
  });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const parsed = registerSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane rejestracji' });
      return;
    }
    const email = parsed.data.email.trim().toLowerCase();
    const password = parsed.data.password;
    const familyName = (parsed.data.familyName || '').trim();
    const pinCode = parsed.data.pinCode;

    const emailExists = await prisma.user.findUnique({ where: { email } });
    if (emailExists) {
      res.status(409).json({ error: 'Konto z tym adresem email już istnieje' });
      return;
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const created = await prisma.$transaction(async (tx) => {
      const family = await tx.family.create({
        data: {
          name: familyName || `Rodzina ${email.split('@')[0]}`,
        },
      });

      const user = await tx.user.create({
        data: {
          email,
          passwordHash,
          pinCode,
          familyId: family.id,
        },
      });

      await tx.familyState.create({
        data: {
          familyId: family.id,
          data: DEFAULT_FAMILY_STATE,
        },
      });

      return user;
    });

    const token = signAuthToken(created);
    res.status(201).json({
      token,
      user: toPublicUser(created),
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Nie udało się utworzyć konta' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const parsed = loginSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane logowania' });
      return;
    }
    const email = parsed.data.email.trim().toLowerCase();
    const password = parsed.data.password;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      res.status(401).json({ error: 'Nieprawidłowy email lub hasło' });
      return;
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      res.status(401).json({ error: 'Nieprawidłowy email lub hasło' });
      return;
    }

    if (!user.active) {
      res.status(403).json({ error: 'Konto jest nieaktywne' });
      return;
    }

    const token = signAuthToken(user);
    res.json({
      token,
      user: toPublicUser(user),
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Logowanie nie powiodło się' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  res.json({ user: req.auth.user });
});

app.put('/api/auth/pin', authMiddleware, async (req, res) => {
  try {
    const parsed = changePinSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'PIN musi mieć dokładnie 4 cyfry' });
      return;
    }
    const pinCode = parsed.data.pinCode;

    const user = await prisma.user.update({
      where: { id: req.auth.user.id },
      data: { pinCode },
    });
    res.json({ user: toPublicUser(user) });
  } catch (error) {
    console.error('Pin update error:', error);
    res.status(500).json({ error: 'Nie udało się zapisać PIN-u' });
  }
});

app.put('/api/auth/password', authMiddleware, async (req, res) => {
  try {
    const parsed = changePasswordSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane zmiany hasła' });
      return;
    }

    const user = await prisma.user.findUnique({ where: { id: req.auth.user.id } });
    if (!user) {
      res.status(404).json({ error: 'Użytkownik nie istnieje' });
      return;
    }

    const currentOk = await bcrypt.compare(parsed.data.currentPassword, user.passwordHash);
    if (!currentOk) {
      res.status(401).json({ error: 'Aktualne hasło jest nieprawidłowe' });
      return;
    }

    const passwordHash = await bcrypt.hash(parsed.data.newPassword, BCRYPT_ROUNDS);
    await prisma.user.update({
      where: { id: user.id },
      data: { passwordHash },
    });

    res.json({ ok: true });
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ error: 'Nie udało się zmienić hasła' });
  }
});

app.get('/api/auth/parents', authMiddleware, requireParent, async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      where: { familyId: req.auth.user.familyId, role: 'PARENT' },
      orderBy: { createdAt: 'asc' },
      select: {
        id: true,
        email: true,
        active: true,
        role: true,
        createdAt: true,
      },
    });
    res.json({ users });
  } catch (error) {
    console.error('List parents error:', error);
    res.status(500).json({ error: 'Nie udało się pobrać listy użytkowników' });
  }
});

app.post('/api/auth/parents', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = createParentSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane użytkownika' });
      return;
    }

    const email = parsed.data.email.trim().toLowerCase();
    const passwordHash = await bcrypt.hash(parsed.data.password, BCRYPT_ROUNDS);

    const exists = await prisma.user.findUnique({ where: { email } });
    if (exists) {
      res.status(409).json({ error: 'Użytkownik o tym email już istnieje' });
      return;
    }

    const created = await prisma.user.create({
      data: {
        email,
        passwordHash,
        pinCode: parsed.data.pinCode || null,
        familyId: req.auth.user.familyId,
        role: 'PARENT',
        active: false,
      },
      select: {
        id: true,
        email: true,
        active: true,
        role: true,
        createdAt: true,
      },
    });

    res.status(201).json({ user: created });
  } catch (error) {
    console.error('Create parent error:', error);
    res.status(500).json({ error: 'Nie udało się dodać użytkownika' });
  }
});

app.put('/api/auth/parents/:id/active', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = toggleParentSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowa wartość aktywności' });
      return;
    }

    const targetId = String(req.params.id || '');
    const target = await prisma.user.findFirst({
      where: { id: targetId, familyId: req.auth.user.familyId, role: 'PARENT' },
    });

    if (!target) {
      res.status(404).json({ error: 'Użytkownik nie istnieje' });
      return;
    }

    if (target.id === req.auth.user.id && !parsed.data.active) {
      res.status(400).json({ error: 'Nie możesz dezaktywować własnego konta' });
      return;
    }

    const updated = await prisma.user.update({
      where: { id: target.id },
      data: { active: parsed.data.active },
      select: {
        id: true,
        email: true,
        active: true,
        role: true,
        createdAt: true,
      },
    });

    res.json({ user: updated });
  } catch (error) {
    console.error('Toggle parent error:', error);
    res.status(500).json({ error: 'Nie udało się zmienić statusu użytkownika' });
  }
});

app.put('/api/auth/password/reset', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = resetPasswordSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane resetu hasła' });
      return;
    }

    const target = await prisma.user.findFirst({
      where: {
        id: parsed.data.userId,
        familyId: req.auth.user.familyId,
        role: 'PARENT',
      },
    });
    if (!target) {
      res.status(404).json({ error: 'Użytkownik nie istnieje' });
      return;
    }

    const passwordHash = await bcrypt.hash(parsed.data.newPassword, BCRYPT_ROUNDS);
    await prisma.user.update({
      where: { id: target.id },
      data: { passwordHash },
    });
    res.json({ ok: true });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Nie udało się zresetować hasła' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const parsed = forgotPasswordSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowy adres email' });
      return;
    }

    const email = parsed.data.email.trim().toLowerCase();
    const user = await prisma.user.findUnique({ where: { email } });
    let debugToken = null;

    if (user && user.active) {
      for (const [token, info] of passwordResetTokens.entries()) {
        if (info.userId === user.id) {
          passwordResetTokens.delete(token);
        }
      }
      const token = crypto.randomBytes(24).toString('hex');
      passwordResetTokens.set(token, {
        userId: user.id,
        expiresAt: Date.now() + RESET_TOKEN_TTL_MS,
      });
      debugToken = token;
    }

    res.json({
      ok: true,
      message: 'Jeśli konto istnieje, instrukcja resetu została wysłana.',
      ...(process.env.NODE_ENV !== 'production' && debugToken ? { debugResetToken: debugToken } : {}),
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Nie udało się rozpocząć resetu hasła' });
  }
});

app.post('/api/auth/reset-password/token', async (req, res) => {
  try {
    const parsed = resetPasswordByTokenSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane resetu hasła' });
      return;
    }

    const reset = passwordResetTokens.get(parsed.data.token);
    if (!reset || reset.expiresAt < Date.now()) {
      if (reset) {
        passwordResetTokens.delete(parsed.data.token);
      }
      res.status(400).json({ error: 'Token resetu wygasł lub jest nieprawidłowy' });
      return;
    }

    const passwordHash = await bcrypt.hash(parsed.data.newPassword, BCRYPT_ROUNDS);
    await prisma.user.update({
      where: { id: reset.userId },
      data: { passwordHash },
    });
    passwordResetTokens.delete(parsed.data.token);
    res.json({ ok: true });
  } catch (error) {
    console.error('Reset password token error:', error);
    res.status(500).json({ error: 'Nie udało się zresetować hasła' });
  }
});

app.post('/api/auth/login-child', async (req, res) => {
  try {
    const parsed = childLoginSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowy kod dostępu dziecka' });
      return;
    }

    const accessCode = parsed.data.accessCode;
    const states = await prisma.familyState.findMany({
      select: { familyId: true, data: true },
    });

    const matches = [];
    for (const state of states) {
      const data = normalizeStateData(state.data);
      data.children.forEach((child) => {
        if (!child.archived && child.accessCode === accessCode) {
          matches.push({ familyId: state.familyId, child });
        }
      });
    }

    if (matches.length === 0) {
      res.status(401).json({ error: 'Nieprawidłowy kod dostępu dziecka' });
      return;
    }

    if (matches.length > 1) {
      res.status(409).json({
        error: 'Kod dostępu nie jest unikalny. Poproś rodzica o zmianę kodu dziecka.',
      });
      return;
    }

    const match = matches[0];
    const token = signChildToken({
      familyId: match.familyId,
      childId: match.child.id,
      childName: match.child.name,
    });

    res.json({
      token,
      user: {
        id: `child:${match.child.id}`,
        role: 'CHILD',
        familyId: match.familyId,
        childId: match.child.id,
        childName: match.child.name,
      },
    });
  } catch (error) {
    console.error('Child login error:', error);
    res.status(500).json({ error: 'Logowanie dziecka nie powiodło się' });
  }
});

app.get('/api/task-templates', authMiddleware, async (req, res) => {
  res.json({ templates: TASK_TEMPLATES });
});

app.get('/api/children', authMiddleware, async (req, res) => {
  try {
    const includeArchived = String(req.query.includeArchived || '') === 'true';
    const { data } = await loadStateData(req.auth.user.familyId);

    let list = data.children;
    if (req.auth.user.role === 'CHILD') {
      list = list.filter((child) => child.id === req.auth.user.childId);
    }
    if (!includeArchived) {
      list = list.filter((child) => !child.archived);
    }

    res.json({ children: list });
  } catch (error) {
    console.error('Children list error:', error);
    res.status(500).json({ error: 'Nie udało się pobrać listy dzieci' });
  }
});

app.post('/api/children', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = childSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane profilu dziecka' });
      return;
    }

    const { state, data } = await loadStateData(req.auth.user.familyId);
    const id = createEntityId('child');
    const activeDays = normalizeActiveDays(parsed.data.activeDays);
    if (activeDays.length === 0) {
      res.status(400).json({ error: 'Dziecko musi mieć co najmniej 1 dzień aktywny' });
      return;
    }
    const accessCode = ensureUniqueChildAccessCode(data.children, parsed.data.accessCode || null);
    if (!accessCode) {
      res.status(409).json({ error: 'Nie udało się wygenerować unikalnego kodu dostępu dziecka' });
      return;
    }

    const child = {
      id,
      name: parsed.data.name.trim(),
      avatar: parsed.data.avatar.trim(),
      activeDays,
      accessCode,
      archived: false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    data.children = [...data.children, child];
    data.streaks = { ...data.streaks, [id]: { current: 0, best: 0, idealWeeksCount: 0, idealWeeksInRow: 0 } };
    data.points = { ...data.points, [id]: 0 };
    data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'ADD_CHILD', 'CHILD', id, {
      name: child.name,
      activeDays: child.activeDays,
    });

    await saveStateData(state.id, data);
    res.status(201).json({ child });
  } catch (error) {
    console.error('Child create error:', error);
    res.status(500).json({ error: 'Nie udało się dodać dziecka' });
  }
});

app.put('/api/children/:id', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = updateChildSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane edycji dziecka' });
      return;
    }

    const childId = String(req.params.id || '');
    const { state, data } = await loadStateData(req.auth.user.familyId);
    const index = data.children.findIndex((child) => child.id === childId);
    if (index < 0) {
      res.status(404).json({ error: 'Dziecko nie istnieje' });
      return;
    }

    const current = data.children[index];
    const next = { ...current };
    if (typeof parsed.data.name === 'string') next.name = parsed.data.name.trim();
    if (typeof parsed.data.avatar === 'string') next.avatar = parsed.data.avatar.trim();
    if (Array.isArray(parsed.data.activeDays)) {
      const normalized = normalizeActiveDays(parsed.data.activeDays);
      if (normalized.length === 0) {
        res.status(400).json({ error: 'Dziecko musi mieć co najmniej 1 dzień aktywny' });
        return;
      }
      next.activeDays = normalized;
    }
    if (typeof parsed.data.accessCode === 'string') {
      const accessCode = ensureUniqueChildAccessCode(data.children, parsed.data.accessCode, childId);
      if (!accessCode) {
        res.status(409).json({ error: 'Kod dostępu dziecka jest zajęty' });
        return;
      }
      next.accessCode = accessCode;
    }
    next.updatedAt = new Date().toISOString();

    data.children[index] = next;
    data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'UPDATE_CHILD', 'CHILD', childId, parsed.data);
    await saveStateData(state.id, data);
    res.json({ child: next });
  } catch (error) {
    console.error('Child update error:', error);
    res.status(500).json({ error: 'Nie udało się zaktualizować dziecka' });
  }
});

app.delete('/api/children/:id', authMiddleware, requireParent, async (req, res) => {
  try {
    const childId = String(req.params.id || '');
    const { state, data } = await loadStateData(req.auth.user.familyId);
    const child = data.children.find((item) => item.id === childId);
    if (!child) {
      res.status(404).json({ error: 'Dziecko nie istnieje' });
      return;
    }

    child.archived = true;
    child.updatedAt = new Date().toISOString();
    data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'ARCHIVE_CHILD', 'CHILD', childId);
    await saveStateData(state.id, data);
    res.json({ ok: true });
  } catch (error) {
    console.error('Child archive error:', error);
    res.status(500).json({ error: 'Nie udało się zarchiwizować dziecka' });
  }
});

app.get('/api/tasks', authMiddleware, async (req, res) => {
  try {
    const includeArchived = String(req.query.includeArchived || '') === 'true';
    const childId = typeof req.query.childId === 'string' ? req.query.childId : null;
    const { data } = await loadStateData(req.auth.user.familyId);

    let list = data.tasks;
    if (req.auth.user.role === 'CHILD') {
      list = list.filter((task) => task.childId === req.auth.user.childId);
    } else if (childId) {
      list = list.filter((task) => task.childId === childId);
    }
    if (!includeArchived) {
      list = list.filter((task) => task.active !== false);
    }

    res.json({ tasks: list });
  } catch (error) {
    console.error('Task list error:', error);
    res.status(500).json({ error: 'Nie udało się pobrać listy zadań' });
  }
});

app.post('/api/tasks', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = taskSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane zadania' });
      return;
    }

    const { state, data } = await loadStateData(req.auth.user.familyId);
    const child = data.children.find((item) => item.id === parsed.data.childId && !item.archived);
    if (!child) {
      res.status(404).json({ error: 'Nie znaleziono dziecka dla tego zadania' });
      return;
    }

    const task = {
      id: createEntityId('task'),
      childId: parsed.data.childId,
      title: parsed.data.title.trim(),
      tier: parsed.data.tier,
      points: parsed.data.points || 0,
      description: parsed.data.description || '',
      daysOfWeek: normalizeTaskDaysOfWeek(parsed.data.daysOfWeek),
      active: parsed.data.active !== false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    data.tasks = [...data.tasks, task];
    data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'ADD_TASK', 'TASK', task.id, {
      childId: task.childId,
      tier: task.tier,
      points: task.points,
    });

    await saveStateData(state.id, data);
    res.status(201).json({ task });
  } catch (error) {
    console.error('Task create error:', error);
    res.status(500).json({ error: 'Nie udało się dodać zadania' });
  }
});

app.put('/api/tasks/:id', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = updateTaskSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane edycji zadania' });
      return;
    }

    const taskId = String(req.params.id || '');
    const { state, data } = await loadStateData(req.auth.user.familyId);
    const index = data.tasks.findIndex((item) => item.id === taskId);
    if (index < 0) {
      res.status(404).json({ error: 'Zadanie nie istnieje' });
      return;
    }

    const next = { ...data.tasks[index] };
    if (typeof parsed.data.childId === 'string') {
      const child = data.children.find((item) => item.id === parsed.data.childId && !item.archived);
      if (!child) {
        res.status(404).json({ error: 'Nie znaleziono dziecka dla tego zadania' });
        return;
      }
      next.childId = parsed.data.childId;
    }
    if (typeof parsed.data.title === 'string') next.title = parsed.data.title.trim();
    if (typeof parsed.data.tier === 'string') next.tier = parsed.data.tier;
    if (typeof parsed.data.points === 'number') next.points = parsed.data.points;
    if (typeof parsed.data.description === 'string' || parsed.data.description === null) {
      next.description = parsed.data.description || '';
    }
    if (parsed.data.daysOfWeek !== undefined) {
      next.daysOfWeek = normalizeTaskDaysOfWeek(parsed.data.daysOfWeek);
    }
    if (typeof parsed.data.active === 'boolean') next.active = parsed.data.active;
    next.updatedAt = new Date().toISOString();

    data.tasks[index] = next;
    data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'UPDATE_TASK', 'TASK', taskId, parsed.data);
    await saveStateData(state.id, data);
    res.json({ task: next });
  } catch (error) {
    console.error('Task update error:', error);
    res.status(500).json({ error: 'Nie udało się zaktualizować zadania' });
  }
});

app.delete('/api/tasks/:id', authMiddleware, requireParent, async (req, res) => {
  try {
    const taskId = String(req.params.id || '');
    const { state, data } = await loadStateData(req.auth.user.familyId);
    const task = data.tasks.find((item) => item.id === taskId);
    if (!task) {
      res.status(404).json({ error: 'Zadanie nie istnieje' });
      return;
    }

    task.active = false;
    task.updatedAt = new Date().toISOString();
    data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'ARCHIVE_TASK', 'TASK', taskId);
    await saveStateData(state.id, data);
    res.json({ ok: true });
  } catch (error) {
    console.error('Task archive error:', error);
    res.status(500).json({ error: 'Nie udało się zarchiwizować zadania' });
  }
});

app.get('/api/completions', authMiddleware, async (req, res) => {
  try {
    const childId = typeof req.query.childId === 'string' ? req.query.childId : null;
    const date = typeof req.query.date === 'string' ? req.query.date : null;
    const pendingOnly = String(req.query.pending || '') === 'true';
    const { data } = await loadStateData(req.auth.user.familyId);

    let list = data.completions;
    if (req.auth.user.role === 'CHILD') {
      list = list.filter((completion) => completion.childId === req.auth.user.childId);
    } else if (childId) {
      list = list.filter((completion) => completion.childId === childId);
    }
    if (date) {
      list = list.filter((completion) => completion.date === date);
    }
    if (pendingOnly) {
      list = list.filter((completion) => completion.doneByChild && !completion.approvedByParent);
    }

    res.json({ completions: list });
  } catch (error) {
    console.error('Completion list error:', error);
    res.status(500).json({ error: 'Nie udało się pobrać listy wykonań' });
  }
});

app.post('/api/completions', authMiddleware, async (req, res) => {
  try {
    const parsed = completionSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane wykonania zadania' });
      return;
    }
    if (!hasChildAccess(req, parsed.data.childId)) {
      res.status(403).json({ error: 'Brak dostępu do profilu dziecka' });
      return;
    }

    const { state, data } = await loadStateData(req.auth.user.familyId);
    const child = data.children.find((item) => item.id === parsed.data.childId && !item.archived);
    if (!child) {
      res.status(404).json({ error: 'Dziecko nie istnieje' });
      return;
    }
    const task = data.tasks.find((item) => item.id === parsed.data.taskId && item.childId === parsed.data.childId);
    if (!task || task.active === false) {
      res.status(404).json({ error: 'Zadanie nie istnieje lub jest nieaktywne' });
      return;
    }

    const existing = data.completions.find(
      (item) =>
        item.taskId === parsed.data.taskId &&
        item.childId === parsed.data.childId &&
        item.date === parsed.data.date,
    );
    const now = new Date().toISOString();

    if (existing) {
      existing.doneByChild = parsed.data.doneByChild;
      if (parsed.data.doneByChild) {
        existing.doneAt = now;
      } else {
        existing.approvedByParent = false;
        existing.approvedAt = null;
      }
      existing.updatedAt = now;

      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'UPDATE_COMPLETION', 'COMPLETION', existing.id, {
        childId: existing.childId,
        taskId: existing.taskId,
        date: existing.date,
        doneByChild: existing.doneByChild,
      });
      await saveStateData(state.id, data);
      res.json({ completion: existing });
      return;
    }

    const completion = {
      id: createEntityId('comp'),
      taskId: parsed.data.taskId,
      childId: parsed.data.childId,
      date: parsed.data.date,
      doneByChild: parsed.data.doneByChild,
      approvedByParent: false,
      approvedAt: null,
      rejectedByParent: false,
      rejectedAt: null,
      doneAt: parsed.data.doneByChild ? now : null,
      createdAt: now,
      updatedAt: now,
    };
    data.completions = [...data.completions, completion];
    data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'ADD_COMPLETION', 'COMPLETION', completion.id, {
      childId: completion.childId,
      taskId: completion.taskId,
      date: completion.date,
    });

    await saveStateData(state.id, data);
    res.status(201).json({ completion });
  } catch (error) {
    console.error('Completion create/update error:', error);
    res.status(500).json({ error: 'Nie udało się zapisać wykonania zadania' });
  }
});

app.get('/api/completions/pending', authMiddleware, requireParent, async (req, res) => {
  try {
    const childId = typeof req.query.childId === 'string' ? req.query.childId : null;
    const date = typeof req.query.date === 'string' ? req.query.date : null;
    const { data } = await loadStateData(req.auth.user.familyId);

    let queue = data.completions.filter((item) => item.doneByChild && !item.approvedByParent);
    if (childId) {
      queue = queue.filter((item) => item.childId === childId);
    }
    if (date) {
      queue = queue.filter((item) => item.date === date);
    }

    res.json({ completions: queue });
  } catch (error) {
    console.error('Pending completions error:', error);
    res.status(500).json({ error: 'Nie udało się pobrać kolejki zatwierdzeń' });
  }
});

app.post('/api/completions/:id/approve', authMiddleware, requireParent, async (req, res) => {
  try {
    const completionId = String(req.params.id || '');
    const { state, data } = await loadStateData(req.auth.user.familyId);
    const completion = data.completions.find((item) => item.id === completionId);
    if (!completion) {
      res.status(404).json({ error: 'Wykonanie nie istnieje' });
      return;
    }

    const now = new Date().toISOString();
    completion.doneByChild = true;
    completion.approvedByParent = true;
    completion.approvedAt = now;
    completion.rejectedByParent = false;
    completion.rejectedAt = null;
    completion.updatedAt = now;

    data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'APPROVE_TASK', 'COMPLETION', completionId, {
      childId: completion.childId,
      taskId: completion.taskId,
      date: completion.date,
    });
    await saveStateData(state.id, data);
    res.json({ completion });
  } catch (error) {
    console.error('Approve completion error:', error);
    res.status(500).json({ error: 'Nie udało się zatwierdzić zadania' });
  }
});

app.post('/api/completions/:id/reject', authMiddleware, requireParent, async (req, res) => {
  try {
    const completionId = String(req.params.id || '');
    const { state, data } = await loadStateData(req.auth.user.familyId);
    const completion = data.completions.find((item) => item.id === completionId);
    if (!completion) {
      res.status(404).json({ error: 'Wykonanie nie istnieje' });
      return;
    }

    const now = new Date().toISOString();
    completion.doneByChild = false;
    completion.approvedByParent = false;
    completion.approvedAt = null;
    completion.rejectedByParent = true;
    completion.rejectedAt = now;
    completion.updatedAt = now;

    data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'REJECT_TASK', 'COMPLETION', completionId, {
      childId: completion.childId,
      taskId: completion.taskId,
      date: completion.date,
    });
    await saveStateData(state.id, data);
    res.json({ completion });
  } catch (error) {
    console.error('Reject completion error:', error);
    res.status(500).json({ error: 'Nie udało się odrzucić zadania' });
  }
});

app.post('/api/completions/approve-bulk', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = bulkApproveSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe filtry zatwierdzania zbiorczego' });
      return;
    }

    const { state, data } = await loadStateData(req.auth.user.familyId);
    const now = new Date().toISOString();
    const approvedIds = [];

    data.completions.forEach((completion) => {
      if (!completion.doneByChild || completion.approvedByParent) {
        return;
      }
      if (parsed.data.childId && completion.childId !== parsed.data.childId) {
        return;
      }
      if (parsed.data.date && completion.date !== parsed.data.date) {
        return;
      }

      completion.approvedByParent = true;
      completion.approvedAt = now;
      completion.rejectedByParent = false;
      completion.rejectedAt = null;
      completion.updatedAt = now;
      approvedIds.push(completion.id);
    });

    data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'APPROVE_TASKS_BULK', 'COMPLETION', 'bulk', {
      approvedCount: approvedIds.length,
      childId: parsed.data.childId || null,
      date: parsed.data.date || null,
    });
    await saveStateData(state.id, data);
    res.json({ ok: true, approvedCount: approvedIds.length, approvedIds });
  } catch (error) {
    console.error('Bulk approve error:', error);
    res.status(500).json({ error: 'Nie udało się zatwierdzić zadań zbiorczo' });
  }
});

app.get('/api/rewards', authMiddleware, async (req, res) => {
  try {
    const { data } = await loadStateData(req.auth.user.familyId);
    const unlocks =
      req.auth.user.role === 'CHILD'
        ? data.rewardUnlocks.filter((item) => item.childId === req.auth.user.childId)
        : data.rewardUnlocks;

    res.json({
      rewards: data.rewards,
      rewardUnlocks: unlocks,
    });
  } catch (error) {
    console.error('Rewards list error:', error);
    res.status(500).json({ error: 'Nie udało się pobrać nagród' });
  }
});

app.post('/api/rewards', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = rewardSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane nagrody' });
      return;
    }

    const { state, data } = await loadStateData(req.auth.user.familyId);
    const reward = {
      id: createEntityId('reward'),
      title: parsed.data.title.trim(),
      description: parsed.data.description || '',
      requiredPoints: parsed.data.requiredPoints ?? null,
      requiredStreak: parsed.data.requiredStreak ?? null,
      requiredIdealWeeks: parsed.data.requiredIdealWeeks ?? null,
      active: parsed.data.active !== false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    data.rewards = [...data.rewards, reward];
    data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'ADD_REWARD', 'REWARD', reward.id, {
      requiredPoints: reward.requiredPoints,
      requiredStreak: reward.requiredStreak,
      requiredIdealWeeks: reward.requiredIdealWeeks,
    });

    await saveStateData(state.id, data);
    res.status(201).json({ reward });
  } catch (error) {
    console.error('Reward create error:', error);
    res.status(500).json({ error: 'Nie udało się dodać nagrody' });
  }
});

app.put('/api/rewards/:id', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = rewardSchema.partial().safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane edycji nagrody' });
      return;
    }

    const rewardId = String(req.params.id || '');
    const { state, data } = await loadStateData(req.auth.user.familyId);
    const reward = data.rewards.find((item) => item.id === rewardId);
    if (!reward) {
      res.status(404).json({ error: 'Nagroda nie istnieje' });
      return;
    }

    if (typeof parsed.data.title === 'string') reward.title = parsed.data.title.trim();
    if (typeof parsed.data.description === 'string' || parsed.data.description === null) {
      reward.description = parsed.data.description || '';
    }
    if (typeof parsed.data.requiredPoints === 'number' || parsed.data.requiredPoints === null) {
      reward.requiredPoints = parsed.data.requiredPoints ?? null;
    }
    if (typeof parsed.data.requiredStreak === 'number' || parsed.data.requiredStreak === null) {
      reward.requiredStreak = parsed.data.requiredStreak ?? null;
    }
    if (typeof parsed.data.requiredIdealWeeks === 'number' || parsed.data.requiredIdealWeeks === null) {
      reward.requiredIdealWeeks = parsed.data.requiredIdealWeeks ?? null;
    }
    if (typeof parsed.data.active === 'boolean') reward.active = parsed.data.active;
    reward.updatedAt = new Date().toISOString();

    data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'UPDATE_REWARD', 'REWARD', rewardId, parsed.data);
    await saveStateData(state.id, data);
    res.json({ reward });
  } catch (error) {
    console.error('Reward update error:', error);
    res.status(500).json({ error: 'Nie udało się zaktualizować nagrody' });
  }
});

app.post('/api/rewards/:id/unlock', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = rewardUnlockSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane odblokowania nagrody' });
      return;
    }

    const rewardId = String(req.params.id || '');
    const { state, data } = await loadStateData(req.auth.user.familyId);
    const reward = data.rewards.find((item) => item.id === rewardId && item.active !== false);
    if (!reward) {
      res.status(404).json({ error: 'Nagroda nie istnieje lub jest nieaktywna' });
      return;
    }
    const child = data.children.find((item) => item.id === parsed.data.childId && !item.archived);
    if (!child) {
      res.status(404).json({ error: 'Dziecko nie istnieje' });
      return;
    }

    const exists = data.rewardUnlocks.find(
      (item) => item.childId === parsed.data.childId && item.rewardId === rewardId,
    );
    if (exists) {
      res.json({ unlock: exists, created: false });
      return;
    }

    const unlock = {
      id: createEntityId('unlock'),
      childId: parsed.data.childId,
      rewardId,
      unlockedAt: new Date().toISOString(),
      claimedAt: null,
      shownAt: null,
    };
    data.rewardUnlocks = [unlock, ...data.rewardUnlocks];
    data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'UNLOCK_REWARD', 'REWARD', rewardId, {
      childId: parsed.data.childId,
    });
    await saveStateData(state.id, data);
    res.status(201).json({ unlock, created: true });
  } catch (error) {
    console.error('Reward unlock error:', error);
    res.status(500).json({ error: 'Nie udało się odblokować nagrody' });
  }
});

app.post('/api/rewards/unlocks/:unlockId/claim', authMiddleware, requireParent, async (req, res) => {
  try {
    const unlockId = String(req.params.unlockId || '');
    const { state, data } = await loadStateData(req.auth.user.familyId);
    const unlock = data.rewardUnlocks.find((item) => item.id === unlockId);
    if (!unlock) {
      res.status(404).json({ error: 'Odblokowanie nagrody nie istnieje' });
      return;
    }

    if (!unlock.claimedAt) {
      unlock.claimedAt = new Date().toISOString();
      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'CLAIM_REWARD', 'REWARD_UNLOCK', unlockId);
      await saveStateData(state.id, data);
    }
    res.json({ unlock });
  } catch (error) {
    console.error('Reward claim error:', error);
    res.status(500).json({ error: 'Nie udało się oznaczyć nagrody jako wydanej' });
  }
});

app.get('/api/family-goal', authMiddleware, async (req, res) => {
  try {
    const { data } = await loadStateData(req.auth.user.familyId);
    res.json({ familyGoal: data.familyGoal });
  } catch (error) {
    console.error('Family goal read error:', error);
    res.status(500).json({ error: 'Nie udało się pobrać celu rodzinnego' });
  }
});

app.put('/api/family-goal', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = familyGoalSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane celu rodzinnego' });
      return;
    }

    const { state, data } = await loadStateData(req.auth.user.familyId);
    data.familyGoal = parsed.data;
    data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'UPDATE_FAMILY_GOAL', 'FAMILY_GOAL', 'family-goal', {
      title: parsed.data.title,
      target: parsed.data.target,
      mode: parsed.data.mode,
    });
    await saveStateData(state.id, data);
    res.json({ familyGoal: data.familyGoal });
  } catch (error) {
    console.error('Family goal update error:', error);
    res.status(500).json({ error: 'Nie udało się zaktualizować celu rodzinnego' });
  }
});

app.get('/api/storage/get/:key', authMiddleware, async (req, res) => {
  const key = String(req.params.key || '');
  if (!isValidStorageKey(key)) {
    res.status(400).json({ error: 'Nieprawidłowy klucz storage' });
    return;
  }

  try {
    const state = await getOrCreateState(req.auth.user.familyId);
    const data = isObjectRecord(state.data) ? state.data : {};
    res.json({
      key,
      value: Object.prototype.hasOwnProperty.call(data, key) ? data[key] : null,
    });
  } catch (error) {
    console.error('Storage get error:', error);
    res.status(500).json({ error: 'Błąd odczytu storage' });
  }
});

app.post('/api/storage/set/:key', authMiddleware, async (req, res) => {
  const key = String(req.params.key || '');
  if (!isValidStorageKey(key)) {
    res.status(400).json({ error: 'Nieprawidłowy klucz storage' });
    return;
  }

  try {
    const state = await getOrCreateState(req.auth.user.familyId);
    const data = isObjectRecord(state.data) ? state.data : {};
    const nextData = { ...data, [key]: req.body?.value ?? null };

    await prisma.familyState.update({
      where: { id: state.id },
      data: { data: nextData },
    });

    res.json({ ok: true, key });
  } catch (error) {
    console.error('Storage set error:', error);
    res.status(500).json({ error: 'Błąd zapisu storage' });
  }
});

app.post('/api/storage/merge', authMiddleware, async (req, res) => {
  const values = req.body?.values;
  if (!isObjectRecord(values)) {
    res.status(400).json({ error: 'Nieprawidlowe dane merge storage' });
    return;
  }

  const keys = Object.keys(values);
  for (const key of keys) {
    if (!isValidStorageKey(key)) {
      res.status(400).json({ error: `Nieprawidlowy klucz storage: ${key}` });
      return;
    }
  }

  try {
    const state = await getOrCreateState(req.auth.user.familyId);
    const data = isObjectRecord(state.data) ? state.data : {};
    const nextData = { ...data, ...values };

    await prisma.familyState.update({
      where: { id: state.id },
      data: { data: nextData },
    });

    res.json({ ok: true, keys });
  } catch (error) {
    console.error('Storage merge error:', error);
    res.status(500).json({ error: 'Blad zapisu storage merge' });
  }
});

app.get('/api/storage/list', authMiddleware, async (req, res) => {
  try {
    const prefix = String(req.query.prefix || '');
    const state = await getOrCreateState(req.auth.user.familyId);
    const data = isObjectRecord(state.data) ? state.data : {};

    const keys = Object.keys(data).filter((key) => key.startsWith(prefix));
    res.json({ keys });
  } catch (error) {
    console.error('Storage list error:', error);
    res.status(500).json({ error: 'Błąd listowania storage' });
  }
});

app.use(express.static(path.join(__dirname)));

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/') || req.path === '/health') {
    next();
    return;
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

let httpServer = null;

const gracefulShutdown = async () => {
  if (httpServer) {
    await new Promise((resolve) => {
      httpServer.close(() => resolve());
    });
  }
  await prisma.$disconnect();
  process.exit(0);
};

if (require.main === module) {
  httpServer = app.listen(PORT, () => {
    console.log(`FamilyQuest server running on port ${PORT}`);
  });

  process.on('SIGINT', gracefulShutdown);
  process.on('SIGTERM', gracefulShutdown);
}

module.exports = {
  app,
  prisma,
};
