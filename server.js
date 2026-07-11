require('dotenv').config();

const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { AsyncLocalStorage } = require('async_hooks');
const { z } = require('zod');
const { Prisma, PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();

const PORT = Number(process.env.PORT || 3000);
const DEFAULT_JWT_SECRET = 'dev-only-change-me-in-production';
const JWT_SECRET = process.env.JWT_SECRET || '';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const CHILD_JWT_EXPIRES_IN = process.env.CHILD_JWT_EXPIRES_IN || '24h';
const CHILD_CODE_PEPPER = process.env.CHILD_CODE_PEPPER || '';
const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || 12);
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000);
const RATE_LIMIT_MAX_REQUESTS = Number(process.env.RATE_LIMIT_MAX_REQUESTS || 0);
const AUTH_RATE_LIMIT_WINDOW_MS = Number(process.env.AUTH_RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000);
const AUTH_RATE_LIMIT_MAX_REQUESTS = Number(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS || 20);
const CHILD_LOGIN_FAILED_WINDOW_MS = Number(process.env.CHILD_LOGIN_FAILED_WINDOW_MS || 15 * 60 * 1000);
const CHILD_LOGIN_FAILED_MAX_ATTEMPTS = Number(process.env.CHILD_LOGIN_FAILED_MAX_ATTEMPTS || 40);
const CHILD_LOGIN_CODE_FAILED_MAX_ATTEMPTS = Number(process.env.CHILD_LOGIN_CODE_FAILED_MAX_ATTEMPTS || 8);
const PARENT_PIN_FAILED_MAX_ATTEMPTS = Number(process.env.PARENT_PIN_FAILED_MAX_ATTEMPTS || 3);
const PARENT_PIN_LOCK_MS = Number(process.env.PARENT_PIN_LOCK_MS || 30 * 1000);
const RESET_TOKEN_TTL_MS = 1000 * 60 * 30;
const POINTS_PER_PASSED_DAY = 2;
const IDEAL_WEEK_BONUS = 3;
const STREAK_HISTORY_DAYS = 3650;
const ALLOW_DEBUG_RESET_TOKEN = process.env.NODE_ENV !== 'production' && process.env.ALLOW_DEBUG_RESET_TOKEN === 'true';
const ALLOW_PUBLIC_REGISTRATION = process.env.ALLOW_PUBLIC_REGISTRATION === 'true';
const AUTH_COOKIE_NAME = 'familyquest_session';
const IDEMPOTENCY_TTL_MS = Number(process.env.IDEMPOTENCY_TTL_MS || 24 * 60 * 60 * 1000);
const IDEMPOTENCY_WAIT_MS = Number(process.env.IDEMPOTENCY_WAIT_MS || 1500);
const IDEMPOTENCY_POLL_MS = Number(process.env.IDEMPOTENCY_POLL_MS || 75);
const FAMILY_STATE_TRANSACTION_MAX_WAIT_MS = Number(process.env.FAMILY_STATE_TRANSACTION_MAX_WAIT_MS || 1000);
const FAMILY_STATE_TRANSACTION_TIMEOUT_MS = Number(process.env.FAMILY_STATE_TRANSACTION_TIMEOUT_MS || 5000);
const FAMILY_SNAPSHOT_ENABLED = process.env.FAMILY_SNAPSHOT_ENABLED !== 'false';

const validateSecret = (name, value, forbiddenValues = []) => {
  if (!value || value.length < 32 || forbiddenValues.includes(value)) {
    throw new Error(`${name} environment variable is required and must be at least 32 characters`);
  }
};

validateSecret('JWT_SECRET', JWT_SECRET, [DEFAULT_JWT_SECRET]);
validateSecret('CHILD_CODE_PEPPER', CHILD_CODE_PEPPER);

const DEFAULT_FAMILY_STATE = {
  children: [],
  tasks: [],
  completions: [],
  extraTasks: [],
  pointAdjustments: [],
  pointLedger: [],
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
  taskPointGrants: {},
};

const parseAllowedOrigins = () => {
  const raw = process.env.CORS_ORIGINS;
  if (!raw) {
    return [];
  }
  if (raw.trim() === '*') {
    throw new Error('CORS_ORIGINS=* is not allowed when credentials are enabled');
  }
  return raw
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
};

const allowedOrigins = parseAllowedOrigins();

const corsOptions = {
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

const syncMetrics = new Map();
const recordSyncMetric = (name, value = 1) => {
  syncMetrics.set(name, Number(syncMetrics.get(name) || 0) + value);
};
const getSyncMetrics = () => Object.fromEntries(syncMetrics.entries());
const idempotencyRequestStorage = new AsyncLocalStorage();

app.set('trust proxy', 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  }),
);
app.use(cors(corsOptions));
app.use(express.json({ limit: '1mb' }));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

const unsafeApiMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

app.use('/api', (req, res, next) => {
  if (!unsafeApiMethods.has(req.method)) {
    next();
    return;
  }
  const hasSessionCookie = String(req.headers.cookie || '').includes(`${AUTH_COOKIE_NAME}=`);
  if (!hasSessionCookie || req.get('x-requested-with') === 'XMLHttpRequest') {
    next();
    return;
  }
  res.status(403).json({ error: 'Brak wymaganego nagłówka zabezpieczającego żądanie' });
});

if (RATE_LIMIT_MAX_REQUESTS > 0) {
  app.use(
    '/api',
    rateLimit({
      windowMs: RATE_LIMIT_WINDOW_MS,
      max: RATE_LIMIT_MAX_REQUESTS,
      standardHeaders: true,
      legacyHeaders: false,
    }),
  );
}

const authRateLimit = rateLimit({
  windowMs: AUTH_RATE_LIMIT_WINDOW_MS,
  max: AUTH_RATE_LIMIT_MAX_REQUESTS,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
});

const childLoginFailures = new Map();
const parentPinFailures = new Map();

const getRateLimitKey = (req) =>
  req.ip || req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';

const cleanupChildLoginFailures = () => {
  const now = Date.now();
  for (const [storedKey, value] of childLoginFailures.entries()) {
    if (value.resetAt <= now) {
      childLoginFailures.delete(storedKey);
    }
  }
};

const getChildLoginFailure = (key) => {
  cleanupChildLoginFailures();
  const now = Date.now();

  const current = childLoginFailures.get(key);

  if (!current || current.resetAt <= now) {
    const fresh = { count: 0, resetAt: now + CHILD_LOGIN_FAILED_WINDOW_MS };
    childLoginFailures.set(key, fresh);
    return { key, current: fresh };
  }

  return { key, current };
};

const clearChildLoginFailures = (req, codeLookupHash = null) => {
  childLoginFailures.delete(`child-login:ip:${getRateLimitKey(req)}`);
  if (codeLookupHash) {
    childLoginFailures.delete(`child-login:code:${codeLookupHash}`);
  }
};

const recordChildLoginFailureForKey = (key) => {
  const { current } = getChildLoginFailure(key);
  current.count += 1;
  return current;
};

const getBlockedChildLoginFailure = (req, codeLookupHash = null) => {
  const ipFailure = getChildLoginFailure(`child-login:ip:${getRateLimitKey(req)}`).current;
  if (ipFailure.count >= CHILD_LOGIN_FAILED_MAX_ATTEMPTS) {
    return ipFailure;
  }
  if (codeLookupHash) {
    const codeFailure = getChildLoginFailure(`child-login:code:${codeLookupHash}`).current;
    if (codeFailure.count >= CHILD_LOGIN_CODE_FAILED_MAX_ATTEMPTS) {
      return codeFailure;
    }
  }
  return null;
};

const recordChildLoginFailure = (req, codeLookupHash = null) => {
  const ipFailure = recordChildLoginFailureForKey(`child-login:ip:${getRateLimitKey(req)}`);
  if (codeLookupHash) {
    recordChildLoginFailureForKey(`child-login:code:${codeLookupHash}`);
  }
  return ipFailure;
};

setInterval(cleanupChildLoginFailures, 60 * 1000).unref();

const cleanupParentPinFailures = () => {
  const now = Date.now();
  for (const [storedKey, value] of parentPinFailures.entries()) {
    if (value.lockedUntil <= now && value.resetAt <= now) {
      parentPinFailures.delete(storedKey);
    }
  }
};

const getParentPinFailureKey = (req) => `parent-pin:${req.auth.user.id}:${getRateLimitKey(req)}`;

const getParentPinFailure = (req) => {
  cleanupParentPinFailures();
  const key = getParentPinFailureKey(req);
  const now = Date.now();
  const current = parentPinFailures.get(key);
  if (!current || (current.lockedUntil <= now && current.resetAt <= now)) {
    const fresh = { count: 0, lockedUntil: 0, resetAt: now + PARENT_PIN_LOCK_MS };
    parentPinFailures.set(key, fresh);
    return { key, current: fresh };
  }
  return { key, current };
};

const getParentPinBlockedResponse = (req) => {
  const { current } = getParentPinFailure(req);
  const now = Date.now();
  if (current.lockedUntil > now) {
    return {
      retryAfterSeconds: Math.max(1, Math.ceil((current.lockedUntil - now) / 1000)),
    };
  }
  return null;
};

const recordParentPinFailure = (req) => {
  const { current } = getParentPinFailure(req);
  current.count += 1;
  current.resetAt = Date.now() + PARENT_PIN_LOCK_MS;
  if (current.count >= PARENT_PIN_FAILED_MAX_ATTEMPTS) {
    current.lockedUntil = Date.now() + PARENT_PIN_LOCK_MS;
    current.resetAt = current.lockedUntil;
  }
  return current;
};

const clearParentPinFailures = (req) => {
  parentPinFailures.delete(getParentPinFailureKey(req));
};

setInterval(cleanupParentPinFailures, 60 * 1000).unref();

const getPasswordResetTokenHash = (token) =>
  crypto.createHash('sha256').update(String(token || ''), 'utf8').digest('hex');

const cleanupExpiredPasswordResetTokens = () =>
  prisma.passwordResetToken
    .deleteMany({
      where: {
        OR: [
          { expiresAt: { lt: new Date() } },
          { usedAt: { not: null } },
        ],
      },
    })
    .catch((error) => {
      console.warn('Password reset token cleanup failed:', error.message);
    });

setInterval(cleanupExpiredPasswordResetTokens, 60 * 1000).unref();

const isObjectRecord = (value) =>
  Boolean(value) && typeof value === 'object' && !Array.isArray(value);

const createJwtId = () => crypto.randomUUID();

const cleanupExpiredRevokedTokens = () =>
  prisma.revokedToken
    .deleteMany({
      where: {
        expiresAt: { lt: new Date() },
      },
    })
    .catch((error) => {
      console.warn('Revoked token cleanup failed:', error.message);
    });

setInterval(cleanupExpiredRevokedTokens, 60 * 1000).unref();

const cleanupExpiredIdempotencyOperations = () =>
  prisma.idempotencyOperation
    .deleteMany({ where: { expiresAt: { lt: new Date() } } })
    .catch((error) => console.warn('Idempotency cleanup failed:', error.message));

setInterval(cleanupExpiredIdempotencyOperations, 60 * 1000).unref();

const signAuthToken = (user) =>
  jwt.sign(
    {
      jti: createJwtId(),
      sub: user.id,
      familyId: user.familyId,
      role: user.role,
      tokenType: 'USER',
      authVersion: Number(user.authVersion || 0),
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN },
  );

const signChildToken = ({ familyId, childId, childName, credentialId }) =>
  jwt.sign(
    {
      jti: createJwtId(),
      sub: `child:${childId}`,
      familyId,
      role: 'CHILD',
      tokenType: 'CHILD',
      childId,
      childName,
      credentialId,
    },
    JWT_SECRET,
    { expiresIn: CHILD_JWT_EXPIRES_IN },
  );

const toPublicUser = (user, sessionRef = null) => ({
  id: user.id,
  email: user.email,
  role: user.role,
  familyId: user.familyId,
  hasPinCode: Boolean(user.pinCode),
  ...(sessionRef ? { sessionRef } : {}),
});

const getSessionRef = (token) => {
  const payload = jwt.decode(token);
  return typeof payload?.jti === 'string' ? payload.jti : null;
};

const parseCookieHeader = (header = '') =>
  String(header || '')
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((acc, part) => {
      const index = part.indexOf('=');
      if (index === -1) return acc;
      const key = part.slice(0, index).trim();
      const value = part.slice(index + 1).trim();
      if (!key) return acc;
      try {
        acc[key] = decodeURIComponent(value);
      } catch {
        acc[key] = value;
      }
      return acc;
    }, {});

const authCookieBaseOptions = (req) => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production' || req.secure || req.get('x-forwarded-proto') === 'https',
  sameSite: 'lax',
  path: '/',
});

const setAuthCookie = (req, res, token, options = {}) => {
  const { persistent = true } = options;
  res.cookie(AUTH_COOKIE_NAME, token, {
    ...authCookieBaseOptions(req),
    ...(persistent ? { maxAge: 1000 * 60 * 60 * 24 * 7 } : {}),
  });
};

const clearAuthCookie = (req, res) => {
  res.clearCookie(AUTH_COOKIE_NAME, authCookieBaseOptions(req));
};

const readBearerToken = (req) => {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    const parsedCookies = parseCookieHeader(req.headers.cookie || '');
    return parsedCookies[AUTH_COOKIE_NAME] || null;
  }
  return header.slice('Bearer '.length);
};

const isTokenRevoked = async (payload) => {
  if (!payload?.jti) return true;
  const revoked = await prisma.revokedToken.findUnique({
    where: { jti: payload.jti },
    select: { id: true },
  });
  return Boolean(revoked);
};

const revokeJwtPayload = async (payload) => {
  if (!payload?.jti || !payload?.exp || !payload?.sub || !payload?.tokenType) return;
  const expiresAt = new Date(payload.exp * 1000);
  if (Number.isNaN(expiresAt.getTime()) || expiresAt <= new Date()) return;
  await prisma.revokedToken.upsert({
    where: { jti: payload.jti },
    update: { expiresAt },
    create: {
      jti: payload.jti,
      tokenType: String(payload.tokenType),
      subjectId: String(payload.sub),
      expiresAt,
    },
  });
};

const authMiddleware = async (req, res, next) => {
  try {
    const token = readBearerToken(req);
    if (!token) {
      res.status(401).json({ error: 'Brak tokenu autoryzacji' });
      return;
    }

    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload.jti || (await isTokenRevoked(payload))) {
      res.status(401).json({ error: 'Sesja wygasła. Zaloguj się ponownie.' });
      return;
    }

    if (payload.tokenType === 'CHILD') {
      if (!payload.credentialId) {
        res.status(401).json({ error: 'Sesja dziecka jest nieważna' });
        return;
      }
      const credential = await prisma.childAccessCredential.findUnique({
        where: { id: payload.credentialId },
        select: { id: true, familyId: true, childId: true, active: true },
      });
      if (
        !credential?.active ||
        credential.familyId !== payload.familyId ||
        credential.childId !== payload.childId
      ) {
        res.status(401).json({ error: 'Sesja dziecka jest nieważna' });
        return;
      }
      const state = await getOrCreateState(payload.familyId);
      const data = isObjectRecord(state.data) ? state.data : {};
      const children = Array.isArray(data.children) ? data.children : [];
      const child = children.find((c) => c.id === payload.childId && !c.archived);
      if (!child) {
        res.status(401).json({ error: 'Sesja dziecka jest nieważna' });
        return;
      }
      req.auth = {
        user: {
          id: payload.sub,
          email: null,
          role: 'CHILD',
          familyId: payload.familyId,
          active: true,
          childId: payload.childId,
          childName: child.name,
          sessionRef: payload.jti,
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
        familyId: true,
        active: true,
        pinCode: true,
        authVersion: true,
      },
    });

    if (!user || !user.active || Number(payload.authVersion) !== Number(user.authVersion || 0)) {
      res.status(401).json({ error: 'Sesja jest nieważna' });
      return;
    }

    req.auth = {
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        familyId: user.familyId,
        active: user.active,
        hasPinCode: Boolean(user.pinCode),
        sessionRef: payload.jti,
      },
    };
    next();
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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

const getOrCreateState = async (familyId, client = prisma) => {
  const existing = await client.familyState.findUnique({ where: { familyId } });
  if (existing) {
    return existing;
  }
  return client.familyState.create({
    data: {
      familyId,
      data: DEFAULT_FAMILY_STATE,
    },
  });
};

class FamilyStateConflictError extends Error {
  constructor(message = 'Stan rodziny zmienił się w trakcie zapisu') {
    super(message);
    this.name = 'FamilyStateConflictError';
    this.code = 'FAMILY_STATE_VERSION_CONFLICT';
  }
}

const isValidStorageKey = (key) => /^[a-zA-Z0-9:_-]{1,80}$/.test(key);

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  familyName: z.string().trim().max(120).optional(),
  pinCode: z.string().regex(/^\d{6}$/).optional(),
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
  pinCode: z.string().regex(/^\d{6}$/),
  currentPassword: z.string().min(1).optional(),
});

const verifyParentPinSchema = z.object({
  pinCode: z.string().regex(/^\d{6}$/),
});

const createParentSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  pinCode: z.string().regex(/^\d{6}$/).optional(),
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
const pointLedgerQuerySchema = z.object({
  childId: z.string().min(1).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  cursor: z.coerce.number().int().min(0).default(0),
});

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

const extraTaskSchema = z.object({
  childId: z.string().min(1),
  title: z.string().trim().min(2).max(240),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
});

const approveExtraTaskSchema = z.object({
  points: z.number().int().min(0).max(1000).default(1),
});

const pointAdjustmentSchema = z.object({
  childId: z.string().min(1),
  type: z.enum(['BONUS', 'PENALTY']),
  points: z.number().int().min(1).max(1000),
  note: z.string().trim().max(240).optional().nullable(),
});

const reverseApprovalSchema = z.object({
  reason: z.string().trim().max(240).optional().nullable(),
});

const bulkApproveSchema = z.object({
  childId: z.string().min(1).optional(),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
  ids: z.array(z.string().min(1)).min(1).max(500).optional(),
});

const bulkRejectSchema = bulkApproveSchema;

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

const parseDateInput = (dateInput) => {
  if (typeof dateInput === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(dateInput)) {
    const [year, month, day] = dateInput.split('-').map(Number);
    return new Date(year, month - 1, day);
  }
  return new Date(dateInput);
};

const isValidDateString = (dateInput) =>
  typeof dateInput === 'string' &&
  /^\d{4}-\d{2}-\d{2}$/.test(dateInput) &&
  toDateString(parseDateInput(dateInput)) === dateInput;

const toDateString = (dateInput = new Date()) => {
  const date = parseDateInput(dateInput);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
};

const isFutureDateString = (dateInput, todayInput = new Date()) => dateInput > toDateString(todayInput);

const getEntityCreatedDate = (entity) => {
  if (!entity?.createdAt) return null;
  const created = toDateString(entity.createdAt);
  return isValidDateString(created) ? created : null;
};

const getDayNumber = (dateInput) => {
  const day = parseDateInput(dateInput).getDay();
  return day === 0 ? 7 : day;
};

const isTaskScheduledForDate = (task, dateInput) => {
  if (!Array.isArray(task?.daysOfWeek) || task.daysOfWeek.length === 0) return true;
  return task.daysOfWeek.includes(getDayNumber(dateInput));
};

const getTaskArchiveDate = (task) => {
  if (!task) return null;
  const archivedAt = task.archivedAt || (task.active === false ? task.updatedAt : null);
  if (!archivedAt) return null;
  const archivedDate = toDateString(archivedAt);
  return isValidDateString(archivedDate) ? archivedDate : null;
};

const getTaskRestoreDate = (task) => {
  if (!task?.restoredAt) return null;
  const restoredDate = toDateString(task.restoredAt);
  return isValidDateString(restoredDate) ? restoredDate : null;
};

const isTaskActiveForDate = (task, dateInput) => {
  if (!task) return false;
  const date = toDateString(dateInput);
  const createdDate = getEntityCreatedDate(task);
  if (createdDate && date < createdDate) return false;

  const archivedDate = getTaskArchiveDate(task);
  if (!archivedDate) return task.active !== false;
  if (date < archivedDate) return true;

  const restoredDate = getTaskRestoreDate(task);
  if (task.active !== false && restoredDate && date >= restoredDate) return true;
  return false;
};

const normalizeTaskArchiveText = (value) => String(value || '').trim().replace(/\s+/g, ' ').toLocaleLowerCase('pl');

const getTaskArchiveFingerprint = (task) =>
  JSON.stringify({
    title: normalizeTaskArchiveText(task?.title),
    tier: task?.tier || '',
    points: Number(task?.points || 0),
    description: normalizeTaskArchiveText(task?.description),
    daysOfWeek: normalizeTaskDaysOfWeek(task?.daysOfWeek),
  });

const isApprovedCompletionBeforeArchive = (task, completion) => {
  if (!task) return false;
  const archivedAt = task.archivedAt || (task.active === false ? task.updatedAt : null);
  if (!archivedAt) return true;
  const restoredDate = getTaskRestoreDate(task);
  if (task.active !== false && restoredDate && completion?.date >= restoredDate) {
    return true;
  }
  const archivedTimestamp = Date.parse(archivedAt);
  const completionTimestamp = Date.parse(
    completion?.approvedAt || completion?.updatedAt || completion?.createdAt || '',
  );
  if (Number.isFinite(archivedTimestamp) && Number.isFinite(completionTimestamp)) {
    return completionTimestamp < archivedTimestamp;
  }

  const archivedDate = getTaskArchiveDate(task);
  if (completion?.date < archivedDate) return true;
  return false;
};

const getIdempotencyOperationCode = (req) => `${req.method}:${req.path}`;
const getRequestHash = (req) =>
  crypto
    .createHash('sha256')
    .update(JSON.stringify(req.body || {}))
    .digest('hex');

const isAtomicallyIdempotentFamilyMutation = (req) => {
  const segments = req.path.split('/').filter(Boolean);
  const [resource, id, action] = segments;
  if (resource === 'children') return segments.length === 1 || segments.length === 2;
  if (resource === 'tasks') {
    return (
      segments.length === 1 ||
      segments.length === 2 ||
      (segments.length === 3 && ['archive-matching', 'restore', 'restore-matching'].includes(action))
    );
  }
  if (resource === 'rewards') {
    return (
      segments.length === 1 ||
      (segments.length === 2 && id !== 'unlocks') ||
      (segments.length === 3 && action === 'unlock') ||
      (segments.length === 4 && id === 'unlocks' && segments[3] === 'claim')
    );
  }
  if (resource === 'family-goal') return segments.length === 1;
  if (resource === 'completions') {
    return (
      segments.length === 1 ||
      (segments.length === 2 && ['approve-bulk', 'reject-bulk'].includes(id)) ||
      (segments.length === 3 && ['approve', 'reject', 'reverse-approval'].includes(action))
    );
  }
  if (resource === 'extra-tasks') {
    return segments.length === 1 || (segments.length === 3 && ['approve', 'reject'].includes(action));
  }
  return (
    (resource === 'point-adjustments' && segments.length === 1) ||
    (resource === 'storage' && ['set', 'merge', 'restore-backup'].includes(id) && segments.length >= 2)
  );
};

const getIdempotencyWhere = ({ userId, familyId, operationCode, idempotencyKey }) => ({
  userId_familyId_operationCode_idempotencyKey: {
    userId,
    familyId,
    operationCode,
    idempotencyKey,
  },
});

const createIdempotencyPendingResult = () => ({
  status: 409,
  body: {
    code: 'IDEMPOTENCY_RESULT_PENDING',
    error: 'Operacja z tym kluczem jest nadal przetwarzana.',
    retryable: true,
  },
  retryAfter: '2',
});

const waitForIdempotencyResult = async (where) => {
  const deadline = Date.now() + IDEMPOTENCY_WAIT_MS;
  const startedAt = Date.now();
  while (Date.now() < deadline) {
    const existing = await prisma.idempotencyOperation.findUnique({ where });
    if (!existing) return null;
    if (existing.completedAt) {
      recordSyncMetric('idempotency_wait_resolved');
      recordSyncMetric('idempotency_wait_ms', Date.now() - startedAt);
      return existing;
    }
    await new Promise((resolve) => setTimeout(resolve, IDEMPOTENCY_POLL_MS));
  }
  recordSyncMetric('idempotency_wait_timed_out');
  recordSyncMetric('idempotency_wait_ms', Date.now() - startedAt);
  return undefined;
};

const idempotencyMiddleware = async (req, res, next) => {
  if (!unsafeApiMethods.has(req.method) || req.path.startsWith('/auth/')) {
    next();
    return;
  }

  const idempotencyKey = String(req.get('Idempotency-Key') || '').trim();
  if (!idempotencyKey) {
    next();
    return;
  }
  if (idempotencyKey.length < 16 || idempotencyKey.length > 200) {
    res.status(400).json({ error: 'Nieprawidłowy Idempotency-Key' });
    return;
  }

  let payload;
  try {
    payload = jwt.verify(readBearerToken(req), JWT_SECRET);
  } catch {
    // The endpoint's auth middleware remains the authoritative authentication
    // check and returns the normal error payload.
    next();
    return;
  }
  if (!payload?.sub || !payload?.familyId) {
    next();
    return;
  }

  const operationCode = getIdempotencyOperationCode(req);
  const context = {
    userId: String(payload.sub),
    familyId: String(payload.familyId),
    operationCode,
    idempotencyKey,
    requestHash: getRequestHash(req),
  };
  if (isAtomicallyIdempotentFamilyMutation(req)) {
    idempotencyRequestStorage.run(context, next);
    return;
  }

  const where = getIdempotencyWhere(context);
  const { requestHash } = context;
  let created = false;
  try {
    await prisma.idempotencyOperation.create({
      data: {
        userId: String(payload.sub),
        familyId: String(payload.familyId),
        operationCode,
        idempotencyKey,
        requestHash,
        expiresAt: new Date(Date.now() + IDEMPOTENCY_TTL_MS),
      },
    });
    created = true;
  } catch (error) {
    if (error?.code !== 'P2002') {
      next(error);
      return;
    }
  }

  if (!created) {
    const existing = await prisma.idempotencyOperation.findUnique({ where });
    if (!existing) {
      next();
      return;
    }
    if (existing.requestHash !== requestHash) {
      recordSyncMetric('idempotency_key_reused');
      res.status(409).json({
        code: 'IDEMPOTENCY_KEY_REUSED',
        error: 'Ten Idempotency-Key został użyty dla innego żądania.',
      });
      return;
    }
    const resolved = existing.completedAt ? existing : await waitForIdempotencyResult(where);
    if (resolved?.completedAt) {
      recordSyncMetric('idempotency_replay');
      res.status(resolved.responseStatus || 200).json(resolved.responseBody);
      return;
    }
    res.set('Retry-After', '2');
    recordSyncMetric('idempotency_result_pending');
    res.status(409).json({
      code: 'IDEMPOTENCY_RESULT_PENDING',
      error: 'Operacja z tym kluczem jest nadal przetwarzana.',
      retryable: true,
    });
    return;
  }

  const originalJson = res.json.bind(res);
  let persisted = false;
  res.json = (body) => {
    if (persisted) return originalJson(body);
    persisted = true;
    const status = res.statusCode;
    const persist = status < 500
      ? prisma.idempotencyOperation.update({
        where,
        data: {
          responseStatus: status,
          responseBody: body,
          completedAt: new Date(),
        },
      })
      : prisma.idempotencyOperation.delete({ where }).catch(() => null);
    persist
      .catch((error) => console.error('Idempotency result persistence error:', error))
      .finally(() => originalJson(body));
    return res;
  };
  next();
};

const getWeekStart = (dateInput) => {
  const date = parseDateInput(dateInput);
  const day = date.getDay();
  const diff = day === 0 ? -6 : 1 - day;
  date.setDate(date.getDate() + diff);
  return toDateString(date);
};

const normalizeStateData = (value) => {
  const input = isObjectRecord(value) ? value : {};
  return {
    children: Array.isArray(input.children) ? input.children : [],
    tasks: Array.isArray(input.tasks) ? input.tasks : [],
    completions: Array.isArray(input.completions) ? input.completions : [],
    extraTasks: Array.isArray(input.extraTasks) ? input.extraTasks : [],
    pointAdjustments: Array.isArray(input.pointAdjustments) ? input.pointAdjustments : [],
    pointLedger: Array.isArray(input.pointLedger) ? input.pointLedger : [],
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
    taskPointGrants: isObjectRecord(input.taskPointGrants) ? input.taskPointGrants : {},
  };
};

const sanitizeChildForStorage = (child) => {
  if (!isObjectRecord(child)) return child;
  const { accessCode: _accessCode, ...safeChild } = child;
  return safeChild;
};

const sanitizeChildrenForStorage = (children) =>
  (Array.isArray(children) ? children : []).map((child) => sanitizeChildForStorage(child));

const sanitizeAuditLogForStorage = (entry) => {
  if (!isObjectRecord(entry)) return entry;
  const details = isObjectRecord(entry.details) ? { ...entry.details } : entry.details;
  if (isObjectRecord(details) && Object.prototype.hasOwnProperty.call(details, 'accessCode')) {
    delete details.accessCode;
    details.accessCodeChanged = true;
  }
  return {
    ...entry,
    ...(isObjectRecord(details) ? { details } : {}),
  };
};

const sanitizeAuditLogsForStorage = (auditLogs) =>
  (Array.isArray(auditLogs) ? auditLogs : []).map((entry) => sanitizeAuditLogForStorage(entry));

const sanitizeStateDataForStorage = (value) => {
  const data = normalizeStateData(value);
  return {
    ...data,
    children: sanitizeChildrenForStorage(data.children),
    auditLogs: sanitizeAuditLogsForStorage(data.auditLogs),
  };
};

const FAMILY_STATE_CONFLICT_BASE_DATA = Symbol('familyStateConflictBaseData');

const cloneStateDataForStorage = (value) => JSON.parse(JSON.stringify(sanitizeStateDataForStorage(value)));

const attachStateDataConflictBase = (target, data) => {
  if (!isObjectRecord(target)) return target;
  Object.defineProperty(target, FAMILY_STATE_CONFLICT_BASE_DATA, {
    value: cloneStateDataForStorage(data),
    enumerable: false,
    configurable: true,
  });
  return target;
};

const getStateDataConflictBase = (state, data) => {
  if (isObjectRecord(data) && data[FAMILY_STATE_CONFLICT_BASE_DATA]) {
    return data[FAMILY_STATE_CONFLICT_BASE_DATA];
  }
  if (isObjectRecord(state) && state[FAMILY_STATE_CONFLICT_BASE_DATA]) {
    return state[FAMILY_STATE_CONFLICT_BASE_DATA];
  }
  return null;
};

const getConflictComparableStateData = (value) => {
  const data = normalizeStateData(value);
  return {
    children: data.children,
    tasks: data.tasks,
    completions: data.completions,
    extraTasks: data.extraTasks,
    pointAdjustments: data.pointAdjustments,
    rewards: data.rewards,
    rewardUnlocks: data.rewardUnlocks,
    familyGoal: data.familyGoal,
  };
};

const isCompatibleFamilyStateConflict = (baseData, latestData) =>
  JSON.stringify(getConflictComparableStateData(baseData)) ===
  JSON.stringify(getConflictComparableStateData(latestData));

const loadStateData = async (familyId, client = prisma) => {
  const state = await getOrCreateState(familyId, client);
  const data = normalizeStateData(state.data);
  attachStateDataConflictBase(state, data);
  attachStateDataConflictBase(data, data);
  return {
    state,
    data,
  };
};

const getFamilyStateVersion = (state) => {
  const version = Number(state?.version);
  return Number.isInteger(version) && version >= 0 ? version : 0;
};

const createSaveStateData = (familyStateClient) => async (state, data, options = {}) => {
  const stateId = isObjectRecord(state) ? state.id : state;
  if (!stateId) {
    throw new Error('Brak identyfikatora stanu rodziny');
  }
  const nextData = cloneStateDataForStorage(data);

  if (!isObjectRecord(state)) {
    return familyStateClient.update({
      where: { id: stateId },
      data: {
        data: nextData,
        version: { increment: 1 },
      },
    });
  }

  const expectedVersion = getFamilyStateVersion(state);
  const result = await familyStateClient.updateMany({
    where: {
      id: stateId,
      version: expectedVersion,
    },
    data: {
      data: nextData,
      version: { increment: 1 },
    },
  });

  if (result.count !== 1) {
    if (options.skipOnConflict) return null;
    const baseData = getStateDataConflictBase(state, data);
    if (options.retryOnCompatibleConflict !== false && baseData) {
      const latestState = await familyStateClient.findUnique({ where: { id: stateId } });
      if (latestState && isCompatibleFamilyStateConflict(baseData, latestState.data)) {
        const retryResult = await familyStateClient.updateMany({
          where: {
            id: stateId,
            version: getFamilyStateVersion(latestState),
          },
          data: {
            data: nextData,
            version: { increment: 1 },
          },
        });
        if (retryResult.count === 1) {
          return familyStateClient.findUnique({ where: { id: stateId } });
        }
      }
    }
    throw new FamilyStateConflictError();
  }

  return familyStateClient.findUnique({ where: { id: stateId } });
};

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

const isFamilyStateConflict = (error) => error?.code === 'FAMILY_STATE_VERSION_CONFLICT';

const sendFamilyStateConflict = (res) =>
  (recordSyncMetric('family_state_conflict'), res.status(409).json({
    error: 'Stan rodziny zmienił się na innym urządzeniu. Odśwież dane i spróbuj ponownie.',
    code: 'FAMILY_STATE_VERSION_CONFLICT',
  }));

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

const isValidChildAccessCode = (value) => typeof value === 'string' && /^\d{4}$/.test(value);

const getChildAccessCodeLookupHash = (accessCode) =>
  crypto
    .createHmac('sha256', CHILD_CODE_PEPPER)
    .update(String(accessCode || ''), 'utf8')
    .digest('hex');

const getGloballyUsedChildAccessCodeHashes = async (options = {}, client = prisma) => {
  const { excludeFamilyId = null, excludeChildId = null } = options;
  const credentials = await client.childAccessCredential.findMany({
    where: { active: true },
    select: { familyId: true, childId: true, codeLookupHash: true },
  });
  return new Set(
    credentials
      .filter((credential) => !(credential.familyId === excludeFamilyId && credential.childId === excludeChildId))
      .map((credential) => credential.codeLookupHash),
  );
};

const pickGloballyUniqueChildAccessCode = async (options = {}, client = prisma) => {
  const { preferredCode = null, excludeFamilyId = null, excludeChildId = null, reservedCodes = new Set() } = options;
  const usedHashes = await getGloballyUsedChildAccessCodeHashes({ excludeFamilyId, excludeChildId }, client);
  reservedCodes.forEach((code) => {
    if (isValidChildAccessCode(code)) usedHashes.add(getChildAccessCodeLookupHash(code));
  });

  if (isValidChildAccessCode(preferredCode) && !usedHashes.has(getChildAccessCodeLookupHash(preferredCode))) {
    return preferredCode;
  }

  if (isValidChildAccessCode(preferredCode)) {
    return null;
  }

  for (let i = 0; i < 10000; i += 1) {
    const code = String(i).padStart(4, '0');
    if (!usedHashes.has(getChildAccessCodeLookupHash(code))) {
      return code;
    }
  }

  return null;
};

const normalizeChildrenAccessCodesGlobally = async (children, options = {}, client = prisma) => {
  const { familyId } = options;
  const usedHashes = await getGloballyUsedChildAccessCodeHashes({ excludeFamilyId: familyId }, client);
  const normalized = [];

  for (const child of children) {
    if (child.archived) {
      normalized.push(child);
      continue;
    }

    let accessCode = isValidChildAccessCode(child.accessCode) && !usedHashes.has(getChildAccessCodeLookupHash(child.accessCode))
      ? child.accessCode
      : null;

    if (!accessCode) {
      for (let i = 0; i < 10000; i += 1) {
        const candidate = String(i).padStart(4, '0');
        if (!usedHashes.has(getChildAccessCodeLookupHash(candidate))) {
          accessCode = candidate;
          break;
        }
      }
    }

    if (!accessCode) {
      return null;
    }

    usedHashes.add(getChildAccessCodeLookupHash(accessCode));
    normalized.push({ ...child, accessCode });
  }

  return normalized;
};

const setChildAccessCredential = async (client, { familyId, childId, accessCode, active = true }) => {
  if (!isValidChildAccessCode(accessCode)) {
    throw new Error('Nieprawidłowy kod dostępu dziecka');
  }
  const codeLookupHash = getChildAccessCodeLookupHash(accessCode);
  const existingForCode = await client.childAccessCredential.findUnique({
    where: { codeLookupHash },
  });
  if (existingForCode?.active && (existingForCode.familyId !== familyId || existingForCode.childId !== childId)) {
    throw new Error('Kod dostępu dziecka jest zajęty');
  }
  if (existingForCode?.active && existingForCode.familyId === familyId && existingForCode.childId === childId) {
    return existingForCode;
  }

  const codeHash = await bcrypt.hash(accessCode, BCRYPT_ROUNDS);
  await client.childAccessCredential.updateMany({
    where: { familyId, childId, active: true },
    data: { active: false },
  });

  if (existingForCode && !existingForCode.active) {
    return client.childAccessCredential.update({
      where: { id: existingForCode.id },
      data: {
        familyId,
        childId,
        codeHash,
        active,
      },
    });
  }

  if (existingForCode && existingForCode.familyId === familyId && existingForCode.childId === childId) {
    return client.childAccessCredential.update({
      where: { id: existingForCode.id },
      data: { codeHash, active },
    });
  }

  return client.childAccessCredential.create({
    data: {
      familyId,
      childId,
      codeLookupHash,
      codeHash,
      active,
    },
  });
};

const deactivateChildAccessCredential = (client, familyId, childId) =>
  client.childAccessCredential.updateMany({
    where: { familyId, childId, active: true },
    data: { active: false },
  });

const findChildAccessCredentialByCode = (accessCode) =>
  prisma.childAccessCredential.findUnique({
    where: { codeLookupHash: getChildAccessCodeLookupHash(accessCode) },
  });

const attachOneTimeAccessCode = (child, accessCode = null) =>
  accessCode ? { ...sanitizeChildForStorage(child), accessCode } : sanitizeChildForStorage(child);

const isSerializableTransactionConflict = (error) =>
  error?.code === 'P2034' || /write conflict|deadlock|could not serialize/i.test(String(error?.message || ''));

const runFamilyStateTransaction = async (action) => {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return await prisma.$transaction(action, {
        isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
        maxWait: FAMILY_STATE_TRANSACTION_MAX_WAIT_MS,
        timeout: FAMILY_STATE_TRANSACTION_TIMEOUT_MS,
      });
    } catch (error) {
      if (attempt < 2 && isSerializableTransactionConflict(error)) {
        continue;
      }
      throw error;
    }
  }
  return null;
};

const claimAtomicIdempotencyOperation = async (tx, context) => {
  const where = getIdempotencyWhere(context);
  const created = await tx.idempotencyOperation.createMany({
    data: {
      userId: context.userId,
      familyId: context.familyId,
      operationCode: context.operationCode,
      idempotencyKey: context.idempotencyKey,
      requestHash: context.requestHash,
      expiresAt: new Date(Date.now() + IDEMPOTENCY_TTL_MS),
    },
    skipDuplicates: true,
  });
  if (created.count === 1) {
    return { where, owner: true };
  }

  const existing = await tx.idempotencyOperation.findUnique({ where });
  if (!existing) {
    // A competing transaction can be rolled back after ON CONFLICT has waited
    // for it. Treat the result as unresolved instead of executing a duplicate.
    return { where, pending: true };
  }
  if (existing.requestHash !== context.requestHash) {
    return {
      where,
      result: {
        status: 409,
        body: {
          code: 'IDEMPOTENCY_KEY_REUSED',
          error: 'Ten Idempotency-Key został użyty dla innego żądania.',
        },
      },
    };
  }
  if (!existing.completedAt) {
    return { where, pending: true };
  }
  return {
    where,
    result: {
      status: existing.responseStatus || 200,
      body: existing.responseBody,
      replayed: true,
    },
  };
};

const isIdempotencyTransactionContention = (error) =>
  error?.code === 'P2028' || isSerializableTransactionConflict(error);

const runFamilyMutation = async (req, action) => {
  const context = idempotencyRequestStorage.getStore();
  try {
    return await runFamilyStateTransaction(async (tx) => {
      const claim = context ? await claimAtomicIdempotencyOperation(tx, context) : null;
      if (claim?.result) {
        if (claim.result.replayed) recordSyncMetric('idempotency_replay');
        if (claim.result.body?.code === 'IDEMPOTENCY_KEY_REUSED') {
          recordSyncMetric('idempotency_key_reused');
        }
        return claim.result;
      }
      if (claim?.pending) {
        recordSyncMetric('idempotency_result_pending');
        return createIdempotencyPendingResult();
      }

      const result = await action(tx);
      if (claim?.owner && result?.status < 500) {
        await tx.idempotencyOperation.update({
          where: claim.where,
          data: {
            responseStatus: result.status,
            responseBody: result.body,
            completedAt: new Date(),
          },
        });
      }
      return result;
    });
  } catch (error) {
    if (!context || !isIdempotencyTransactionContention(error)) throw error;

    const resolved = await waitForIdempotencyResult(getIdempotencyWhere(context));
    if (resolved?.completedAt) {
      recordSyncMetric('idempotency_replay');
      return {
        status: resolved.responseStatus || 200,
        body: resolved.responseBody,
        replayed: true,
      };
    }
    recordSyncMetric('idempotency_result_pending');
    return createIdempotencyPendingResult();
  }
};

const sendFamilyMutationResult = (res, result) => {
  if (result?.retryAfter) res.set('Retry-After', result.retryAfter);
  res.status(result.status).json(result.body);
};

const bootstrapChildAccessCredentials = async () => {
  const states = await prisma.familyState.findMany({
    select: { id: true, familyId: true, data: true },
  });

  for (const snapshot of states) {
    await prisma.$transaction(async (tx) => {
      const state = await tx.familyState.findUnique({ where: { id: snapshot.id } });
      if (!state) return;
      const data = normalizeStateData(state.data);
      let changed = false;

      for (const child of data.children) {
        if (!child?.id) continue;
        if (child.archived) {
          await deactivateChildAccessCredential(tx, state.familyId, child.id);
        } else {
          const activeCredential = await tx.childAccessCredential.findFirst({
            where: { familyId: state.familyId, childId: child.id, active: true },
          });
          if (!activeCredential) {
            const accessCode = await pickGloballyUniqueChildAccessCode(
              { preferredCode: child.accessCode || null },
              tx,
            );
            if (!accessCode) {
              throw new Error(`Brak wolnego kodu dostępu dla dziecka ${child.id}`);
            }
            await setChildAccessCredential(tx, {
              familyId: state.familyId,
              childId: child.id,
              accessCode,
            });
          }
        }

        if (Object.prototype.hasOwnProperty.call(child, 'accessCode')) {
          delete child.accessCode;
          changed = true;
        }
      }

      const storageData = cloneStateDataForStorage(data);
      if (JSON.stringify(storageData) !== JSON.stringify(normalizeStateData(state.data))) {
        changed = true;
      }

      if (changed) {
        await tx.familyState.update({
          where: { id: state.id },
          data: {
            data: storageData,
            version: { increment: 1 },
          },
        });
      }
    });
  }
};

const hasChildAccess = (req, childId) =>
  req.auth.user.role === 'PARENT' || req.auth.user.childId === childId;

const getTaskPointKey = (childId, taskId, date, task = null) => {
  if (task?.tier === 'WEEKLY') {
    return `${childId}:${taskId}:week:${getWeekStart(date)}`;
  }
  return `${childId}:${taskId}:${date}`;
};
const getDayPointKey = (childId, date) => `${childId}:${date}`;
const getWeekPointKey = (childId, weekStart) => `${childId}:${weekStart}`;

const evaluateDayForData = (data, childId, date) => {
  const child = data.children.find((item) => item.id === childId);
  if (!child) return 'NOT_ACTIVE';
  const activeDays = Array.isArray(child.activeDays) ? child.activeDays : [];
  if (!activeDays.includes(getDayNumber(date))) return 'NOT_ACTIVE';

  const minTasks = data.tasks.filter(
    (task) =>
      task.childId === childId &&
      task.tier === 'MIN' &&
      (isTaskActiveForDate(task, date) ||
        data.completions.some(
          (completion) =>
            completion.taskId === task.id &&
            completion.childId === childId &&
            completion.date === date &&
            completion.approvedByParent &&
            isApprovedCompletionBeforeArchive(task, completion),
        )) &&
      isTaskScheduledForDate(task, date),
  );
  if (minTasks.length === 0) return 'NO_REQUIRED_TASKS';

  const approvedCount = minTasks.filter((task) =>
    data.completions.some(
      (completion) =>
        completion.taskId === task.id &&
        completion.childId === childId &&
        completion.date === date &&
        completion.approvedByParent,
    ),
  ).length;
  return approvedCount === minTasks.length ? 'PASSED' : 'FAILED';
};

const evaluateWeekForData = (data, childId, weekStart) => {
  let activeDays = 0;
  let passedDays = 0;
  for (let i = 0; i < 7; i += 1) {
    const date = parseDateInput(weekStart);
    date.setDate(date.getDate() + i);
    const dateStr = toDateString(date);
    const status = evaluateDayForData(data, childId, dateStr);
    if (status === 'NOT_ACTIVE' || status === 'NO_REQUIRED_TASKS') continue;
    activeDays += 1;
    if (status === 'PASSED') passedDays += 1;
  }
  if (activeDays === 0) return 'NO_ACTIVE_DAYS';
  return passedDays === activeDays ? 'IDEAL' : 'NOT_IDEAL';
};

const calculateStreakForChildData = (data, childId, todayInput = new Date()) => {
  const child = data.children.find((item) => item.id === childId && !item.archived);
  if (!child) {
    return {
      current: 0,
      best: 0,
      lastEvaluatedDate: null,
      idealWeeksCount: 0,
      idealWeeksInRow: 0,
    };
  }

  const today = parseDateInput(toDateString(todayInput));
  const minStart = parseDateInput(today);
  minStart.setDate(today.getDate() - STREAK_HISTORY_DAYS);

  const createdDate = child.createdAt ? parseDateInput(toDateString(child.createdAt)) : minStart;
  const startDate = createdDate > minStart ? createdDate : minStart;
  const cursor = parseDateInput(startDate);
  const weekMap = {};
  let current = 0;
  let best = 0;
  let lastEvaluatedDate = null;

  while (cursor <= today) {
    const dateStr = toDateString(cursor);
    const status = evaluateDayForData(data, childId, dateStr);

    if (status === 'PASSED') {
      current += 1;
      best = Math.max(best, current);
      lastEvaluatedDate = dateStr;
    } else if (status === 'FAILED') {
      current = 0;
      lastEvaluatedDate = dateStr;
    }

    const weekStart = getWeekStart(dateStr);
    if (!weekMap[weekStart]) {
      weekMap[weekStart] = evaluateWeekForData(data, childId, weekStart);
    }

    cursor.setDate(cursor.getDate() + 1);
  }

  let idealWeeksCount = 0;
  let idealWeeksInRow = 0;
  let rollingIdealRow = 0;
  Object.keys(weekMap)
    .sort()
    .forEach((weekStart) => {
      const status = weekMap[weekStart];
      if (status === 'NO_ACTIVE_DAYS') return;
      if (status === 'IDEAL') {
        idealWeeksCount += 1;
        rollingIdealRow += 1;
      } else {
        rollingIdealRow = 0;
      }
      idealWeeksInRow = rollingIdealRow;
    });

  return {
    current,
    best,
    lastEvaluatedDate,
    idealWeeksCount,
    idealWeeksInRow,
  };
};

const refreshChildStreak = (data, childId, todayInput = new Date()) => {
  data.streaks = {
    ...data.streaks,
    [childId]: calculateStreakForChildData(data, childId, todayInput),
  };
  return data.streaks[childId];
};

const refreshAllStreaks = (data, todayInput = new Date()) => {
  const nextStreaks = {};
  data.children
    .filter((child) => !child.archived)
    .forEach((child) => {
      nextStreaks[child.id] = calculateStreakForChildData(data, child.id, todayInput);
    });
  data.streaks = nextStreaks;
  return data.streaks;
};

const compareChildrenForLeaderboard = (points, streaks) => (a, b) => {
  const pointDiff = Number(points[b.id] || 0) - Number(points[a.id] || 0);
  if (pointDiff !== 0) return pointDiff;

  const streakDiff = Number(streaks[b.id]?.current || 0) - Number(streaks[a.id]?.current || 0);
  if (streakDiff !== 0) return streakDiff;

  const idealDiff = Number(streaks[b.id]?.idealWeeksInRow || 0) - Number(streaks[a.id]?.idealWeeksInRow || 0);
  if (idealDiff !== 0) return idealDiff;

  return String(a.name || '').localeCompare(String(b.name || ''), 'pl');
};

const validateChildDate = (child, date, { allowFuture = false } = {}) => {
  if (!isValidDateString(date)) {
    return 'Nieprawidłowa data';
  }
  if (!allowFuture && isFutureDateString(date)) {
    return 'Nie można zapisywać zadań z przyszłości';
  }
  const createdDate = getEntityCreatedDate(child);
  if (createdDate && date < createdDate) {
    return 'Data nie może być wcześniejsza niż utworzenie profilu dziecka';
  }
  return null;
};

const validateTaskCompletionDate = (child, task, date) => {
  const dateError = validateChildDate(child, date);
  if (dateError) return dateError;
  if (!Array.isArray(child.activeDays) || !child.activeDays.includes(getDayNumber(date))) {
    return 'Dziecko nie ma aktywnego dnia w tej dacie';
  }
  if (!isTaskScheduledForDate(task, date)) {
    return 'Zadanie nie jest zaplanowane na ten dzień';
  }
  return null;
};

const getCompletionTimestamp = (completion) =>
  Date.parse(completion?.approvedAt || completion?.updatedAt || completion?.createdAt || 0) || 0;

const getAdjustmentTimestamp = (adjustment) => Date.parse(adjustment?.createdAt || 0) || 0;

const getLedgerTimestamp = (item) =>
  Date.parse(item?.occurredAt || item?.approvedAt || item?.createdAt || item?.updatedAt || 0) || 0;

const compareLedgerEventsAscending = (a, b) => {
  const timeDiff = getLedgerTimestamp(a) - getLedgerTimestamp(b);
  if (timeDiff !== 0) return timeDiff;
  return String(a.id || a.sourceId || '').localeCompare(String(b.id || b.sourceId || ''), 'pl');
};

const compareLedgerEventsDescending = (a, b) => {
  const timeDiff = getLedgerTimestamp(b) - getLedgerTimestamp(a);
  if (timeDiff !== 0) return timeDiff;
  return String(b.id || b.sourceId || '').localeCompare(String(a.id || a.sourceId || ''), 'pl');
};

const recomputePointsAndGrants = (data) => {
  const nextPoints = {};
  const taskPointGrants = {};
  const dayPointGrants = {};
  const weekBonusGrants = {};
  const pointLedger = [];
  const ledgerEvents = [];
  const relevantDayKeys = new Set();
  const relevantWeekKeys = new Set();
  const childrenById = new Map(data.children.filter((child) => !child.archived).map((child) => [child.id, child]));
  const tasksById = new Map(data.tasks.map((task) => [task.id, task]));

  childrenById.forEach((child) => {
    nextPoints[child.id] = 0;
  });

  const queueLedgerEntry = ({
    id,
    childId,
    type,
    delta,
    title,
    note = '',
    sourceType = null,
    sourceId = null,
    date = null,
    occurredAt = null,
    affectsBalance = true,
    previousPoints = null,
    newPoints = null,
  }) => {
    if (!childrenById.has(childId)) return null;
    const appliedDelta = Number(delta || 0);
    if (!Number.isFinite(appliedDelta) || appliedDelta === 0) return null;
    const event = {
      id: id || createEntityId('ledger'),
      childId,
      type,
      delta: appliedDelta,
      points: Math.abs(appliedDelta),
      previousPoints,
      newPoints,
      title: title || 'Zmiana punktów',
      note: note || '',
      sourceType,
      sourceId,
      date,
      occurredAt: occurredAt || new Date().toISOString(),
      affectsBalance,
    };
    ledgerEvents.push(event);
    return event;
  };

  data.completions
    .filter((completion) => completion.approvedByParent)
    .sort((a, b) => getCompletionTimestamp(a) - getCompletionTimestamp(b))
    .forEach((completion) => {
      const child = childrenById.get(completion.childId);
      const task = tasksById.get(completion.taskId);
      if (
        !child ||
        !task ||
        task.childId !== completion.childId ||
        !isApprovedCompletionBeforeArchive(task, completion) ||
        validateTaskCompletionDate(child, task, completion.date)
      ) return;

      const taskPointKey = getTaskPointKey(completion.childId, completion.taskId, completion.date, task);
      if (Number(task.points || 0) > 0 && !taskPointGrants[taskPointKey]) {
        taskPointGrants[taskPointKey] = true;
        queueLedgerEntry({
          id: `task:${taskPointKey}`,
          childId: completion.childId,
          type: 'TASK_APPROVED',
          delta: Number(task.points || 0),
          title: task.title || 'Zatwierdzone zadanie',
          sourceType: 'COMPLETION',
          sourceId: completion.id,
          date: completion.date,
          occurredAt: completion.approvedAt || completion.updatedAt || completion.createdAt,
        });
      }

      relevantDayKeys.add(getDayPointKey(completion.childId, completion.date));
      relevantWeekKeys.add(getWeekPointKey(completion.childId, getWeekStart(completion.date)));
    });

  [...relevantDayKeys].sort().forEach((dayKey) => {
    const [childId, date] = dayKey.split(':');
    if (evaluateDayForData(data, childId, date) !== 'PASSED') return;
    dayPointGrants[dayKey] = true;
    queueLedgerEntry({
      id: `day:${dayKey}`,
      childId,
      type: 'DAY_PASSED',
      delta: POINTS_PER_PASSED_DAY,
      title: 'Zaliczony dzień',
      sourceType: 'DAY',
      sourceId: dayKey,
      date,
      occurredAt: `${date}T23:59:00.000Z`,
    });
  });

  [...relevantWeekKeys].sort().forEach((weekKey) => {
    const [childId, weekStart] = weekKey.split(':');
    if (evaluateWeekForData(data, childId, weekStart) !== 'IDEAL') return;
    weekBonusGrants[weekKey] = true;
    queueLedgerEntry({
      id: `week:${weekKey}`,
      childId,
      type: 'WEEK_IDEAL',
      delta: IDEAL_WEEK_BONUS,
      title: 'Idealny tydzień',
      sourceType: 'WEEK',
      sourceId: weekKey,
      date: weekStart,
      occurredAt: `${weekStart}T23:59:30.000Z`,
    });
  });

  data.extraTasks
    .filter((task) => task.status === 'APPROVED')
    .sort((a, b) => Date.parse(a.approvedAt || a.updatedAt || a.createdAt || 0) - Date.parse(b.approvedAt || b.updatedAt || b.createdAt || 0))
    .forEach((task) =>
      queueLedgerEntry({
        id: `extra:${task.id}`,
        childId: task.childId,
        type: 'EXTRA_TASK',
        delta: Number(task.points || 0),
        title: task.title || 'Zadanie dodatkowe',
        sourceType: 'EXTRA_TASK',
        sourceId: task.id,
        date: task.date || null,
        occurredAt: task.approvedAt || task.updatedAt || task.createdAt,
      }),
    );

  data.pointAdjustments
    .slice()
    .sort((a, b) => getAdjustmentTimestamp(a) - getAdjustmentTimestamp(b))
    .forEach((adjustment) => {
      if (!childrenById.has(adjustment.childId)) return;
      const delta =
        typeof adjustment.delta === 'number'
          ? adjustment.delta
          : adjustment.type === 'PENALTY'
            ? -Number(adjustment.points || 0)
            : Number(adjustment.points || 0);
      if (!Number.isFinite(delta) || delta === 0) return;
      const affectsBalance = adjustment.affectsBalance !== false;
      queueLedgerEntry({
        id: `adjustment:${adjustment.id}`,
        childId: adjustment.childId,
        type: adjustment.type || (delta < 0 ? 'PENALTY' : 'BONUS'),
        delta,
        title:
          adjustment.note ||
          (adjustment.type === 'REVERSAL'
            ? 'Cofnięcie zatwierdzenia'
            : adjustment.type === 'PENALTY'
              ? 'Kara punktowa'
              : 'Premia punktowa'),
        note: adjustment.note || '',
        sourceType: 'POINT_ADJUSTMENT',
        sourceId: adjustment.id,
        date: adjustment.sourceDate || null,
        occurredAt: adjustment.createdAt || adjustment.updatedAt,
        affectsBalance,
        previousPoints: affectsBalance ? null : adjustment.previousPoints,
        newPoints: affectsBalance ? null : adjustment.newPoints,
      });
    });

  ledgerEvents
    .sort(compareLedgerEventsAscending)
    .forEach((event) => {
      const hasPreviousPoints =
        event.previousPoints !== null && event.previousPoints !== undefined && Number.isFinite(Number(event.previousPoints));
      const hasNewPoints = event.newPoints !== null && event.newPoints !== undefined && Number.isFinite(Number(event.newPoints));
      const previous = hasPreviousPoints ? Number(event.previousPoints) : Number(nextPoints[event.childId] || 0);
      const next = hasNewPoints
        ? Number(event.newPoints)
        : event.affectsBalance === false
          ? previous
          : Math.max(0, previous + Number(event.delta || 0));
      const actualDelta = event.affectsBalance === false ? Number(event.delta || 0) : next - previous;
      const entry = {
        ...event,
        delta: actualDelta,
        points: Math.abs(actualDelta),
        previousPoints: previous,
        newPoints: next,
      };
      pointLedger.push(entry);
      if (event.affectsBalance !== false) {
        nextPoints[event.childId] = next;
      }
    });

  data.points = nextPoints;
  data.taskPointGrants = taskPointGrants;
  data.dayPointGrants = dayPointGrants;
  data.weekBonusGrants = weekBonusGrants;
  data.pointLedger = pointLedger.sort(compareLedgerEventsDescending);
  refreshAllStreaks(data);
  return data;
};

const getComputedStateFingerprint = (data) =>
  JSON.stringify({
    points: data.points,
    streaks: data.streaks,
    pointLedger: data.pointLedger,
    taskPointGrants: data.taskPointGrants,
    dayPointGrants: data.dayPointGrants,
    weekBonusGrants: data.weekBonusGrants,
  });

const recomputePointsAndGrantsIfChanged = (data) => {
  const before = getComputedStateFingerprint(data);
  recomputePointsAndGrants(data);
  return getComputedStateFingerprint(data) !== before;
};

const hasStateDataChanged = (previousData, nextData) => JSON.stringify(previousData) !== JSON.stringify(nextData);

const adjustPoints = (data, childId, amount) => {
  const current = Number(data.points[childId] || 0);
  const next = Math.max(0, current + amount);
  data.points = {
    ...data.points,
    [childId]: next,
  };
  return {
    previousPoints: current,
    newPoints: next,
    appliedDelta: next - current,
  };
};

const addPoints = (data, childId, amount) => {
  if (!amount || amount <= 0) return null;
  return adjustPoints(data, childId, amount);
};

const isRewardUnlockVisible = (unlock) => !unlock?.revokedAt;

const getVisibleRewardUnlocks = (unlocks) =>
  (Array.isArray(unlocks) ? unlocks : []).filter(isRewardUnlockVisible);

const getRewardUnlockHistory = (data) => {
  const childrenById = new Map(data.children.map((child) => [child.id, child]));
  const rewardsById = new Map(data.rewards.map((reward) => [reward.id, reward]));
  const auditLogs = Array.isArray(data.auditLogs) ? data.auditLogs : [];

  return (Array.isArray(data.rewardUnlocks) ? data.rewardUnlocks : [])
    .map((unlock) => {
      const child = childrenById.get(unlock.childId);
      const reward = rewardsById.get(unlock.rewardId);
      if (!child || !reward) return null;

      const events = [];
      const addEvent = (type, at, source, details = {}) => {
        if (!at) return;
        const exists = events.some((event) => event.type === type && event.at === at);
        if (!exists) {
          events.push({ type, at, source, details });
        }
      };

      addEvent('UNLOCKED', unlock.unlockedAt || unlock.createdAt, 'unlock');
      addEvent('REVOKED', unlock.revokedAt, 'unlock', { reason: unlock.revokedReason || null });
      addEvent('RESTORED', unlock.restoredAt, 'unlock');
      addEvent('CLAIMED', unlock.claimedAt, 'unlock');

      auditLogs
        .filter((entry) => entry.entityType === 'REWARD_UNLOCK' && entry.entityId === unlock.id)
        .forEach((entry) => {
          if (entry.action === 'REVOKE_REWARD_UNLOCK') {
            addEvent('REVOKED', entry.createdAt, 'audit', entry.details || {});
          }
          if (entry.action === 'RESTORE_REWARD_UNLOCK') {
            addEvent('RESTORED', entry.createdAt, 'audit', entry.details || {});
          }
          if (entry.action === 'CLAIM_REWARD') {
            addEvent('CLAIMED', entry.createdAt, 'audit', entry.details || {});
          }
        });

      events.sort((a, b) => Date.parse(a.at || 0) - Date.parse(b.at || 0));

      const status = unlock.claimedAt ? 'CLAIMED' : unlock.revokedAt ? 'REVOKED' : unlock.restoredAt ? 'RESTORED' : 'AVAILABLE';
      const latestAt =
        events.length > 0 ? events[events.length - 1].at : unlock.updatedAt || unlock.unlockedAt || unlock.createdAt || null;

      return {
        id: unlock.id,
        childId: unlock.childId,
        childName: child.name,
        rewardId: unlock.rewardId,
        rewardTitle: reward.title,
        rewardDescription: reward.description || '',
        requiredPoints: reward.requiredPoints ?? null,
        requiredStreak: reward.requiredStreak ?? null,
        requiredIdealWeeks: reward.requiredIdealWeeks ?? null,
        status,
        unlockedAt: unlock.unlockedAt || null,
        revokedAt: unlock.revokedAt || null,
        restoredAt: unlock.restoredAt || null,
        claimedAt: unlock.claimedAt || null,
        revokedReason: unlock.revokedReason || null,
        latestAt,
        events,
      };
    })
    .filter(Boolean)
    .sort((a, b) => Date.parse(b.latestAt || 0) - Date.parse(a.latestAt || 0));
};

const buildFamilyStatePatch = (data, user) => {
  recomputePointsAndGrants(data);
  reconcileRewardUnlocksForAllChildren(data, user?.id);

  const leaderboardChildren = data.children
    .filter((child) => !child.archived)
    .map((child) => ({
      id: child.id,
      name: child.name,
      avatar: child.avatar,
    }));
  const leaderboardPoints = {};
  const leaderboardStreaks = {};

  leaderboardChildren.forEach((child) => {
    leaderboardPoints[child.id] = Number(data.points[child.id] || 0);
    leaderboardStreaks[child.id] = data.streaks[child.id] || calculateStreakForChildData(data, child.id);
  });

  return {
    completions: filterStorageValueForUser('completions', data, user),
    extraTasks: filterStorageValueForUser('extraTasks', data, user),
    points: filterStorageValueForUser('points', data, user),
    streaks: filterStorageValueForUser('streaks', data, user),
    pointLedger: filterStorageValueForUser('pointLedger', data, user),
    rewardUnlocks: filterStorageValueForUser('rewardUnlocks', data, user),
    rewardUnlockHistory: user?.role === 'PARENT' ? getRewardUnlockHistory(data) : [],
    dayPointGrants: filterStorageValueForUser('dayPointGrants', data, user),
    weekBonusGrants: filterStorageValueForUser('weekBonusGrants', data, user),
    taskPointGrants: filterStorageValueForUser('taskPointGrants', data, user),
    auditLogs: filterStorageValueForUser('auditLogs', data, user),
    familyLeaderboard: {
      children: leaderboardChildren.slice().sort(compareChildrenForLeaderboard(leaderboardPoints, leaderboardStreaks)),
      points: leaderboardPoints,
      streaks: leaderboardStreaks,
    },
  };
};

const isRewardEligibleForChild = (data, reward, childId) => {
  const childPoints = Number(data.points[childId] || 0);
  const childStreak = data.streaks[childId] || { current: 0, idealWeeksInRow: 0 };
  const pointsOk = !reward.requiredPoints || childPoints >= reward.requiredPoints;
  const streakOk = !reward.requiredStreak || Number(childStreak.current || 0) >= reward.requiredStreak;
  const idealOk = !reward.requiredIdealWeeks || Number(childStreak.idealWeeksInRow || 0) >= reward.requiredIdealWeeks;
  return pointsOk && streakOk && idealOk;
};

const reconcileRewardUnlocksForChild = (data, childId, actorUserId, now = new Date().toISOString()) => {
  const child = data.children.find((item) => item.id === childId && !item.archived);
  if (!child) return;

  data.rewards.forEach((reward) => {
    if (reward.active === false) return;
    const unlocksForReward = data.rewardUnlocks.filter((item) => item.childId === childId && item.rewardId === reward.id);
    const activeUnlock = unlocksForReward.find((item) => !item.revokedAt);
    const revokedUnlock = unlocksForReward.find((item) => item.revokedAt && !item.claimedAt);
    const eligible = isRewardEligibleForChild(data, reward, childId);

    if (!eligible) {
      const requiredPoints = Number(reward.requiredPoints || 0);
      const childPoints = Number(data.points[childId] || 0);
      if (requiredPoints > 0 && childPoints < requiredPoints && activeUnlock && !activeUnlock.claimedAt) {
        activeUnlock.revokedAt = now;
        activeUnlock.revokedReason = 'POINTS_BELOW_THRESHOLD';
        activeUnlock.updatedAt = now;
        data.auditLogs = addAuditLogEntry(data, actorUserId, 'REVOKE_REWARD_UNLOCK', 'REWARD_UNLOCK', activeUnlock.id, {
          childId,
          rewardId: reward.id,
          requiredPoints,
          childPoints,
        });
      }
      return;
    }

    if (activeUnlock) return;

    if (revokedUnlock) {
      revokedUnlock.revokedAt = null;
      revokedUnlock.revokedReason = null;
      revokedUnlock.restoredAt = now;
      revokedUnlock.updatedAt = now;
      data.auditLogs = addAuditLogEntry(data, actorUserId, 'RESTORE_REWARD_UNLOCK', 'REWARD_UNLOCK', revokedUnlock.id, {
        childId,
        rewardId: reward.id,
      });
      return;
    }

    const unlock = {
      id: createEntityId('unlock'),
      childId,
      rewardId: reward.id,
      unlockedAt: now,
      claimedAt: null,
      shownAt: null,
      revokedAt: null,
      revokedReason: null,
      restoredAt: null,
      updatedAt: now,
    };
    data.rewardUnlocks = [unlock, ...data.rewardUnlocks];
    data.auditLogs = addAuditLogEntry(data, actorUserId, 'UNLOCK_REWARD', 'REWARD', reward.id, { childId });
  });
};

const unlockEligibleRewards = (data, childId, actorUserId, now = new Date().toISOString()) => {
  reconcileRewardUnlocksForChild(data, childId, actorUserId, now);
};

const reconcileRewardUnlocksForAllChildren = (data, actorUserId, now = new Date().toISOString()) => {
  data.children
    .filter((child) => !child.archived)
    .forEach((child) => reconcileRewardUnlocksForChild(data, child.id, actorUserId, now));
};

const applyApprovalEffects = (data, completion, actorUserId, now = new Date().toISOString()) => {
  if (!completion || completion.approvedByParent) {
    return false;
  }

  const child = data.children.find((item) => item.id === completion.childId && !item.archived);
  const task = data.tasks.find((item) => item.id === completion.taskId && item.childId === completion.childId);
  if (!child || !task || !isTaskActiveForDate(task, completion.date)) {
    return false;
  }
  const completionDateError = validateTaskCompletionDate(child, task, completion.date);
  if (completionDateError) {
    return false;
  }

  const previousStatus = evaluateDayForData(data, completion.childId, completion.date);
  completion.doneByChild = true;
  completion.approvedByParent = true;
  completion.approvedAt = now;
  completion.rejectedByParent = false;
  completion.rejectedAt = null;
  completion.updatedAt = now;

  const taskPointKey = getTaskPointKey(completion.childId, completion.taskId, completion.date, task);
  if (task && Number(task.points || 0) > 0 && !data.taskPointGrants[taskPointKey]) {
    data.taskPointGrants = { ...data.taskPointGrants, [taskPointKey]: true };
    addPoints(data, completion.childId, Number(task.points || 0));
  }

  const nextStatus = evaluateDayForData(data, completion.childId, completion.date);
  if (previousStatus !== 'PASSED' && nextStatus === 'PASSED') {
    const dayPointKey = getDayPointKey(completion.childId, completion.date);
    if (!data.dayPointGrants[dayPointKey]) {
      data.dayPointGrants = { ...data.dayPointGrants, [dayPointKey]: true };
      addPoints(data, completion.childId, POINTS_PER_PASSED_DAY);
    }

    const weekStart = getWeekStart(completion.date);
    const weekPointKey = getWeekPointKey(completion.childId, weekStart);
    if (!data.weekBonusGrants[weekPointKey] && evaluateWeekForData(data, completion.childId, weekStart) === 'IDEAL') {
      data.weekBonusGrants = { ...data.weekBonusGrants, [weekPointKey]: true };
      addPoints(data, completion.childId, IDEAL_WEEK_BONUS);
    }
  }

  refreshChildStreak(data, completion.childId, now);
  unlockEligibleRewards(data, completion.childId, actorUserId);
  return true;
};

const reverseApprovalEffects = (data, completion, actorUserId, reason = '', now = new Date().toISOString()) => {
  if (!completion || !completion.approvedByParent) {
    return null;
  }

  recomputePointsAndGrants(data);
  const childId = completion.childId;
  const previousPoints = Number(data.points[childId] || 0);

  completion.doneByChild = false;
  completion.approvedByParent = false;
  completion.approvedAt = null;
  completion.rejectedByParent = true;
  completion.rejectedAt = now;
  completion.reversedAt = now;
  completion.reversedBy = actorUserId;
  completion.reversalReason = reason || 'Cofnięcie zatwierdzenia';
  completion.updatedAt = now;

  recomputePointsAndGrants(data);
  const newPoints = Number(data.points[childId] || 0);
  const appliedDelta = newPoints - previousPoints;
  const task = data.tasks.find((item) => item.id === completion.taskId && item.childId === childId);
  const child = data.children.find((item) => item.id === childId);
  const adjustment = {
    id: createEntityId('points'),
    childId,
    type: 'REVERSAL',
    requestedPoints: Math.abs(appliedDelta),
    points: Math.abs(appliedDelta),
    delta: appliedDelta,
    previousPoints,
    newPoints,
    affectsBalance: false,
    sourceCompletionId: completion.id,
    sourceTaskId: completion.taskId,
    sourceDate: completion.date,
    note:
      reason ||
      `Cofnięto zatwierdzenie: ${task?.title || 'zadanie'} (${completion.date || 'bez daty'})`,
    createdBy: actorUserId,
    createdAt: now,
    updatedAt: now,
  };

  data.pointAdjustments = [adjustment, ...data.pointAdjustments];
  reconcileRewardUnlocksForChild(data, childId, actorUserId, now);
  data.auditLogs = addAuditLogEntry(data, actorUserId, 'REVERSE_TASK_APPROVAL', 'COMPLETION', completion.id, {
    childId,
    childName: child?.name || null,
    taskId: completion.taskId,
    taskTitle: task?.title || null,
    date: completion.date,
    previousPoints,
    newPoints,
    delta: appliedDelta,
    reason: adjustment.note,
  });

  return {
    completion,
    pointAdjustment: adjustment,
    points: data.points,
    reversal: {
      previousPoints,
      newPoints,
      delta: appliedDelta,
      removedPoints: Math.abs(appliedDelta),
      childId,
      taskId: completion.taskId,
      taskTitle: task?.title || null,
      date: completion.date,
    },
  };
};

const normalizeRestoredBackupData = (backup, actorUserId, now = new Date().toISOString()) => {
  const source = isObjectRecord(backup?.data) ? backup.data : backup;
  if (!isObjectRecord(source)) {
    return null;
  }

  const nextData = normalizeStateData(source);
  nextData.children = nextData.children.map((child) => ({
    ...child,
    accessCode: ensureUniqueChildAccessCode(nextData.children, child.accessCode, child.id) || child.accessCode || null,
  }));
  recomputePointsAndGrants(nextData);
  reconcileRewardUnlocksForAllChildren(nextData, actorUserId, now);
  nextData.auditLogs = addAuditLogEntry(nextData, actorUserId, 'RESTORE_BACKUP', 'BACKUP', 'family', {
    restoredAt: now,
    childrenCount: nextData.children.length,
    tasksCount: nextData.tasks.length,
    completionsCount: nextData.completions.length,
    extraTasksCount: nextData.extraTasks.length,
    rewardUnlocksCount: nextData.rewardUnlocks.length,
  });
  return nextData;
};

const pickChildMapValue = (source, childId) => {
  if (!isObjectRecord(source)) {
    return {};
  }
  return Object.prototype.hasOwnProperty.call(source, childId) ? { [childId]: source[childId] } : {};
};

const filterStorageValueForUser = (key, data, user) => {
  if (key === 'rewardUnlocks') {
    const visibleUnlocks = getVisibleRewardUnlocks(data.rewardUnlocks);
    return user.role === 'CHILD' ? visibleUnlocks.filter((unlock) => unlock.childId === user.childId) : visibleUnlocks;
  }

  if (user.role !== 'CHILD') {
    if (key === 'children') {
      return sanitizeChildrenForStorage(data.children);
    }
    return Object.prototype.hasOwnProperty.call(data, key) ? data[key] : null;
  }

  const childId = user.childId;
  switch (key) {
    case 'children':
      return data.children.filter((child) => child.id === childId).map((child) => sanitizeChildForStorage(child));
    case 'tasks':
      return data.tasks.filter((task) => task.childId === childId);
    case 'completions':
      return data.completions.filter((completion) => completion.childId === childId);
    case 'extraTasks':
      return data.extraTasks.filter((task) => task.childId === childId);
    case 'pointAdjustments':
      return data.pointAdjustments.filter((adjustment) => adjustment.childId === childId);
    case 'pointLedger':
      return data.pointLedger.filter((entry) => entry.childId === childId);
    case 'streaks':
      return pickChildMapValue(data.streaks, childId);
    case 'points':
      return pickChildMapValue(data.points, childId);
    case 'rewardUnlocks':
      return getVisibleRewardUnlocks(data.rewardUnlocks).filter((unlock) => unlock.childId === childId);
    case 'rewards':
      return data.rewards;
    case 'familyGoal':
      return data.familyGoal;
    case 'auditLogs':
      return [];
    case 'dayPointGrants':
    case 'weekBonusGrants':
    case 'taskPointGrants':
      return {};
    default:
      return null;
  }
};

const mergeChildCompletions = (data, incoming, childId) => {
  if (!Array.isArray(incoming)) {
    return data.completions;
  }

  const now = new Date().toISOString();
  const childTaskIds = new Set(
    data.tasks
      .filter((task) => task.childId === childId && task.active !== false)
      .map((task) => task.id),
  );
  const existingOwnById = new Map(
    data.completions
      .filter((completion) => completion.childId === childId && typeof completion.id === 'string')
      .map((completion) => [completion.id, completion]),
  );

  const nextOwn = incoming
    .filter(
      (completion) =>
        isObjectRecord(completion) &&
        completion.childId === childId &&
        typeof completion.taskId === 'string' &&
        typeof completion.date === 'string' &&
        childTaskIds.has(completion.taskId),
    )
    .map((completion) => {
      const existing = typeof completion.id === 'string' ? existingOwnById.get(completion.id) : null;
      const wasApproved = existing?.approvedByParent === true;
      const doneByChild = wasApproved ? true : completion.doneByChild === true;
      return {
        ...existing,
        id: existing?.id || (typeof completion.id === 'string' ? completion.id : createEntityId('comp')),
        taskId: completion.taskId,
        childId,
        date: completion.date,
        doneByChild,
        approvedByParent: wasApproved,
        approvedAt: wasApproved ? existing.approvedAt || null : null,
        rejectedByParent: doneByChild ? false : existing?.rejectedByParent === true,
        rejectedAt: doneByChild ? null : existing?.rejectedAt || null,
        doneAt: doneByChild ? completion.doneAt || existing?.doneAt || now : null,
        createdAt: existing?.createdAt || completion.createdAt || now,
        updatedAt: now,
      };
    });

  return [
    ...data.completions.filter((completion) => completion.childId !== childId),
    ...nextOwn,
  ];
};

const mergeChildRewardUnlocks = (data, incoming, childId) => {
  if (!Array.isArray(incoming)) {
    return data.rewardUnlocks;
  }

  const incomingById = new Map(
    incoming
      .filter((unlock) => isObjectRecord(unlock) && unlock.childId === childId && typeof unlock.id === 'string')
      .map((unlock) => [unlock.id, unlock]),
  );

  return data.rewardUnlocks.map((unlock) => {
    const incomingUnlock = incomingById.get(unlock.id);
    if (!incomingUnlock || unlock.childId !== childId) {
      return unlock;
    }
    return {
      ...unlock,
      shownAt: typeof incomingUnlock.shownAt === 'string' ? incomingUnlock.shownAt : unlock.shownAt || null,
    };
  });
};

const getRecordTimestamp = (item) => {
  const raw = item?.updatedAt || item?.approvedAt || item?.createdAt || item?.unlockedAt || item?.claimedAt || null;
  const timestamp = raw ? Date.parse(raw) : Number.NaN;
  return Number.isFinite(timestamp) ? timestamp : 0;
};

const mergeArrayRecordsById = (existing, incoming) => {
  if (!Array.isArray(incoming)) {
    return Array.isArray(existing) ? existing : [];
  }

  const merged = new Map();
  (Array.isArray(existing) ? existing : []).forEach((item) => {
    if (isObjectRecord(item) && typeof item.id === 'string') {
      merged.set(item.id, item);
    }
  });

  incoming.forEach((item) => {
    if (!isObjectRecord(item) || typeof item.id !== 'string') return;
    const current = merged.get(item.id);
    if (!current || getRecordTimestamp(item) >= getRecordTimestamp(current)) {
      merged.set(item.id, { ...current, ...item });
    }
  });

  return [...merged.values()];
};

const mergeObjectMap = (existing, incoming) => ({
  ...(isObjectRecord(existing) ? existing : {}),
  ...(isObjectRecord(incoming) ? incoming : {}),
});

const mergeAuditLogs = (existing, incoming) =>
  mergeArrayRecordsById(existing, incoming)
    .sort((a, b) => getRecordTimestamp(b) - getRecordTimestamp(a))
    .slice(0, 500);

const rejectInvalidPendingCompletions = (data, now = new Date().toISOString()) => {
  const children = Array.isArray(data.children) ? data.children : [];
  const tasks = Array.isArray(data.tasks) ? data.tasks : [];
  const completions = Array.isArray(data.completions) ? data.completions : [];
  const childrenById = new Map(children.map((child) => [child.id, child]));
  const tasksById = new Map(tasks.map((task) => [task.id, task]));

  data.completions = completions.map((completion) => {
    if (!completion?.doneByChild || completion.approvedByParent) {
      return completion;
    }
    const child = childrenById.get(completion.childId);
    const task = tasksById.get(completion.taskId);
    if (
      child &&
      task &&
      task.childId === completion.childId &&
      isTaskActiveForDate(task, completion.date) &&
      !validateTaskCompletionDate(child, task, completion.date)
    ) {
      return completion;
    }
    return {
      ...completion,
      doneByChild: false,
      approvedByParent: false,
      approvedAt: null,
      rejectedByParent: true,
      rejectedAt: completion.rejectedAt || now,
      updatedAt: now,
    };
  });
};

const buildFamilySnapshot = async (familyId, viewer) =>
  prisma.$transaction(
    async (tx) => {
      const state = await tx.familyState.findUnique({ where: { familyId } });
      if (!state) {
        throw new Error('Brak stanu rodziny');
      }
      const data = normalizeStateData(state.data);
      // Derived values are computed for this representation only. GET endpoints
      // never persist this work or increment the aggregate version.
      recomputePointsAndGrants(data);
      const leaderboardChildren = data.children
        .filter((child) => !child.archived)
        .map((child) => ({ id: child.id, name: child.name, avatar: child.avatar }));
      const leaderboardPoints = Object.fromEntries(leaderboardChildren.map((child) => [child.id, Number(data.points[child.id] || 0)]));
      const leaderboardStreaks = Object.fromEntries(leaderboardChildren.map((child) => [child.id, data.streaks[child.id] || calculateStreakForChildData(data, child.id)]));
      const parentUsers = viewer.role === 'PARENT'
        ? await tx.user.findMany({
          where: { familyId, role: 'PARENT' },
          select: { id: true, email: true, active: true, pinCode: true },
          orderBy: { createdAt: 'asc' },
        })
        : [];
      const family = {
        children: filterStorageValueForUser('children', data, viewer),
        tasks: filterStorageValueForUser('tasks', data, viewer),
        completions: filterStorageValueForUser('completions', data, viewer),
        extraTasks: filterStorageValueForUser('extraTasks', data, viewer),
        pointAdjustments: filterStorageValueForUser('pointAdjustments', data, viewer),
        pointLedger: filterStorageValueForUser('pointLedger', data, viewer),
        rewards: filterStorageValueForUser('rewards', data, viewer),
        streaks: filterStorageValueForUser('streaks', data, viewer),
        points: filterStorageValueForUser('points', data, viewer),
        rewardUnlocks: filterStorageValueForUser('rewardUnlocks', data, viewer),
        familyGoal: filterStorageValueForUser('familyGoal', data, viewer),
        auditLogs: filterStorageValueForUser('auditLogs', data, viewer),
        dayPointGrants: filterStorageValueForUser('dayPointGrants', data, viewer),
        weekBonusGrants: filterStorageValueForUser('weekBonusGrants', data, viewer),
        taskPointGrants: filterStorageValueForUser('taskPointGrants', data, viewer),
        familyLeaderboard: {
          children: leaderboardChildren.slice().sort(compareChildrenForLeaderboard(leaderboardPoints, leaderboardStreaks)),
          points: leaderboardPoints,
          streaks: leaderboardStreaks,
        },
        rewardUnlockHistory: viewer.role === 'PARENT' ? getRewardUnlockHistory(data) : [],
        parentUsers: parentUsers.map((user) => ({
          id: user.id,
          email: user.email,
          active: user.active,
          hasPinCode: Boolean(user.pinCode),
        })),
      };
      return {
        familyId,
        version: getFamilyStateVersion(state),
        generatedAt: state.updatedAt.toISOString(),
        viewer: {
          id: viewer.id,
          email: viewer.email || null,
          role: viewer.role,
          familyId: viewer.familyId,
          childId: viewer.childId || null,
          childName: viewer.childName || null,
          hasPinCode: Boolean(viewer.hasPinCode),
          sessionRef: viewer.sessionRef,
        },
        permissions: {
          canManageFamily: viewer.role === 'PARENT',
          canManageOwnChildTasks: viewer.role === 'CHILD',
        },
        family,
      };
    },
    { isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead },
  );

const buildFamilySnapshotEtag = (snapshot) => {
  const scope = snapshot.viewer.role === 'CHILD'
    ? `child-${snapshot.viewer.childId}`
    : 'parent';
  const computedForDay = new Date().toISOString().slice(0, 10);
  return `"family-${snapshot.familyId}-viewer-${snapshot.viewer.id}-role-${snapshot.viewer.role.toLowerCase()}-scope-${scope}-v${snapshot.version}-day-${computedForDay}"`;
};

const mergeParentStorageValues = (data, values) => {
  const nextData = { ...data, ...values };
  if (Object.prototype.hasOwnProperty.call(values, 'children')) {
    nextData.children = data.children;
  }
  if (Object.prototype.hasOwnProperty.call(values, 'tasks')) {
    nextData.tasks = mergeArrayRecordsById(data.tasks, values.tasks);
  }
  if (Object.prototype.hasOwnProperty.call(values, 'completions')) {
    nextData.completions = mergeArrayRecordsById(data.completions, values.completions);
  }
  if (Object.prototype.hasOwnProperty.call(values, 'extraTasks')) {
    nextData.extraTasks = mergeArrayRecordsById(data.extraTasks, values.extraTasks);
  }
  if (Object.prototype.hasOwnProperty.call(values, 'pointAdjustments')) {
    nextData.pointAdjustments = mergeArrayRecordsById(data.pointAdjustments, values.pointAdjustments);
  }
  if (Object.prototype.hasOwnProperty.call(values, 'rewards')) {
    nextData.rewards = mergeArrayRecordsById(data.rewards, values.rewards);
  }
  if (Object.prototype.hasOwnProperty.call(values, 'rewardUnlocks')) {
    nextData.rewardUnlocks = mergeArrayRecordsById(data.rewardUnlocks, values.rewardUnlocks);
  }
  if (Object.prototype.hasOwnProperty.call(values, 'auditLogs')) {
    nextData.auditLogs = mergeAuditLogs(data.auditLogs, values.auditLogs);
  }
  // Points are server-authoritative. They are changed by approvals, extra tasks,
  // bonuses and penalties, not by client storage snapshots. Accepting snapshot
  // points can resurrect stale values after a penalty.
  nextData.points = data.points;
  nextData.pointLedger = data.pointLedger;
  if (Object.prototype.hasOwnProperty.call(values, 'streaks')) {
    nextData.streaks = mergeObjectMap(data.streaks, values.streaks);
  }
  if (Object.prototype.hasOwnProperty.call(values, 'dayPointGrants')) {
    nextData.dayPointGrants = mergeObjectMap(data.dayPointGrants, values.dayPointGrants);
  }
  if (Object.prototype.hasOwnProperty.call(values, 'weekBonusGrants')) {
    nextData.weekBonusGrants = mergeObjectMap(data.weekBonusGrants, values.weekBonusGrants);
  }
  if (Object.prototype.hasOwnProperty.call(values, 'taskPointGrants')) {
    nextData.taskPointGrants = mergeObjectMap(data.taskPointGrants, values.taskPointGrants);
  }
  if (
    Object.prototype.hasOwnProperty.call(values, 'children') ||
    Object.prototype.hasOwnProperty.call(values, 'tasks') ||
    Object.prototype.hasOwnProperty.call(values, 'completions') ||
    Object.prototype.hasOwnProperty.call(values, 'streaks')
  ) {
    rejectInvalidPendingCompletions(nextData);
    refreshAllStreaks(nextData);
  }
  return nextData;
};

const mergeStorageValuesForUser = (data, values, user) => {
  if (user.role !== 'CHILD') {
    return mergeParentStorageValues(data, values);
  }

  const nextData = { ...data };
  const childId = user.childId;
  if (Object.prototype.hasOwnProperty.call(values, 'completions')) {
    nextData.completions = mergeChildCompletions(data, values.completions, childId);
    rejectInvalidPendingCompletions(nextData);
  }
  if (Object.prototype.hasOwnProperty.call(values, 'rewardUnlocks')) {
    nextData.rewardUnlocks = mergeChildRewardUnlocks(data, values.rewardUnlocks, childId);
  }
  return nextData;
};

const CHILD_STORAGE_KEYS = new Set([
  'children',
  'tasks',
  'completions',
  'extraTasks',
  'pointAdjustments',
  'pointLedger',
  'rewards',
  'streaks',
  'points',
  'rewardUnlocks',
  'familyGoal',
  'auditLogs',
  'dayPointGrants',
  'weekBonusGrants',
  'taskPointGrants',
]);

app.use('/api/auth/login', authRateLimit);
app.use('/api/auth/register', authRateLimit);
app.use('/api/auth/forgot-password', authRateLimit);
app.use('/api/auth/reset-password/token', authRateLimit);
app.use('/api/auth/login-child', authRateLimit);
app.use('/api/auth/parent-pin/verify', authRateLimit);
app.use('/api', idempotencyMiddleware);

app.get('/health', async (req, res) => {
  let db = 'ok';
  try {
    await prisma.$queryRaw`SELECT 1`;
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    db = 'error';
  }
  res.json({
    status: db === 'ok' ? 'ok' : 'degraded',
    db,
    timestamp: new Date().toISOString(),
  });
});

app.get('/livez', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
  });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    if (!ALLOW_PUBLIC_REGISTRATION) {
      res.status(403).json({ error: 'Publiczna rejestracja jest wyłączona' });
      return;
    }

    const parsed = registerSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane rejestracji' });
      return;
    }
    const email = parsed.data.email.trim().toLowerCase();
    const password = parsed.data.password;
    const familyName = (parsed.data.familyName || '').trim();
    const pinCode = parsed.data.pinCode || null;

    const emailExists = await prisma.user.findUnique({ where: { email } });
    if (emailExists) {
      res.status(409).json({ error: 'Konto z tym adresem email już istnieje' });
      return;
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const pinCodeHash = pinCode ? await bcrypt.hash(pinCode, BCRYPT_ROUNDS) : null;

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
          pinCode: pinCodeHash,
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
    setAuthCookie(req, res, token);
    res.status(201).json({
      token,
      user: toPublicUser(created, getSessionRef(token)),
    });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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
    setAuthCookie(req, res, token);
    res.json({
      token,
      user: toPublicUser(user, getSessionRef(token)),
    });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Login error:', error);
    res.status(500).json({ error: 'Logowanie nie powiodło się' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  res.json({ user: req.auth.user });
});

app.get('/api/family-state', authMiddleware, async (req, res) => {
  if (!FAMILY_SNAPSHOT_ENABLED) {
    res.status(404).json({ code: 'FAMILY_SNAPSHOT_DISABLED', error: 'Snapshot synchronizacji jest tymczasowo wyłączony.' });
    return;
  }
  const startedAt = Date.now();
  try {
    const snapshot = await buildFamilySnapshot(req.auth.user.familyId, req.auth.user);
    const etag = buildFamilySnapshotEtag(snapshot);
    res.set('ETag', etag);
    res.set('Cache-Control', 'private, must-revalidate');
    if (req.get('If-None-Match') === etag) {
      recordSyncMetric('snapshot_not_modified');
      res.status(304).end();
      return;
    }
    recordSyncMetric('snapshot_success');
    res.json(snapshot);
  } catch (error) {
    recordSyncMetric('snapshot_error');
    console.error('Family snapshot error:', error);
    res.status(500).json({ error: 'Nie udało się pobrać spójnego stanu rodziny' });
  } finally {
    recordSyncMetric('snapshot_duration_ms', Date.now() - startedAt);
  }
});

app.get('/api/sync/metrics', authMiddleware, requireParent, (req, res) => {
  res.json({ metrics: getSyncMetrics() });
});

app.post('/api/auth/parent-pin/verify', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = verifyParentPinSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'PIN musi mieć dokładnie 6 cyfr' });
      return;
    }
    const blocked = getParentPinBlockedResponse(req);
    if (blocked) {
      res.status(429).json({
        error: `Za dużo błędnych PIN-ów. Spróbuj za ${blocked.retryAfterSeconds} s.`,
        retryAfterSeconds: blocked.retryAfterSeconds,
      });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id: req.auth.user.id },
      select: { id: true, pinCode: true },
    });
    if (!user?.pinCode) {
      res.status(409).json({ error: 'Najpierw ustaw 6-cyfrowy PIN rodzica' });
      return;
    }

    const ok = await bcrypt.compare(parsed.data.pinCode, user.pinCode);
    if (!ok) {
      const failure = recordParentPinFailure(req);
      const retryAfterSeconds = failure.lockedUntil > Date.now()
        ? Math.max(1, Math.ceil((failure.lockedUntil - Date.now()) / 1000))
        : null;
      res.status(retryAfterSeconds ? 429 : 401).json({
        error: retryAfterSeconds
          ? `Za dużo błędnych PIN-ów. Spróbuj za ${retryAfterSeconds} s.`
          : 'Nieprawidłowy PIN rodzica',
        retryAfterSeconds,
        attemptsRemaining: retryAfterSeconds
          ? 0
          : Math.max(0, PARENT_PIN_FAILED_MAX_ATTEMPTS - failure.count),
      });
      return;
    }

    clearParentPinFailures(req);
    res.json({ ok: true });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Parent PIN verify error:', error);
    res.status(500).json({ error: 'Nie udało się sprawdzić PIN-u' });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  try {
    const token = readBearerToken(req);
    if (token) {
      try {
        const payload = jwt.verify(token, JWT_SECRET);
        await revokeJwtPayload(payload);
      } catch {
        // Logout must still clear the browser cookie when the token is already invalid.
      }
    }
    clearAuthCookie(req, res);
    res.json({ ok: true });
  } catch (error) {
    console.error('Logout error:', error);
    clearAuthCookie(req, res);
    res.json({ ok: true });
  }
});

app.put('/api/auth/pin', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = changePinSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'PIN musi mieć dokładnie 6 cyfr' });
      return;
    }
    const existingUser = await prisma.user.findUnique({
      where: { id: req.auth.user.id },
      select: { id: true, passwordHash: true },
    });
    if (!existingUser) {
      res.status(404).json({ error: 'Użytkownik nie istnieje' });
      return;
    }
    if (!parsed.data.currentPassword) {
      res.status(400).json({ error: 'Podaj aktualne hasło, aby zmienić PIN' });
      return;
    }
    const passwordOk = await bcrypt.compare(parsed.data.currentPassword, existingUser.passwordHash);
    if (!passwordOk) {
      res.status(401).json({ error: 'Aktualne hasło jest nieprawidłowe' });
      return;
    }
    const pinCodeHash = await bcrypt.hash(parsed.data.pinCode, BCRYPT_ROUNDS);

    const user = await prisma.user.update({
      where: { id: req.auth.user.id },
      data: { pinCode: pinCodeHash },
    });
    res.json({ user: toPublicUser(user) });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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
      data: { passwordHash, authVersion: { increment: 1 } },
    });

    res.json({ ok: true });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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
        pinCode: true,
      },
    });
    res.json({
      users: users.map((user) => ({
        id: user.id,
        email: user.email,
        active: user.active,
        role: user.role,
        createdAt: user.createdAt,
        hasPinCode: Boolean(user.pinCode),
      })),
    });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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
    const pinCodeHash = parsed.data.pinCode ? await bcrypt.hash(parsed.data.pinCode, BCRYPT_ROUNDS) : null;

    const exists = await prisma.user.findUnique({ where: { email } });
    if (exists) {
      res.status(409).json({ error: 'Użytkownik o tym email już istnieje' });
      return;
    }

    const created = await prisma.user.create({
      data: {
        email,
        passwordHash,
        pinCode: pinCodeHash,
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
        pinCode: true,
      },
    });

    res.status(201).json({
      user: {
        id: created.id,
        email: created.email,
        active: created.active,
        role: created.role,
        createdAt: created.createdAt,
        hasPinCode: Boolean(created.pinCode),
      },
    });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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
        pinCode: true,
      },
    });

    res.json({
      user: {
        id: updated.id,
        email: updated.email,
        active: updated.active,
        role: updated.role,
        createdAt: updated.createdAt,
        hasPinCode: Boolean(updated.pinCode),
      },
    });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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
      data: { passwordHash, authVersion: { increment: 1 } },
    });
    res.json({ ok: true });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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
      const token = crypto.randomBytes(24).toString('hex');
      await prisma.passwordResetToken.deleteMany({
        where: { userId: user.id },
      });
      await prisma.passwordResetToken.create({
        data: {
          userId: user.id,
          tokenHash: getPasswordResetTokenHash(token),
          expiresAt: new Date(Date.now() + RESET_TOKEN_TTL_MS),
        },
      });
      debugToken = token;
    }

    res.json({
      ok: true,
      message: 'Jeśli konto istnieje, instrukcja resetu została wysłana.',
      ...(ALLOW_DEBUG_RESET_TOKEN && debugToken ? { debugResetToken: debugToken } : {}),
    });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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

    const reset = await prisma.passwordResetToken.findUnique({
      where: { tokenHash: getPasswordResetTokenHash(parsed.data.token) },
    });
    if (!reset || reset.usedAt || reset.expiresAt < new Date()) {
      res.status(400).json({ error: 'Token resetu wygasł lub jest nieprawidłowy' });
      return;
    }

    const passwordHash = await bcrypt.hash(parsed.data.newPassword, BCRYPT_ROUNDS);
    await prisma.$transaction([
      prisma.user.update({
        where: { id: reset.userId },
        data: { passwordHash, authVersion: { increment: 1 } },
      }),
      prisma.passwordResetToken.update({
        where: { id: reset.id },
        data: { usedAt: new Date() },
      }),
      prisma.passwordResetToken.deleteMany({
        where: {
          userId: reset.userId,
          id: { not: reset.id },
        },
      }),
    ]);
    res.json({ ok: true });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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
    const codeLookupHash = getChildAccessCodeLookupHash(accessCode);
    const temporaryBlock = getBlockedChildLoginFailure(req, codeLookupHash);
    if (temporaryBlock) {
      const retryAfterSeconds = Math.max(1, Math.ceil((temporaryBlock.resetAt - Date.now()) / 1000));
      res.set('Retry-After', String(retryAfterSeconds));
      res.status(429).json({
        error: 'Zbyt wiele błędnych kodów. Spróbuj ponownie za chwilę.',
      });
      return;
    }

    const credential = await findChildAccessCredentialByCode(accessCode);
    const codeOk = credential?.active ? await bcrypt.compare(accessCode, credential.codeHash) : false;
    if (!credential || !codeOk) {
      recordChildLoginFailure(req, codeLookupHash);
      res.status(401).json({ error: 'Nieprawidłowy kod dostępu dziecka' });
      return;
    }

    const state = await getOrCreateState(credential.familyId);
    const data = normalizeStateData(state.data);
    const child = data.children.find((item) => item.id === credential.childId && !item.archived);
    if (!child) {
      await deactivateChildAccessCredential(prisma, credential.familyId, credential.childId);
      recordChildLoginFailure(req, codeLookupHash);
      res.status(401).json({ error: 'Nieprawidłowy kod dostępu dziecka' });
      return;
    }

    const token = signChildToken({
      familyId: credential.familyId,
      childId: child.id,
      childName: child.name,
      credentialId: credential.id,
    });
    setAuthCookie(req, res, token, { persistent: false });
    clearChildLoginFailures(req, codeLookupHash);

    res.json({
      token,
      user: {
        id: `child:${child.id}`,
        role: 'CHILD',
        familyId: credential.familyId,
        childId: child.id,
        childName: child.name,
        sessionRef: getSessionRef(token),
      },
    });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Child login error:', error);
    res.status(500).json({ error: 'Logowanie dziecka nie powiodło się' });
  }
});

app.get('/api/task-templates', authMiddleware, async (req, res) => {
  res.json({ templates: TASK_TEMPLATES });
});

app.get('/api/leaderboard', authMiddleware, async (req, res) => {
  try {
    const { data } = await loadStateData(req.auth.user.familyId);
    recomputePointsAndGrants(data);
    const children = data.children
      .filter((child) => !child.archived)
      .map((child) => ({
        id: child.id,
        name: child.name,
        avatar: child.avatar,
      }));
    const allowedIds = new Set(children.map((child) => child.id));
    const points = {};
    const streaks = {};

    children.forEach((child) => {
      points[child.id] = Number(data.points[child.id] || 0);
      streaks[child.id] = calculateStreakForChildData(data, child.id);
    });
    const rankedChildren = children.sort(compareChildrenForLeaderboard(points, streaks));

    res.json({
      children: rankedChildren.filter((child) => allowedIds.has(child.id)),
      points,
      streaks,
    });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Leaderboard error:', error);
    res.status(500).json({ error: 'Nie udało się pobrać tablicy wyników' });
  }
});

app.get('/api/point-ledger', authMiddleware, async (req, res) => {
  try {
    const parsed = pointLedgerQuerySchema.safeParse(req.query || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe parametry historii punktów' });
      return;
    }

    const { childId, limit, cursor } = parsed.data;
    const effectiveChildId = req.auth.user.role === 'CHILD' ? req.auth.user.childId : childId;
    if (!effectiveChildId) {
      res.status(400).json({ error: 'Wybierz dziecko dla historii punktów' });
      return;
    }
    if (!hasChildAccess(req, effectiveChildId)) {
      res.status(403).json({ error: 'Brak dostępu do historii punktów tego dziecka' });
      return;
    }

    const { data } = await loadStateData(req.auth.user.familyId);
    // Historia punktów jest odczytem. Przeliczenie służy tylko zbudowaniu
    // bieżącej reprezentacji i nie może zmieniać wersji FamilyState.
    recomputePointsAndGrantsIfChanged(data);

    const entries = data.pointLedger
      .filter((entry) => entry.childId === effectiveChildId)
      .sort(compareLedgerEventsDescending);
    const pageEntries = entries.slice(cursor, cursor + limit);
    const nextCursor = cursor + pageEntries.length < entries.length ? cursor + pageEntries.length : null;

    res.json({
      childId: effectiveChildId,
      entries: pageEntries,
      nextCursor,
      limit,
      total: entries.length,
    });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Point ledger error:', error);
    res.status(500).json({ error: 'Nie udało się pobrać historii punktów' });
  }
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

    res.json({ children: list.map((child) => sanitizeChildForStorage(child)) });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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

    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const saveTxStateData = createSaveStateData(tx.familyState);
      const id = createEntityId('child');
      const activeDays = normalizeActiveDays(parsed.data.activeDays);
      if (activeDays.length === 0) {
        return { status: 400, body: { error: 'Dziecko musi mieć co najmniej 1 dzień aktywny' } };
      }
      const accessCode = await pickGloballyUniqueChildAccessCode(
        { preferredCode: parsed.data.accessCode || null },
        tx,
      );
      if (!accessCode) {
        return { status: 409, body: { error: 'Kod dostępu dziecka jest zajęty' } };
      }

      const child = {
        id,
        name: parsed.data.name.trim(),
        avatar: parsed.data.avatar.trim(),
        activeDays,
        archived: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      data.children = [...data.children, child];
      await setChildAccessCredential(tx, {
        familyId: req.auth.user.familyId,
        childId: id,
        accessCode,
      });
      data.streaks = { ...data.streaks, [id]: { current: 0, best: 0, idealWeeksCount: 0, idealWeeksInRow: 0 } };
      data.points = { ...data.points, [id]: 0 };
      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'ADD_CHILD', 'CHILD', id, {
        name: child.name,
        activeDays: child.activeDays,
      });

      await saveTxStateData(state, data);
      return { status: 201, body: { child: attachOneTimeAccessCode(child, accessCode) } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const saveTxStateData = createSaveStateData(tx.familyState);
      const index = data.children.findIndex((child) => child.id === childId);
      if (index < 0) {
        return { status: 404, body: { error: 'Dziecko nie istnieje' } };
      }

      const current = data.children[index];
      const next = { ...current };
      let oneTimeAccessCode = null;
      if (typeof parsed.data.name === 'string') next.name = parsed.data.name.trim();
      if (typeof parsed.data.avatar === 'string') next.avatar = parsed.data.avatar.trim();
      if (Array.isArray(parsed.data.activeDays)) {
        const normalized = normalizeActiveDays(parsed.data.activeDays);
        if (normalized.length === 0) {
          return { status: 400, body: { error: 'Dziecko musi mieć co najmniej 1 dzień aktywny' } };
        }
        next.activeDays = normalized;
      }
      if (typeof parsed.data.accessCode === 'string') {
        const accessCode = await pickGloballyUniqueChildAccessCode(
          {
            preferredCode: parsed.data.accessCode,
            excludeFamilyId: req.auth.user.familyId,
            excludeChildId: childId,
          },
          tx,
        );
        if (!accessCode) {
          return { status: 409, body: { error: 'Kod dostępu dziecka jest zajęty' } };
        }
        await setChildAccessCredential(tx, {
          familyId: req.auth.user.familyId,
          childId,
          accessCode,
        });
        oneTimeAccessCode = accessCode;
      }
      next.updatedAt = new Date().toISOString();

      data.children[index] = next;
      const auditDetails = { ...parsed.data };
      if (Object.prototype.hasOwnProperty.call(auditDetails, 'accessCode')) {
        auditDetails.accessCodeChanged = true;
        delete auditDetails.accessCode;
      }
      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'UPDATE_CHILD', 'CHILD', childId, auditDetails);
      await saveTxStateData(state, data);
      return { status: 200, body: { child: attachOneTimeAccessCode(next, oneTimeAccessCode) } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Child update error:', error);
    res.status(500).json({ error: 'Nie udało się zaktualizować dziecka' });
  }
});

app.delete('/api/children/:id', authMiddleware, requireParent, async (req, res) => {
  try {
    const childId = String(req.params.id || '');
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const saveTxStateData = createSaveStateData(tx.familyState);
      const child = data.children.find((item) => item.id === childId);
      if (!child) {
        return { status: 404, body: { error: 'Dziecko nie istnieje' } };
      }

      child.archived = true;
      child.updatedAt = new Date().toISOString();
      await deactivateChildAccessCredential(tx, req.auth.user.familyId, childId);
      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'ARCHIVE_CHILD', 'CHILD', childId);
      await saveTxStateData(state, data);
      return { status: 200, body: { ok: true } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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

    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const child = data.children.find((item) => item.id === parsed.data.childId && !item.archived);
      if (!child) return { status: 404, body: { error: 'Nie znaleziono dziecka dla tego zadania' } };

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
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 201, body: { task } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const index = data.tasks.findIndex((item) => item.id === taskId);
      if (index < 0) return { status: 404, body: { error: 'Zadanie nie istnieje' } };

      const next = { ...data.tasks[index] };
      if (typeof parsed.data.childId === 'string') {
        const child = data.children.find((item) => item.id === parsed.data.childId && !item.archived);
        if (!child) return { status: 404, body: { error: 'Nie znaleziono dziecka dla tego zadania' } };
        next.childId = parsed.data.childId;
      }
      if (typeof parsed.data.title === 'string') next.title = parsed.data.title.trim();
      if (typeof parsed.data.tier === 'string') next.tier = parsed.data.tier;
      if (typeof parsed.data.points === 'number') next.points = parsed.data.points;
      if (typeof parsed.data.description === 'string' || parsed.data.description === null) next.description = parsed.data.description || '';
      if (parsed.data.daysOfWeek !== undefined) next.daysOfWeek = normalizeTaskDaysOfWeek(parsed.data.daysOfWeek);
      if (typeof parsed.data.active === 'boolean') {
        next.active = parsed.data.active;
        if (parsed.data.active) {
          if (next.archivedAt) next.restoredAt = new Date().toISOString();
        } else if (!next.archivedAt) {
          next.archivedAt = new Date().toISOString();
          next.restoredAt = null;
        }
      }
      next.updatedAt = new Date().toISOString();

      const current = data.tasks[index];
      const hasApprovedHistory = data.completions.some(
        (completion) => completion.taskId === taskId && completion.approvedByParent,
      );
      const changesHistoricalRules =
        current.childId !== next.childId ||
        current.tier !== next.tier ||
        Number(current.points || 0) !== Number(next.points || 0) ||
        JSON.stringify(normalizeTaskDaysOfWeek(current.daysOfWeek)) !== JSON.stringify(normalizeTaskDaysOfWeek(next.daysOfWeek));
      if (hasApprovedHistory && changesHistoricalRules) {
        return {
          status: 409,
          body: {
            error:
              'Nie można zmienić punktów, typu, harmonogramu ani dziecka dla zadania z zatwierdzoną historią. Zarchiwizuj je i utwórz nowe zadanie.',
          },
        };
      }

      data.tasks[index] = next;
      rejectInvalidPendingCompletions(data);
      recomputePointsAndGrants(data);
      reconcileRewardUnlocksForAllChildren(data, req.auth.user.id);
      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'UPDATE_TASK', 'TASK', taskId, parsed.data);
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 200, body: { task: next } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Task update error:', error);
    res.status(500).json({ error: 'Nie udało się zaktualizować zadania' });
  }
});

app.delete('/api/tasks/:id', authMiddleware, requireParent, async (req, res) => {
  try {
    const taskId = String(req.params.id || '');
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const task = data.tasks.find((item) => item.id === taskId);
      if (!task) return { status: 404, body: { error: 'Zadanie nie istnieje' } };

      const now = new Date().toISOString();
      task.active = false;
      task.archivedAt = task.archivedAt || now;
      task.updatedAt = now;
      recomputePointsAndGrants(data);
      reconcileRewardUnlocksForAllChildren(data, req.auth.user.id, now);
      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'ARCHIVE_TASK', 'TASK', taskId, {
        childId: task.childId,
        title: task.title,
        archivedAt: task.archivedAt,
      });
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 200, body: { ok: true, archivedTaskIds: [task.id], archivedCount: 1, archivedAt: task.archivedAt } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Task archive error:', error);
    res.status(500).json({ error: 'Nie udało się zarchiwizować zadania' });
  }
});

app.post('/api/tasks/:id/archive-matching', authMiddleware, requireParent, async (req, res) => {
  try {
    const taskId = String(req.params.id || '');
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const sourceTask = data.tasks.find((item) => item.id === taskId);
      if (!sourceTask) return { status: 404, body: { error: 'Zadanie nie istnieje' } };

      const sourceFingerprint = getTaskArchiveFingerprint(sourceTask);
      const now = new Date().toISOString();
      const archivedTaskIds = [];
      data.tasks.forEach((task) => {
        if (task.active === false || getTaskArchiveFingerprint(task) !== sourceFingerprint) return;
        task.active = false;
        task.archivedAt = task.archivedAt || now;
        task.updatedAt = now;
        archivedTaskIds.push(task.id);
      });
      if (archivedTaskIds.length === 0) {
        return { status: 409, body: { error: 'Nie znaleziono aktywnych pasujących zadań do archiwizacji' } };
      }

      recomputePointsAndGrants(data);
      reconcileRewardUnlocksForAllChildren(data, req.auth.user.id, now);
      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'ARCHIVE_TASKS_MATCHING', 'TASK', taskId, {
        archivedTaskIds,
        archivedCount: archivedTaskIds.length,
        title: sourceTask.title,
        tier: sourceTask.tier,
        archivedAt: now,
      });
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 200, body: { ok: true, archivedTaskIds, archivedCount: archivedTaskIds.length, archivedAt: now } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Matching task archive error:', error);
    res.status(500).json({ error: 'Nie udało się zarchiwizować pasujących zadań' });
  }
});

app.post('/api/tasks/:id/restore', authMiddleware, requireParent, async (req, res) => {
  try {
    const taskId = String(req.params.id || '');
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const task = data.tasks.find((item) => item.id === taskId);
      if (!task) return { status: 404, body: { error: 'Zadanie nie istnieje' } };
      if (task.active !== false) return { status: 409, body: { error: 'Zadanie jest już aktywne' } };

      const now = new Date().toISOString();
      task.active = true;
      task.restoredAt = now;
      task.updatedAt = now;
      recomputePointsAndGrants(data);
      reconcileRewardUnlocksForAllChildren(data, req.auth.user.id, now);
      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'RESTORE_TASK', 'TASK', taskId, {
        childId: task.childId,
        title: task.title,
        archivedAt: task.archivedAt || null,
        restoredAt: task.restoredAt,
      });
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 200, body: { ok: true, task, restoredAt: task.restoredAt } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Task restore error:', error);
    res.status(500).json({ error: 'Nie udało się przywrócić zadania' });
  }
});

app.post('/api/tasks/:id/restore-matching', authMiddleware, requireParent, async (req, res) => {
  try {
    const taskId = String(req.params.id || '');
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const sourceTask = data.tasks.find((item) => item.id === taskId);
      if (!sourceTask) return { status: 404, body: { error: 'Zadanie nie istnieje' } };

      const sourceFingerprint = getTaskArchiveFingerprint(sourceTask);
      const now = new Date().toISOString();
      const restoredTaskIds = [];
      data.tasks.forEach((task) => {
        if (task.active !== false || getTaskArchiveFingerprint(task) !== sourceFingerprint) return;
        task.active = true;
        task.restoredAt = now;
        task.updatedAt = now;
        restoredTaskIds.push(task.id);
      });
      if (restoredTaskIds.length === 0) {
        return { status: 409, body: { error: 'Nie znaleziono zarchiwizowanych pasujących zadań do przywrócenia' } };
      }

      recomputePointsAndGrants(data);
      reconcileRewardUnlocksForAllChildren(data, req.auth.user.id, now);
      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'RESTORE_TASKS_MATCHING', 'TASK', taskId, {
        restoredTaskIds,
        restoredCount: restoredTaskIds.length,
        title: sourceTask.title,
        tier: sourceTask.tier,
        restoredAt: now,
      });
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 200, body: { ok: true, restoredTaskIds, restoredCount: restoredTaskIds.length, restoredAt: now } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Matching task restore error:', error);
    res.status(500).json({ error: 'Nie udało się przywrócić pasujących zadań' });
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
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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

    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const child = data.children.find((item) => item.id === parsed.data.childId && !item.archived);
      if (!child) return { status: 404, body: { error: 'Dziecko nie istnieje' } };
      const task = data.tasks.find((item) => item.id === parsed.data.taskId && item.childId === parsed.data.childId);
      if (!task || !isTaskActiveForDate(task, parsed.data.date)) {
        return { status: 404, body: { error: 'Zadanie nie istnieje lub jest nieaktywne' } };
      }
      const completionDateError = validateTaskCompletionDate(child, task, parsed.data.date);
      if (completionDateError) return { status: 400, body: { error: completionDateError } };

      const existing = data.completions.find(
        (item) =>
          item.taskId === parsed.data.taskId &&
          item.childId === parsed.data.childId &&
          item.date === parsed.data.date,
      );
      const now = new Date().toISOString();
      const saveTxStateData = createSaveStateData(tx.familyState);

      if (existing) {
        if (existing.approvedByParent) {
          if (parsed.data.doneByChild !== true) {
            return {
              status: 409,
              body: { error: 'Zatwierdzonego zadania nie można cofnąć bez jawnej korekty punktów' },
            };
          }
          return { status: 200, body: { completion: existing } };
        }
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
        await saveTxStateData(state, data);
        return { status: 200, body: { completion: existing } };
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
      await saveTxStateData(state, data);
      return { status: 201, body: { completion } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Pending completions error:', error);
    res.status(500).json({ error: 'Nie udało się pobrać kolejki zatwierdzeń' });
  }
});

app.post('/api/completions/:id/approve', authMiddleware, requireParent, async (req, res) => {
  try {
    const completionId = String(req.params.id || '');
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const completion = data.completions.find((item) => item.id === completionId);
      if (!completion) {
        return { status: 404, body: { error: 'Wykonanie nie istnieje' } };
      }
      if (completion.approvedByParent) {
        return { status: 409, body: { error: 'Zadanie jest już zatwierdzone' } };
      }

      const now = new Date().toISOString();
      if (!applyApprovalEffects(data, completion, req.auth.user.id, now)) {
        return { status: 409, body: { error: 'Nie można zatwierdzić nieaktywnego lub niepoprawnego zadania' } };
      }

      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'APPROVE_TASK', 'COMPLETION', completionId, {
        childId: completion.childId,
        taskId: completion.taskId,
        date: completion.date,
      });
      const statePatch = buildFamilyStatePatch(data, req.auth.user);
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 200, body: { completion, statePatch } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Approve completion error:', error);
    res.status(500).json({ error: 'Nie udało się zatwierdzić zadania' });
  }
});

app.post('/api/completions/:id/reject', authMiddleware, requireParent, async (req, res) => {
  try {
    const completionId = String(req.params.id || '');
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const completion = data.completions.find((item) => item.id === completionId);
      if (!completion) {
        return { status: 404, body: { error: 'Wykonanie nie istnieje' } };
      }
      if (completion.approvedByParent) {
        return {
          status: 409,
          body: { error: 'Zatwierdzonego zadania nie można odrzucić bez jawnej korekty punktów' },
        };
      }
      const child = data.children.find((item) => item.id === completion.childId && !item.archived);
      const task = data.tasks.find((item) => item.id === completion.taskId && item.childId === completion.childId);
      if (!child || !task || !isTaskActiveForDate(task, completion.date)) {
        return { status: 404, body: { error: 'Zadanie lub dziecko nie istnieje' } };
      }
      const completionDateError = validateTaskCompletionDate(child, task, completion.date);
      if (completionDateError) {
        return { status: 400, body: { error: completionDateError } };
      }

      const now = new Date().toISOString();
      completion.doneByChild = false;
      completion.approvedByParent = false;
      completion.approvedAt = null;
      completion.rejectedByParent = true;
      completion.rejectedAt = now;
      completion.updatedAt = now;
      refreshChildStreak(data, completion.childId, now);

      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'REJECT_TASK', 'COMPLETION', completionId, {
        childId: completion.childId,
        taskId: completion.taskId,
        date: completion.date,
      });
      const statePatch = buildFamilyStatePatch(data, req.auth.user);
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 200, body: { completion, statePatch } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Reject completion error:', error);
    res.status(500).json({ error: 'Nie udało się odrzucić zadania' });
  }
});

app.post('/api/completions/:id/reverse-approval', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = reverseApprovalSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowy powód cofnięcia zatwierdzenia' });
      return;
    }

    const completionId = String(req.params.id || '');
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const completion = data.completions.find((item) => item.id === completionId);
      if (!completion) {
        return { status: 404, body: { error: 'Wykonanie nie istnieje' } };
      }
      if (!completion.approvedByParent) {
        return { status: 409, body: { error: 'Tylko zatwierdzone zadanie można cofnąć' } };
      }

      const body = reverseApprovalEffects(data, completion, req.auth.user.id, parsed.data.reason || '');
      if (!body) {
        return { status: 409, body: { error: 'Nie udało się cofnąć zatwierdzenia' } };
      }

      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 200, body };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Reverse approval error:', error);
    res.status(500).json({ error: 'Nie udało się cofnąć zatwierdzenia' });
  }
});

app.post('/api/completions/approve-bulk', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = bulkApproveSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe filtry zatwierdzania zbiorczego' });
      return;
    }

    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const now = new Date().toISOString();
      const approvedIds = [];
      const requestedIds = parsed.data.ids ? new Set(parsed.data.ids) : null;

      data.completions.forEach((completion) => {
        if (!completion.doneByChild || completion.approvedByParent) {
          return;
        }
        if (requestedIds && !requestedIds.has(completion.id)) {
          return;
        }
        if (parsed.data.childId && completion.childId !== parsed.data.childId) {
          return;
        }
        if (parsed.data.date && completion.date !== parsed.data.date) {
          return;
        }

        if (applyApprovalEffects(data, completion, req.auth.user.id, now)) {
          approvedIds.push(completion.id);
        }
      });

      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'APPROVE_TASKS_BULK', 'COMPLETION', 'bulk', {
        approvedCount: approvedIds.length,
        requestedCount: requestedIds ? requestedIds.size : null,
        childId: parsed.data.childId || null,
        date: parsed.data.date || null,
      });
      const statePatch = buildFamilyStatePatch(data, req.auth.user);
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 200, body: { ok: true, approvedCount: approvedIds.length, approvedIds, statePatch } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Bulk approve error:', error);
    res.status(500).json({ error: 'Nie udało się zatwierdzić zadań zbiorczo' });
  }
});

app.post('/api/completions/reject-bulk', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = bulkRejectSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe filtry odrzucania zbiorczego' });
      return;
    }

    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const now = new Date().toISOString();
      const rejectedIds = [];
      const skippedApprovedIds = [];
      const requestedIds = parsed.data.ids ? new Set(parsed.data.ids) : null;
      const affectedChildIds = new Set();

      data.completions.forEach((completion) => {
        if (!completion.doneByChild || completion.rejectedByParent) {
          return;
        }
        if (requestedIds && !requestedIds.has(completion.id)) {
          return;
        }
        if (parsed.data.childId && completion.childId !== parsed.data.childId) {
          return;
        }
        if (parsed.data.date && completion.date !== parsed.data.date) {
          return;
        }
        if (completion.approvedByParent) {
          skippedApprovedIds.push(completion.id);
          return;
        }

        completion.doneByChild = false;
        completion.approvedByParent = false;
        completion.approvedAt = null;
        completion.rejectedByParent = true;
        completion.rejectedAt = now;
        completion.updatedAt = now;
        rejectedIds.push(completion.id);
        affectedChildIds.add(completion.childId);
      });

      affectedChildIds.forEach((childId) => refreshChildStreak(data, childId, now));
      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'REJECT_TASKS_BULK', 'COMPLETION', 'bulk', {
        rejectedCount: rejectedIds.length,
        skippedApprovedCount: skippedApprovedIds.length,
        requestedCount: requestedIds ? requestedIds.size : null,
        childId: parsed.data.childId || null,
        date: parsed.data.date || null,
      });
      const statePatch = buildFamilyStatePatch(data, req.auth.user);
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return {
        status: 200,
        body: {
          ok: true,
          rejectedCount: rejectedIds.length,
          rejectedIds,
          skippedApprovedIds,
          statePatch,
        },
      };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Bulk reject error:', error);
    res.status(500).json({ error: 'Nie udało się odrzucić zadań zbiorczo' });
  }
});

app.get('/api/extra-tasks', authMiddleware, async (req, res) => {
  try {
    const childId = typeof req.query.childId === 'string' ? req.query.childId : null;
    const date = typeof req.query.date === 'string' ? req.query.date : null;
    const pendingOnly = String(req.query.pending || '') === 'true';
    const { data } = await loadStateData(req.auth.user.familyId);

    let list = data.extraTasks;
    if (req.auth.user.role === 'CHILD') {
      list = list.filter((task) => task.childId === req.auth.user.childId);
    } else if (childId) {
      list = list.filter((task) => task.childId === childId);
    }
    if (date) {
      list = list.filter((task) => task.date === date);
    }
    if (pendingOnly) {
      list = list.filter((task) => task.status === 'PENDING');
    }

    res.json({ extraTasks: list });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Extra task list error:', error);
    res.status(500).json({ error: 'Nie udało się pobrać zadań dodatkowych' });
  }
});

app.post('/api/extra-tasks', authMiddleware, async (req, res) => {
  try {
    const parsed = extraTaskSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane zadania dodatkowego' });
      return;
    }
    if (!hasChildAccess(req, parsed.data.childId)) {
      res.status(403).json({ error: 'Brak dostępu do profilu dziecka' });
      return;
    }

    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const child = data.children.find((item) => item.id === parsed.data.childId && !item.archived);
      if (!child) return { status: 404, body: { error: 'Dziecko nie istnieje' } };
      const extraTaskDate = parsed.data.date || toDateString(new Date());
      const extraTaskDateError = validateChildDate(child, extraTaskDate);
      if (extraTaskDateError) return { status: 400, body: { error: extraTaskDateError } };

      const now = new Date().toISOString();
      const extraTask = {
        id: createEntityId('extra'),
        childId: parsed.data.childId,
        title: parsed.data.title.trim(),
        date: extraTaskDate,
        status: 'PENDING',
        points: 1,
        approvedByParent: false,
        approvedAt: null,
        rejectedAt: null,
        submittedAt: now,
        createdAt: now,
        updatedAt: now,
      };

      data.extraTasks = [extraTask, ...data.extraTasks];
      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'ADD_EXTRA_TASK', 'EXTRA_TASK', extraTask.id, {
        childId: extraTask.childId,
        date: extraTask.date,
        title: extraTask.title,
      });
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 201, body: { extraTask } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Extra task create error:', error);
    res.status(500).json({ error: 'Nie udało się zgłosić zadania dodatkowego' });
  }
});

app.post('/api/extra-tasks/:id/approve', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = approveExtraTaskSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowa liczba punktów' });
      return;
    }

    const extraTaskId = String(req.params.id || '');
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const extraTask = data.extraTasks.find((item) => item.id === extraTaskId);
      if (!extraTask) {
        return { status: 404, body: { error: 'Zadanie dodatkowe nie istnieje' } };
      }
      if (extraTask.status === 'APPROVED') {
        const statePatch = buildFamilyStatePatch(data, req.auth.user);
        return { status: 200, body: { extraTask, statePatch } };
      }

      const now = new Date().toISOString();
      extraTask.status = 'APPROVED';
      extraTask.points = parsed.data.points;
      extraTask.approvedByParent = true;
      extraTask.approvedAt = now;
      extraTask.rejectedAt = null;
      extraTask.updatedAt = now;

      addPoints(data, extraTask.childId, parsed.data.points);
      unlockEligibleRewards(data, extraTask.childId, req.auth.user.id);
      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'APPROVE_EXTRA_TASK', 'EXTRA_TASK', extraTask.id, {
        childId: extraTask.childId,
        date: extraTask.date,
        points: parsed.data.points,
        title: extraTask.title,
      });

      const statePatch = buildFamilyStatePatch(data, req.auth.user);
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 200, body: { extraTask, statePatch } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Approve extra task error:', error);
    res.status(500).json({ error: 'Nie udało się zatwierdzić zadania dodatkowego' });
  }
});

app.post('/api/extra-tasks/:id/reject', authMiddleware, requireParent, async (req, res) => {
  try {
    const extraTaskId = String(req.params.id || '');
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const extraTask = data.extraTasks.find((item) => item.id === extraTaskId);
      if (!extraTask) {
        return { status: 404, body: { error: 'Zadanie dodatkowe nie istnieje' } };
      }
      if (extraTask.status === 'APPROVED') {
        return { status: 409, body: { error: 'Zatwierdzonego zadania dodatkowego nie można odrzucić' } };
      }

      const now = new Date().toISOString();
      extraTask.status = 'REJECTED';
      extraTask.points = null;
      extraTask.approvedByParent = false;
      extraTask.approvedAt = null;
      extraTask.rejectedAt = now;
      extraTask.updatedAt = now;

      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'REJECT_EXTRA_TASK', 'EXTRA_TASK', extraTask.id, {
        childId: extraTask.childId,
        date: extraTask.date,
        title: extraTask.title,
      });

      const statePatch = buildFamilyStatePatch(data, req.auth.user);
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 200, body: { extraTask, statePatch } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Reject extra task error:', error);
    res.status(500).json({ error: 'Nie udało się odrzucić zadania dodatkowego' });
  }
});

app.get('/api/point-adjustments', authMiddleware, async (req, res) => {
  try {
    const childId = typeof req.query.childId === 'string' ? req.query.childId : null;
    const { data } = await loadStateData(req.auth.user.familyId);

    let list = data.pointAdjustments;
    if (req.auth.user.role === 'CHILD') {
      list = list.filter((adjustment) => adjustment.childId === req.auth.user.childId);
    } else if (childId) {
      list = list.filter((adjustment) => adjustment.childId === childId);
    }

    res.json({ pointAdjustments: list });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Point adjustments list error:', error);
    res.status(500).json({ error: 'Nie udało się pobrać premii i kar punktowych' });
  }
});

app.post('/api/point-adjustments', authMiddleware, requireParent, async (req, res) => {
  const parsed = pointAdjustmentSchema.safeParse(req.body || {});
  if (!parsed.success) {
    res.status(400).json({ error: 'Nieprawidłowe dane premii lub kary' });
    return;
  }

  try {
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      recomputePointsAndGrants(data);

      const child = data.children.find((item) => item.id === parsed.data.childId && !item.archived);
      if (!child) {
        return { status: 404, body: { error: 'Dziecko nie istnieje' } };
      }

      const requestedPoints = parsed.data.points;
      const delta = parsed.data.type === 'BONUS' ? requestedPoints : -requestedPoints;
      const result = adjustPoints(data, parsed.data.childId, delta);
      if (parsed.data.type === 'PENALTY' && result.appliedDelta === 0) {
        return { status: 409, body: { error: 'Dziecko nie ma punktów do odjęcia' } };
      }
      const now = new Date().toISOString();
      const adjustment = {
        id: createEntityId('points'),
        childId: parsed.data.childId,
        type: parsed.data.type,
        requestedPoints,
        points: Math.abs(result.appliedDelta),
        delta: result.appliedDelta,
        previousPoints: result.previousPoints,
        newPoints: result.newPoints,
        note: parsed.data.note ? parsed.data.note.trim() : '',
        createdBy: req.auth.user.id,
        createdAt: now,
        updatedAt: now,
      };

      data.pointAdjustments = [adjustment, ...data.pointAdjustments];
      data.auditLogs = addAuditLogEntry(
        data,
        req.auth.user.id,
        parsed.data.type === 'BONUS' ? 'GRANT_POINT_BONUS' : 'APPLY_POINT_PENALTY',
        'POINT_ADJUSTMENT',
        adjustment.id,
        {
          childId: adjustment.childId,
          requestedPoints: adjustment.requestedPoints,
          appliedPoints: adjustment.points,
          delta: adjustment.delta,
          note: adjustment.note,
        },
      );
      recomputePointsAndGrants(data);
      reconcileRewardUnlocksForChild(data, parsed.data.childId, req.auth.user.id, now);

      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 201, body: { pointAdjustment: adjustment, points: data.points } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Point adjustment create error:', error);
    res.status(500).json({ error: 'Nie udało się zapisać premii lub kary' });
  }
});

app.get('/api/rewards', authMiddleware, async (req, res) => {
  try {
    const { data } = await loadStateData(req.auth.user.familyId);
    const visibleUnlocks = getVisibleRewardUnlocks(data.rewardUnlocks);
    const unlocks =
      req.auth.user.role === 'CHILD'
        ? visibleUnlocks.filter((item) => item.childId === req.auth.user.childId)
        : visibleUnlocks;

    res.json({
      rewards: data.rewards,
      rewardUnlocks: unlocks,
    });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Rewards list error:', error);
    res.status(500).json({ error: 'Nie udało się pobrać nagród' });
  }
});

app.get('/api/rewards/history', authMiddleware, requireParent, async (req, res) => {
  try {
    const { data } = await loadStateData(req.auth.user.familyId);

    res.json({
      rewardUnlockHistory: getRewardUnlockHistory(data),
    });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Reward history error:', error);
    res.status(500).json({ error: 'Nie udało się pobrać historii nagród' });
  }
});

app.post('/api/rewards', authMiddleware, requireParent, async (req, res) => {
  try {
    const parsed = rewardSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Nieprawidłowe dane nagrody' });
      return;
    }

    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
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
      reconcileRewardUnlocksForAllChildren(data, req.auth.user.id);
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 201, body: { reward } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const reward = data.rewards.find((item) => item.id === rewardId);
      if (!reward) return { status: 404, body: { error: 'Nagroda nie istnieje' } };

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
      reconcileRewardUnlocksForAllChildren(data, req.auth.user.id);
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 200, body: { reward } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Reward update error:', error);
    res.status(500).json({ error: 'Nie udało się zaktualizować nagrody' });
  }
});

app.delete('/api/rewards/:id', authMiddleware, requireParent, async (req, res) => {
  try {
    const rewardId = String(req.params.id || '');
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const reward = data.rewards.find((item) => item.id === rewardId);
      if (!reward) return { status: 404, body: { error: 'Nagroda nie istnieje' } };

      reward.active = false;
      reward.updatedAt = new Date().toISOString();
      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'ARCHIVE_REWARD', 'REWARD', rewardId);
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 200, body: { reward } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Reward archive error:', error);
    res.status(500).json({ error: 'Nie udało się zarchiwizować nagrody' });
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
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const reward = data.rewards.find((item) => item.id === rewardId && item.active !== false);
      if (!reward) return { status: 404, body: { error: 'Nagroda nie istnieje lub jest nieaktywna' } };
      const child = data.children.find((item) => item.id === parsed.data.childId && !item.archived);
      if (!child) return { status: 404, body: { error: 'Dziecko nie istnieje' } };

      const exists = data.rewardUnlocks.find(
        (item) => item.childId === parsed.data.childId && item.rewardId === rewardId && !item.revokedAt,
      );
      if (exists) return { status: 200, body: { unlock: exists, created: false } };
      const revoked = data.rewardUnlocks.find(
        (item) => item.childId === parsed.data.childId && item.rewardId === rewardId && item.revokedAt && !item.claimedAt,
      );
      const saveTxStateData = createSaveStateData(tx.familyState);
      if (revoked) {
        revoked.revokedAt = null;
        revoked.revokedReason = null;
        revoked.restoredAt = new Date().toISOString();
        revoked.updatedAt = revoked.restoredAt;
        data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'RESTORE_REWARD_UNLOCK', 'REWARD_UNLOCK', revoked.id, {
          childId: parsed.data.childId,
          rewardId,
          manual: true,
        });
        await saveTxStateData(state, data);
        return { status: 200, body: { unlock: revoked, created: false, restored: true } };
      }

      const now = new Date().toISOString();
      const unlock = {
        id: createEntityId('unlock'),
        childId: parsed.data.childId,
        rewardId,
        unlockedAt: now,
        claimedAt: null,
        shownAt: null,
        revokedAt: null,
        revokedReason: null,
        restoredAt: null,
        updatedAt: now,
      };
      data.rewardUnlocks = [unlock, ...data.rewardUnlocks];
      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'UNLOCK_REWARD', 'REWARD', rewardId, {
        childId: parsed.data.childId,
      });
      await saveTxStateData(state, data);
      return { status: 201, body: { unlock, created: true } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Reward unlock error:', error);
    res.status(500).json({ error: 'Nie udało się odblokować nagrody' });
  }
});

app.post('/api/rewards/unlocks/:unlockId/claim', authMiddleware, requireParent, async (req, res) => {
  try {
    const unlockId = String(req.params.unlockId || '');
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const unlock = data.rewardUnlocks.find((item) => item.id === unlockId);
      if (!unlock) return { status: 404, body: { error: 'Odblokowanie nagrody nie istnieje' } };
      if (unlock.revokedAt) {
        return { status: 409, body: { error: 'Nagroda została utracona i nie jest teraz dostępna do wydania' } };
      }

      if (!unlock.claimedAt) {
        unlock.claimedAt = new Date().toISOString();
        data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'CLAIM_REWARD', 'REWARD_UNLOCK', unlockId);
        const saveTxStateData = createSaveStateData(tx.familyState);
        await saveTxStateData(state, data);
      }
      return { status: 200, body: { unlock } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Reward claim error:', error);
    res.status(500).json({ error: 'Nie udało się oznaczyć nagrody jako wydanej' });
  }
});

app.get('/api/family-goal', authMiddleware, async (req, res) => {
  try {
    const { data } = await loadStateData(req.auth.user.familyId);
    res.json({ familyGoal: data.familyGoal });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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

    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      data.familyGoal = parsed.data;
      data.auditLogs = addAuditLogEntry(data, req.auth.user.id, 'UPDATE_FAMILY_GOAL', 'FAMILY_GOAL', 'family-goal', {
        title: parsed.data.title,
        target: parsed.data.target,
        mode: parsed.data.mode,
      });
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, data);
      return { status: 200, body: { familyGoal: data.familyGoal } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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
    const { data } = await loadStateData(req.auth.user.familyId);
    if (['points', 'streaks', 'pointLedger', 'taskPointGrants', 'dayPointGrants', 'weekBonusGrants'].includes(key)) {
      recomputePointsAndGrants(data);
    }
    res.json({
      key,
      value: filterStorageValueForUser(key, data, req.auth.user),
    });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
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
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const nextData = mergeStorageValuesForUser(data, { [key]: req.body?.value ?? null }, req.auth.user);
      if (!hasStateDataChanged(data, nextData)) {
        return { status: 200, body: { ok: true, key, skipped: true } };
      }
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, nextData);
      return { status: 200, body: { ok: true, key } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Storage set error:', error);
    res.status(500).json({ error: 'Błąd zapisu storage' });
  }
});

app.post('/api/storage/merge', authMiddleware, async (req, res) => {
  const values = req.body?.values;
  if (!isObjectRecord(values)) {
    res.status(400).json({ error: 'Nieprawidłowe dane merge storage' });
    return;
  }

  const keys = Object.keys(values);
  for (const key of keys) {
    if (!isValidStorageKey(key)) {
      res.status(400).json({ error: `Nieprawidłowy klucz storage: ${key}` });
      return;
    }
  }

  try {
    const result = await runFamilyMutation(req, async (tx) => {
      const { state, data } = await loadStateData(req.auth.user.familyId, tx);
      const nextData = mergeStorageValuesForUser(data, values, req.auth.user);
      if (!hasStateDataChanged(data, nextData)) {
        return { status: 200, body: { ok: true, keys, skipped: true } };
      }
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, nextData);
      return { status: 200, body: { ok: true, keys } };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Storage merge error:', error);
    res.status(500).json({ error: 'Błąd zapisu storage merge' });
  }
});

app.post('/api/storage/restore-backup', authMiddleware, requireParent, async (req, res) => {
  const backup = Object.prototype.hasOwnProperty.call(req.body || {}, 'backup') ? req.body.backup : req.body;

  try {
    const result = await runFamilyMutation(req, async (tx) => {
      const nextData = normalizeRestoredBackupData(backup, req.auth.user.id);
      if (!nextData) {
        return { status: 400, body: { error: 'Nieprawidłowy plik backupu' } };
      }

      const normalizedChildren = await normalizeChildrenAccessCodesGlobally(
        nextData.children,
        { familyId: req.auth.user.familyId },
        tx,
      );
      if (!normalizedChildren) {
        return { status: 409, body: { error: 'Brak wolnych kodów dostępu dla dzieci' } };
      }

      const childAccessCodes = [];
      await tx.childAccessCredential.updateMany({
        where: { familyId: req.auth.user.familyId, active: true },
        data: { active: false },
      });
      for (const child of normalizedChildren) {
        if (!child.archived && isValidChildAccessCode(child.accessCode)) {
          await setChildAccessCredential(tx, {
            familyId: req.auth.user.familyId,
            childId: child.id,
            accessCode: child.accessCode,
          });
          childAccessCodes.push({ childId: child.id, accessCode: child.accessCode });
        }
      }

      nextData.children = sanitizeChildrenForStorage(normalizedChildren);
      const { state } = await loadStateData(req.auth.user.familyId, tx);
      const saveTxStateData = createSaveStateData(tx.familyState);
      await saveTxStateData(state, nextData);
      return {
        status: 200,
        body: {
          ok: true,
          restored: {
            children: nextData.children.length,
            tasks: nextData.tasks.length,
            completions: nextData.completions.length,
            extraTasks: nextData.extraTasks.length,
            rewardUnlocks: nextData.rewardUnlocks.length,
          },
          points: nextData.points,
          streaks: nextData.streaks,
          childAccessCodes,
        },
      };
    });
    sendFamilyMutationResult(res, result);
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Storage restore backup error:', error);
    res.status(500).json({ error: 'Nie udało się odtworzyć backupu' });
  }
});

app.get('/api/storage/list', authMiddleware, async (req, res) => {
  try {
    const prefix = String(req.query.prefix || '');
    const { data } = await loadStateData(req.auth.user.familyId);

    const sourceKeys = req.auth.user.role === 'CHILD' ? [...CHILD_STORAGE_KEYS] : Object.keys(data);
    const keys = sourceKeys.filter((key) => key.startsWith(prefix));
    res.json({ keys });
  } catch (error) {
    if (isFamilyStateConflict(error)) {
      sendFamilyStateConflict(res);
      return;
    }
    console.error('Storage list error:', error);
    res.status(500).json({ error: 'Błąd listowania storage' });
  }
});

const frontendDistPath = path.join(__dirname, 'dist');
const frontendStaticPath = fs.existsSync(path.join(frontendDistPath, 'index.html')) ? frontendDistPath : __dirname;

app.use(
  express.static(frontendStaticPath, {
    setHeaders: (res, filePath) => {
      if (/\.(html|js|css)$/i.test(filePath) || filePath.endsWith('service-worker.js')) {
        res.setHeader('Cache-Control', 'no-store, max-age=0');
      }
    },
  }),
);

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/') || req.path === '/health' || req.path === '/livez') {
    next();
    return;
  }
  res.sendFile(path.join(frontendStaticPath, 'index.html'));
});

app.use((err, req, res, _next) => {
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
  __test: {
    recomputePointsAndGrants,
    normalizeRestoredBackupData,
    reverseApprovalEffects,
    createSaveStateData,
    attachStateDataConflictBase,
    sanitizeStateDataForStorage,
    bootstrapChildAccessCredentials,
    parseDateInput,
    toDateString,
    isValidDateString,
    getDayNumber,
    FamilyStateConflictError,
    isFamilyStateConflict,
  },
};
