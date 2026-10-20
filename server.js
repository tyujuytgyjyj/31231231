'use strict';

require('dotenv').config();

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const session = require('express-session');
const SQLiteStoreFactory = require('connect-sqlite3');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');

const SQLiteStore = SQLiteStoreFactory(session);
const PORT = Number(process.env.PORT || 4000);
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const DB_PATH = path.resolve(process.env.DATABASE_PATH || path.join(DATA_DIR, 'cosmos.sqlite'));
const PUBLIC_MODEL_ID = 'cosmos-photon-3';
const PUBLIC_MODEL_NAME = 'Cosmos Photon 3';
const BLAZAR_MODEL_ID = 'cosmos-blazar-3';
const BLAZAR_MODEL_NAME = 'Cosmos Blazar 3';
const BLAZAR_DAILY_TOKEN_LIMIT = 10000;
const GEMINI_MODEL = String(process.env.GEMINI_MODEL || 'gemma-4-31b-it').trim() || 'gemma-4-31b-it';
const GEMINI_API_BASE_URL = String(process.env.GEMINI_API_BASE_URL || 'https://generativelanguage.googleapis.com/v1beta').replace(/\/+$/, '');
const APP_NAME = process.env.PUBLIC_APP_NAME || 'Cosmos';
const SESSION_SECRET = process.env.SESSION_SECRET || (process.env.NODE_ENV === 'production' ? '' : 'development-only-secret-change-me-before-deployment');
const SESSION_MAX_AGE_MS = Number(process.env.SESSION_MAX_AGE_MS || 7 * 24 * 60 * 60 * 1000);
const REQUEST_TIMEOUT_MS = Number(process.env.PHOTON_REQUEST_TIMEOUT_MS || 90000);
const MAX_CONCURRENT_REQUESTS = Math.max(1, Number(process.env.PHOTON_MAX_CONCURRENT_REQUESTS || 12));
const REQUESTS_PER_MINUTE = Math.max(10, Number(process.env.API_USER_REQUESTS_PER_MINUTE || 120));
const EMAIL_VERIFICATION_REQUIRED = String(process.env.EMAIL_VERIFICATION_REQUIRED || 'false').toLowerCase() === 'true';
const CODE_TTL_MINUTES = Math.max(3, Number(process.env.EMAIL_CODE_TTL_MINUTES || 10));
const BCRYPT_ROUNDS = Math.min(14, Math.max(10, Number(process.env.BCRYPT_ROUNDS || 12)));

if (process.env.NODE_ENV === 'production' && SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must contain at least 32 characters in production.');
}
if (process.env.NODE_ENV === 'production' && !EMAIL_VERIFICATION_REQUIRED) {
  throw new Error('EMAIL_VERIFICATION_REQUIRED must be true in production.');
}
if (EMAIL_VERIFICATION_REQUIRED && (!process.env.EMAIL_HOST || !process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD || !process.env.EMAIL_FROM)) {
  throw new Error('Email verification is enabled but SMTP configuration is incomplete.');
}

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  email_verified INTEGER NOT NULL DEFAULT 0,
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended')),
  plan TEXT NOT NULL DEFAULT 'free',
  created_at INTEGER NOT NULL,
  last_login_at INTEGER
);
CREATE TABLE IF NOT EXISTS verification_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  consumed_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verification_user_created ON verification_codes(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  prefix TEXT NOT NULL,
  last_four TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS usage_logs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  api_key_id TEXT REFERENCES api_keys(id) ON DELETE SET NULL,
  model TEXT NOT NULL,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_user_created ON usage_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_created ON usage_logs(created_at DESC);
CREATE TABLE IF NOT EXISTS token_reservations (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  model TEXT NOT NULL,
  reserved_tokens INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_token_reservations_user_model ON token_reservations(user_id, model, created_at);
`);
db.prepare('DELETE FROM token_reservations WHERE expires_at <= ?').run(Date.now());

const mailer = EMAIL_VERIFICATION_REQUIRED ? nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT || 587),
  secure: String(process.env.EMAIL_SECURE || 'false').toLowerCase() === 'true',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASSWORD },
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 15000
}) : null;

let activeGenerations = 0;

function makeId() {
  return crypto.randomUUID();
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function timingSafeStringEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function safeUser(row) {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    role: row.role,
    status: row.status,
    plan: row.plan,
    emailVerified: Boolean(row.email_verified),
    createdAt: row.created_at
  };
}

function csrfMiddleware(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const provided = req.get('X-CSRF-Token');
  if (!req.session || !req.session.csrfToken || !provided || !timingSafeStringEqual(req.session.csrfToken, provided)) {
    return res.status(403).json({ error: { message: 'Your session needs to be refreshed. Reload the page and try again.', code: 'csrf' } });
  }
  next();
}

function sessionRequired(req, res, next) {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: { message: 'Please sign in to continue.', code: 'unauthenticated' } });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.status !== 'active' || (EMAIL_VERIFICATION_REQUIRED && !user.email_verified)) {
    req.session.destroy(() => {});
    return res.status(401).json({ error: { message: 'Your session is no longer valid. Please sign in again.', code: 'unauthenticated' } });
  }
  req.user = user;
  next();
}

function apiKeyRequired(req, res, next) {
  const auth = req.get('Authorization') || '';
  const match = auth.match(/^Bearer\s+(cos_live_[A-Za-z0-9_-]{30,})$/);
  if (!match) return res.status(401).json({ error: { message: 'A valid Cosmos API key is required.', type: 'authentication_error', code: 'invalid_api_key' } });
  const keyHash = sha256(match[1]);
  const row = db.prepare(`SELECT api_keys.*, users.status AS user_status, users.email_verified, users.plan
    FROM api_keys JOIN users ON users.id = api_keys.user_id
    WHERE api_keys.key_hash = ? AND api_keys.revoked_at IS NULL`).get(keyHash);
  if (!row || row.user_status !== 'active' || (EMAIL_VERIFICATION_REQUIRED && !row.email_verified)) {
    return res.status(401).json({ error: { message: 'A valid Cosmos API key is required.', type: 'authentication_error', code: 'invalid_api_key' } });
  }
  req.apiUser = { id: row.user_id, plan: row.plan };
  req.apiKey = row;
  db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(Date.now(), row.id);
  next();
}

function getClientInfo(req) {
  return { ip: req.ip || '', userAgent: String(req.get('User-Agent') || '').slice(0, 300) };
}

function createVerificationCode(user) {
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const now = Date.now();
  db.prepare('UPDATE verification_codes SET consumed_at = ? WHERE user_id = ? AND consumed_at IS NULL').run(now, user.id);
  db.prepare('INSERT INTO verification_codes (id,user_id,code_hash,expires_at,created_at) VALUES (?,?,?,?,?)')
    .run(makeId(), user.id, sha256(`${user.email}:${code}:${SESSION_SECRET}`), now + CODE_TTL_MINUTES * 60 * 1000, now);
  return code;
}

async function sendVerificationEmail(user) {
  const code = createVerificationCode(user);
  await mailer.sendMail({
    from: process.env.EMAIL_FROM,
    to: user.email,
    subject: `${APP_NAME} verification code`,
    text: `Your ${APP_NAME} verification code is ${code}. It expires in ${CODE_TTL_MINUTES} minutes. If you did not request this code, you can ignore this email.`,
    html: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:32px auto;color:#171717"><h2>${APP_NAME}</h2><p>Use this code to verify your email address.</p><div style="font-size:30px;font-weight:700;letter-spacing:8px;padding:18px 0">${code}</div><p>This code expires in ${CODE_TTL_MINUTES} minutes. If you did not request it, you can ignore this email.</p></div>`
  });
}

function regenerateSession(req, user, callback) {
  req.session.regenerate((err) => {
    if (err) return callback(err);
    req.session.userId = user.id;
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    req.session.createdAt = Date.now();
    db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(Date.now(), user.id);
    callback(null);
  });
}

function usageTotals(userId, since) {
  const row = db.prepare(`SELECT COUNT(*) AS requests, COALESCE(SUM(input_tokens),0) AS input_tokens,
    COALESCE(SUM(output_tokens),0) AS output_tokens,
    COALESCE(AVG(latency_ms),0) AS avg_latency_ms,
    SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS successful
    FROM usage_logs WHERE user_id = ? AND created_at >= ?`).get(userId, since);
  return {
    requests: Number(row.requests || 0),
    inputTokens: Number(row.input_tokens || 0),
    outputTokens: Number(row.output_tokens || 0),
    avgLatencyMs: Math.round(Number(row.avg_latency_ms || 0)),
    successful: Number(row.successful || 0)
  };
}

function getModelList() {
  return [
    {
      id: PUBLIC_MODEL_ID,
      name: PUBLIC_MODEL_NAME,
      description: 'A fast, lightweight model for everyday API workloads.',
      contextWindow: 32768,
      inputModalities: ['text'],
      outputModalities: ['text'],
      availability: 'available',
      usageNote: 'Generous fair-use access. Throughput may adapt to overall service demand.'
    },
    {
      id: BLAZAR_MODEL_ID,
      name: BLAZAR_MODEL_NAME,
      description: 'A high-capability model for complex reasoning, writing, and development tasks.',
      inputModalities: ['text'],
      outputModalities: ['text'],
      availability: process.env.GEMINI_API_KEY ? 'configured' : 'not_configured',
      dailyTokenLimit: BLAZAR_DAILY_TOKEN_LIMIT,
      usageNote: '10,000 tokens per user per UTC day. Input and output tokens both count toward the daily limit.'
    }
  ];
}

function utcDayStart(ts = Date.now()) {
  const date = new Date(ts);
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
}

function blazarDailyUsage(userId, ts = Date.now()) {
  const since = utcDayStart(ts);
  const spentRow = db.prepare(`SELECT COALESCE(SUM(input_tokens + output_tokens),0) AS used
    FROM usage_logs WHERE user_id = ? AND model = ? AND created_at >= ?`).get(userId, BLAZAR_MODEL_ID, since);
  const reservedRow = db.prepare(`SELECT COALESCE(SUM(reserved_tokens),0) AS reserved
    FROM token_reservations WHERE user_id = ? AND model = ? AND created_at >= ? AND expires_at > ?`).get(userId, BLAZAR_MODEL_ID, since, ts);
  const usedTokens = Number(spentRow.used || 0);
  const reservedTokens = Number(reservedRow.reserved || 0);
  return {
    limit: BLAZAR_DAILY_TOKEN_LIMIT,
    used: Math.min(BLAZAR_DAILY_TOKEN_LIMIT, usedTokens),
    consumed: usedTokens,
    reserved: reservedTokens,
    remaining: Math.max(0, BLAZAR_DAILY_TOKEN_LIMIT - usedTokens - reservedTokens),
    resetsAt: since + 24 * 60 * 60 * 1000
  };
}

function reserveBlazarTokens(userId, promptTokens, requestedOutputTokens, reservationId, startedAt) {
  const reserve = db.transaction(() => {
    const dayStart = utcDayStart(startedAt);
    db.prepare('DELETE FROM token_reservations WHERE expires_at <= ?').run(startedAt);
    const spent = Number(db.prepare(`SELECT COALESCE(SUM(input_tokens + output_tokens),0) AS used
      FROM usage_logs WHERE user_id = ? AND model = ? AND created_at >= ?`).get(userId, BLAZAR_MODEL_ID, dayStart).used || 0);
    const pending = Number(db.prepare(`SELECT COALESCE(SUM(reserved_tokens),0) AS reserved
      FROM token_reservations WHERE user_id = ? AND model = ? AND created_at >= ? AND expires_at > ?`).get(userId, BLAZAR_MODEL_ID, dayStart, startedAt).reserved || 0);
    const remaining = BLAZAR_DAILY_TOKEN_LIMIT - spent - pending;
    const input = Math.max(0, Math.floor(Number(promptTokens) || 0));
    if (remaining <= input) return { allowed: false, remaining: Math.max(0, remaining), maxOutputTokens: 0 };
    const maxOutputTokens = Math.min(Math.max(1, Math.floor(Number(requestedOutputTokens) || 1)), remaining - input);
    const reservedTokens = input + maxOutputTokens;
    db.prepare('INSERT INTO token_reservations (id,user_id,model,reserved_tokens,created_at,expires_at) VALUES (?,?,?,?,?,?)')
      .run(reservationId, userId, BLAZAR_MODEL_ID, reservedTokens, startedAt, startedAt + REQUEST_TIMEOUT_MS + 60000);
    return { allowed: true, remaining, maxOutputTokens, reservedTokens };
  });
  return reserve();
}

function estimateOutputTokens(text) {
  return text ? Math.ceil(Buffer.byteLength(String(text), 'utf8') / 3) : 0;
}

function displayModelName(model) {
  return model === BLAZAR_MODEL_ID ? BLAZAR_MODEL_NAME : PUBLIC_MODEL_NAME;
}

function publicApiError(res, status, message, code, type) {
  return res.status(status).json({ error: { message, type: type || 'api_error', code } });
}

function validateCompletion(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return 'The request body must be a JSON object.';
  if (![PUBLIC_MODEL_ID, BLAZAR_MODEL_ID].includes(body.model)) return `The requested model is not available. Use ${PUBLIC_MODEL_ID} or ${BLAZAR_MODEL_ID}.`;
  if (!Array.isArray(body.messages) || body.messages.length < 1 || body.messages.length > 100) return 'messages must contain between 1 and 100 items.';
  let totalChars = 0;
  for (const message of body.messages) {
    if (!message || !['system', 'user', 'assistant'].includes(message.role) || typeof message.content !== 'string') {
      return 'Each message must contain a supported role and text content.';
    }
    totalChars += message.content.length;
  }
  if (totalChars > 200000) return 'The combined message content is too large.';
  if (body.stream !== undefined && typeof body.stream !== 'boolean') return 'stream must be a boolean.';
  const requestedMaxTokens = body.max_tokens ?? body.max_completion_tokens;
  if (requestedMaxTokens !== undefined && (!Number.isInteger(requestedMaxTokens) || requestedMaxTokens < 1 || requestedMaxTokens > 10000)) return 'max_tokens must be an integer from 1 to 10000.';
  if (body.temperature !== undefined && (typeof body.temperature !== 'number' || !Number.isFinite(body.temperature) || body.temperature < 0 || body.temperature > 2)) return 'temperature must be between 0 and 2.';
  return null;
}

function recordUsage({ userId, apiKeyId, model = PUBLIC_MODEL_ID, status, latencyMs, inputTokens, outputTokens, createdAt = Date.now() }) {
  db.prepare(`INSERT INTO usage_logs (id,user_id,api_key_id,model,input_tokens,output_tokens,status,latency_ms,created_at)
    VALUES (?,?,?,?,?,?,?,?,?)`).run(
    makeId(), userId, apiKeyId || null, model,
    Math.max(0, Number(inputTokens) || 0), Math.max(0, Number(outputTokens) || 0),
    status, Math.max(0, Math.round(latencyMs || 0)), createdAt
  );
}

function userRateLimitExceeded(userId) {
  const minuteAgo = Date.now() - 60000;
  const count = db.prepare('SELECT COUNT(*) AS n FROM usage_logs WHERE user_id = ? AND created_at >= ?').get(userId, minuteAgo).n;
  const loadRatio = Math.min(1, activeGenerations / MAX_CONCURRENT_REQUESTS);
  const adaptiveLimit = Math.max(10, Math.floor(REQUESTS_PER_MINUTE * (1 - 0.65 * loadRatio)));
  return Number(count) >= adaptiveLimit;
}

async function handleCompletion(req, res, identity) {
  const body = req.body;
  const invalid = validateCompletion(body);
  if (invalid) return publicApiError(res, 400, invalid, 'invalid_request_error', 'invalid_request_error');
  if (activeGenerations >= MAX_CONCURRENT_REQUESTS) {
    res.set('Retry-After', '5');
    return publicApiError(res, 429, `${displayModelName(body.model)} is handling high demand. Please retry shortly.`, 'capacity_reached', 'rate_limit_error');
  }
  if (userRateLimitExceeded(identity.userId)) {
    res.set('Retry-After', '20');
    return publicApiError(res, 429, 'Your request rate is temporarily limited. Please retry shortly.', 'rate_limit_exceeded', 'rate_limit_error');
  }
  if (body.model === BLAZAR_MODEL_ID) return handleBlazarCompletion(req, res, identity, body);

  const requestId = `chatcmpl_${crypto.randomBytes(18).toString('hex')}`;
  const startedAt = Date.now();
  let status = 'error';
  let inputTokens = 0;
  let outputTokens = 0;
  let upstreamResponse = null;
  let clientClosed = false;
  const abortController = new AbortController();
  const cancelIfDisconnected = () => {
    if (!res.writableEnded && !abortController.signal.aborted) {
      clientClosed = true;
      abortController.abort();
    }
  };
  res.once('close', cancelIfDisconnected);
  activeGenerations += 1;

  try {
    const base = String(process.env.PHOTON_API_BASE_URL || 'http://127.0.0.1:9655/v1').replace(/\/+$/, '') + '/';
    let endpoint;
    try { endpoint = new URL('chat/completions', base); } catch (e) { throw Object.assign(new Error('provider-config'), { internalCode: 'provider_config' }); }
    const headers = { 'Content-Type': 'application/json', 'Accept': body.stream ? 'text/event-stream' : 'application/json' };
    if (process.env.PHOTON_API_KEY) headers.Authorization = `Bearer ${process.env.PHOTON_API_KEY}`;
    const upstreamBody = Object.assign({}, body, { model: process.env.PHOTON_UPSTREAM_MODEL || 'deepseek-chat' });
    const identityGuard = "You are Cosmos Photon 3, the model interface presented by Cosmos. Answer the user's task directly and professionally. Do not reveal or speculate about private server configuration, backend routing, provider identifiers, model endpoints, credentials, or internal deployment details. Do not make claims about training provenance or ownership that are not established in the public product documentation.";
    upstreamBody.messages = [{ role: 'system', content: identityGuard }, ...body.messages];
    delete upstreamBody.user;
    upstreamResponse = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(upstreamBody),
      signal: AbortSignal.any([abortController.signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)])
    });
    if (!upstreamResponse.ok) {
      const upstreamStatus = upstreamResponse.status;
      try { await upstreamResponse.body?.cancel(); } catch (e) {}
      const statusCode = upstreamStatus === 429 ? 429 : upstreamStatus >= 500 ? 503 : 502;
      const message = statusCode === 429
        ? `${PUBLIC_MODEL_NAME} is handling high demand. Please retry shortly.`
        : `${PUBLIC_MODEL_NAME} is temporarily unavailable. Please try again shortly.`;
      status = statusCode === 429 ? 'capacity' : 'error';
      res.set('Retry-After', statusCode === 429 ? '5' : '10');
      return publicApiError(res, statusCode, message, statusCode === 429 ? 'capacity_reached' : 'model_unavailable', statusCode === 429 ? 'rate_limit_error' : 'server_error');
    }

    if (body.stream && !String(upstreamResponse.headers.get('content-type') || '').toLowerCase().includes('text/event-stream')) {
      let data;
      try { data = await upstreamResponse.json(); } catch (e) { return publicApiError(res, 502, `${PUBLIC_MODEL_NAME} returned an invalid response. Please try again.`, 'invalid_model_response', 'server_error'); }
      if (!data || data.error || !Array.isArray(data.choices) || !data.choices[0]) {
        return publicApiError(res, 503, `${PUBLIC_MODEL_NAME} is temporarily unavailable. Please try again shortly.`, 'model_unavailable', 'server_error');
      }
      inputTokens = Number(data.usage?.prompt_tokens ?? data.usage?.input_tokens ?? 0);
      outputTokens = Number(data.usage?.completion_tokens ?? data.usage?.output_tokens ?? 0);
      const created = Number(data.created) || Math.floor(Date.now() / 1000);
      const text = String(data.choices[0].message?.content || '');
      res.status(200).set({ 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache, no-transform', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no', 'X-Request-Id': requestId });
      res.flushHeaders?.();
      const emit = chunk => res.write(`data: ${JSON.stringify(chunk)}\n\n`);
      emit({ id: requestId, object: 'chat.completion.chunk', created, model: PUBLIC_MODEL_ID, choices: [{ index: 0, delta: { role: 'assistant' }, finish_reason: null }] });
      if (text) emit({ id: requestId, object: 'chat.completion.chunk', created, model: PUBLIC_MODEL_ID, choices: [{ index: 0, delta: { content: text }, finish_reason: null }] });
      emit({ id: requestId, object: 'chat.completion.chunk', created, model: PUBLIC_MODEL_ID, choices: [{ index: 0, delta: {}, finish_reason: data.choices[0].finish_reason || 'stop' }] });
      if (data.usage) emit({ id: requestId, object: 'chat.completion.chunk', created, model: PUBLIC_MODEL_ID, choices: [], usage: data.usage });
      res.write('data: [DONE]\n\n');
      res.end();
      status = 'success';
      return;
    }

    if (body.stream) {
      res.status(200);
      res.set({
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no',
        'X-Request-Id': requestId
      });
      res.flushHeaders?.();
      let buffer = '';
      const decoder = new TextDecoder();
      const writeEventLine = (line) => {
        if (line.startsWith('data:')) {
          const rawData = line.slice(5).trim();
          if (rawData && rawData !== '[DONE]') {
            try {
              const chunk = JSON.parse(rawData);
              if (chunk && chunk.error) {
                res.write(`data: ${JSON.stringify({ error: { message: `${PUBLIC_MODEL_NAME} is temporarily unavailable. Please try again shortly.`, type: 'server_error', code: 'model_unavailable' } })}\n`);
                return;
              }
              chunk.id = requestId;
              chunk.model = PUBLIC_MODEL_ID;
              delete chunk.system_fingerprint;
              if (chunk.usage) {
                inputTokens = Number(chunk.usage.prompt_tokens ?? chunk.usage.input_tokens ?? 0);
                outputTokens = Number(chunk.usage.completion_tokens ?? chunk.usage.output_tokens ?? 0);
              }
              res.write(`data: ${JSON.stringify(chunk)}\n`);
              return;
            } catch (e) {
              if (e instanceof SyntaxError) {
                res.write('data: [DONE]\n');
                return;
              }
            }
          }
          res.write(line + '\n');
          return;
        }
        res.write(line + '\n');
      };
      for await (const chunk of upstreamResponse.body) {
        if (abortController.signal.aborted || res.destroyed) break;
        buffer += decoder.decode(chunk, { stream: true });
        let newline;
        while ((newline = buffer.indexOf('\n')) !== -1) {
          const line = buffer.slice(0, newline).replace(/\r$/, '');
          buffer = buffer.slice(newline + 1);
          writeEventLine(line);
        }
      }
      buffer += decoder.decode();
      if (buffer && !res.destroyed) writeEventLine(buffer.replace(/\r$/, ''));
      if (!res.destroyed && !res.writableEnded) res.end();
      status = clientClosed ? 'cancelled' : 'success';
    } else {
      const data = await upstreamResponse.json();
      if (!data || typeof data !== 'object' || data.error) {
        status = 'error';
        return publicApiError(res, 502, `${PUBLIC_MODEL_NAME} is temporarily unavailable. Please try again shortly.`, 'invalid_model_response', 'server_error');
      }
      inputTokens = Number(data.usage?.prompt_tokens ?? data.usage?.input_tokens ?? 0);
      outputTokens = Number(data.usage?.completion_tokens ?? data.usage?.output_tokens ?? 0);
      const output = Object.assign({}, data, { id: requestId, model: PUBLIC_MODEL_ID });
      delete output.system_fingerprint;
      status = 'success';
      res.set('X-Request-Id', requestId).json(output);
    }
  } catch (err) {
    if (clientClosed || err.name === 'AbortError' && res.destroyed) {
      status = 'cancelled';
    } else {
      status = 'error';
      if (!res.headersSent) {
        const timedOut = err.name === 'TimeoutError' || err.name === 'AbortError';
        publicApiError(res, 503,
          timedOut ? 'The request took too long. Please try again.' : `${PUBLIC_MODEL_NAME} is temporarily unavailable. Please try again shortly.`,
          timedOut ? 'request_timeout' : 'model_unavailable', 'server_error');
      } else if (!res.writableEnded && !res.destroyed) {
        res.write(`data: ${JSON.stringify({ error: { message: `${PUBLIC_MODEL_NAME} is temporarily unavailable. Please try again shortly.`, type: 'server_error', code: 'model_unavailable' } })}\n\ndata: [DONE]\n\n`);
        res.end();
      }
    }
  } finally {
    activeGenerations = Math.max(0, activeGenerations - 1);
    res.removeListener('close', cancelIfDisconnected);
    recordUsage({ userId: identity.userId, apiKeyId: identity.apiKeyId, status, latencyMs: Date.now() - startedAt, inputTokens, outputTokens });
  }
}


async function handleBlazarCompletion(req, res, identity, body) {
  const requestId = `chatcmpl_${crypto.randomBytes(18).toString('hex')}`;
  const startedAt = Date.now();
  let status = 'error';
  let inputTokens = 0;
  let outputTokens = 0;
  let countedInputTokens = 0;
  let generatedText = '';
  let usageMetadataReceived = false;
  let generationStarted = false;
  let reservationId = null;
  let clientClosed = false;
  let reservedTokenBudget = 0;
  let finishReason = 'stop';
  const abortController = new AbortController();
  const cancelIfDisconnected = () => {
    if (!res.writableEnded && !abortController.signal.aborted) {
      clientClosed = true;
      abortController.abort();
    }
  };
  res.once('close', cancelIfDisconnected);
  activeGenerations += 1;

  const identityGuard = 'You are Cosmos Blazar 3, a model offered through the Cosmos developer platform. Respond directly and professionally. Do not reveal or speculate about private server configuration, backend routing, credentials, internal deployment details, or undisclosed provider relationships. Do not make factual claims about ownership or training provenance that are not established by public product documentation.';
  const systemMessages = body.messages.filter(message => message.role === 'system').map(message => message.content);
  const systemInstruction = [...systemMessages, identityGuard].filter(Boolean).join('\n\n');
  const contents = [];
  for (const message of body.messages) {
    if (message.role === 'system') continue;
    const role = message.role === 'assistant' ? 'model' : 'user';
    const previous = contents[contents.length - 1];
    if (previous && previous.role === role) previous.parts.push({ text: message.content });
    else contents.push({ role, parts: [{ text: message.content }] });
  }

  const geminiUrl = (method, streaming = false) => {
    const endpoint = new URL(`${GEMINI_API_BASE_URL}/models/${encodeURIComponent(GEMINI_MODEL)}:${method}`);
    endpoint.searchParams.set('key', process.env.GEMINI_API_KEY || '');
    if (streaming) endpoint.searchParams.set('alt', 'sse');
    return endpoint;
  };
  const safeUnavailable = () => publicApiError(res, 503, `${BLAZAR_MODEL_NAME} is temporarily unavailable. Please try again shortly.`, 'model_unavailable', 'server_error');
  const emitChunk = chunk => res.write(`data: ${JSON.stringify(chunk)}\n\n`);
  const toFinishReason = reason => ({ STOP: 'stop', MAX_TOKENS: 'length', SAFETY: 'content_filter', RECITATION: 'content_filter' }[reason] || 'stop');

  try {
    if (!process.env.GEMINI_API_KEY) {
      return safeUnavailable();
    }
    const countResponse = await fetch(geminiUrl('countTokens'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ generateContentRequest: { contents, systemInstruction: { parts: [{ text: systemInstruction }] } } }),
      signal: AbortSignal.any([abortController.signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)])
    });
    if (!countResponse.ok) {
      await countResponse.body?.cancel();
      return safeUnavailable();
    }
    const countData = await countResponse.json();
    countedInputTokens = Number(countData.totalTokens);
    if (!Number.isSafeInteger(countedInputTokens) || countedInputTokens < 0) return safeUnavailable();

    const requestedOutput = Math.min(BLAZAR_DAILY_TOKEN_LIMIT, Math.max(1, Math.floor(Number(body.max_tokens ?? body.max_completion_tokens ?? 2048))));
    reservationId = makeId();
    const reservation = reserveBlazarTokens(identity.userId, countedInputTokens, requestedOutput, reservationId, startedAt);
    if (!reservation.allowed) {
      reservationId = null;
      status = 'quota_exceeded';
      res.set('Retry-After', String(Math.max(1, Math.ceil((utcDayStart(startedAt) + 86400000 - startedAt) / 1000))));
      return publicApiError(res, 429, `${BLAZAR_MODEL_NAME} has reached its 10,000-token daily allowance. Try again after the daily reset or use ${PUBLIC_MODEL_NAME}.`, 'daily_token_limit', 'rate_limit_error');
    }
    reservedTokenBudget = reservation.reservedTokens;
    inputTokens = countedInputTokens;

    const generationConfig = { maxOutputTokens: reservation.maxOutputTokens };
    if (typeof body.temperature === 'number') generationConfig.temperature = body.temperature;
    if (typeof body.top_p === 'number' && body.top_p >= 0 && body.top_p <= 1) generationConfig.topP = body.top_p;
    const generationBody = { contents, systemInstruction: { parts: [{ text: systemInstruction }] }, generationConfig };
    const upstream = await fetch(geminiUrl(body.stream ? 'streamGenerateContent' : 'generateContent', Boolean(body.stream)), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': body.stream ? 'text/event-stream' : 'application/json' },
      body: JSON.stringify(generationBody),
      signal: AbortSignal.any([abortController.signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)])
    });
    if (!upstream.ok) {
      const upstreamStatus = upstream.status;
      inputTokens = 0;
      outputTokens = 0;
      await upstream.body?.cancel();
      if (upstreamStatus === 429) {
        status = 'capacity';
        res.set('Retry-After', '10');
        return publicApiError(res, 429, `${BLAZAR_MODEL_NAME} is handling high demand. Please retry shortly.`, 'capacity_reached', 'rate_limit_error');
      }
      return safeUnavailable();
    }

    generationStarted = true;
    if (body.stream) {
      res.status(200).set({ 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache, no-transform', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no', 'X-Request-Id': requestId });
      res.flushHeaders?.();
      const created = Math.floor(startedAt / 1000);
      emitChunk({ id: requestId, object: 'chat.completion.chunk', created, model: BLAZAR_MODEL_ID, choices: [{ index: 0, delta: { role: 'assistant' }, finish_reason: null }] });
      let buffer = '';
      const decoder = new TextDecoder();
      const processSseLine = line => {
        if (!line.startsWith('data:')) return;
        const raw = line.slice(5).trim();
        if (!raw || raw === '[DONE]') return;
        let chunk;
        try { chunk = JSON.parse(raw); } catch (e) { return; }
        const candidate = chunk.candidates?.[0];
        const deltaText = Array.isArray(candidate?.content?.parts) ? candidate.content.parts.map(part => typeof part.text === 'string' ? part.text : '').join('') : '';
        if (deltaText) {
          generatedText += deltaText;
          emitChunk({ id: requestId, object: 'chat.completion.chunk', created, model: BLAZAR_MODEL_ID, choices: [{ index: 0, delta: { content: deltaText }, finish_reason: null }] });
        }
        if (candidate?.finishReason) finishReason = toFinishReason(candidate.finishReason);
        const usage = chunk.usageMetadata;
        if (usage) {
          usageMetadataReceived = true;
          inputTokens = Math.max(countedInputTokens, Number(usage.promptTokenCount) || 0);
          const totalTokens = Number(usage.totalTokenCount) || 0;
          const fallbackOutputTokens = (Number(usage.candidatesTokenCount) || 0) + (Number(usage.thoughtsTokenCount) || 0) + (Number(usage.toolUsePromptTokenCount) || 0);
          outputTokens = totalTokens > 0 ? Math.max(0, totalTokens - inputTokens) : (fallbackOutputTokens || outputTokens);
        }
      };
      for await (const part of upstream.body) {
        if (abortController.signal.aborted || res.destroyed) break;
        buffer += decoder.decode(part, { stream: true });
        let newline;
        while ((newline = buffer.indexOf('\n')) !== -1) {
          const line = buffer.slice(0, newline).replace(/\r$/, '');
          buffer = buffer.slice(newline + 1);
          processSseLine(line);
        }
      }
      buffer += decoder.decode();
      if (buffer && !res.destroyed) processSseLine(buffer.replace(/\r$/, ''));
      inputTokens = Math.min(reservation.reservedTokens, Math.max(inputTokens, countedInputTokens));
      if (!usageMetadataReceived && generationStarted) outputTokens = reservation.maxOutputTokens;
      else if (!outputTokens && generatedText) outputTokens = Math.min(reservation.maxOutputTokens, estimateOutputTokens(generatedText));
      outputTokens = Math.min(Math.max(0, outputTokens), reservation.maxOutputTokens, Math.max(0, reservation.reservedTokens - inputTokens));
      if (!res.destroyed && !res.writableEnded) {
        emitChunk({ id: requestId, object: 'chat.completion.chunk', created, model: BLAZAR_MODEL_ID, choices: [{ index: 0, delta: {}, finish_reason: finishReason }] });
        emitChunk({ id: requestId, object: 'chat.completion.chunk', created, model: BLAZAR_MODEL_ID, choices: [], usage: { prompt_tokens: inputTokens, completion_tokens: outputTokens, total_tokens: inputTokens + outputTokens } });
        res.write('data: [DONE]\n\n');
        res.end();
      }
      status = clientClosed ? 'cancelled' : 'success';
    } else {
      const data = await upstream.json();
      usageMetadataReceived = Boolean(data.usageMetadata);
      inputTokens = Math.min(reservation.reservedTokens, Math.max(countedInputTokens, Number(data.usageMetadata?.promptTokenCount) || 0));
      const totalTokens = Number(data.usageMetadata?.totalTokenCount) || 0;
      const fallbackOutputTokens = (Number(data.usageMetadata?.candidatesTokenCount) || 0) + (Number(data.usageMetadata?.thoughtsTokenCount) || 0) + (Number(data.usageMetadata?.toolUsePromptTokenCount) || 0);
      const candidate = data?.candidates?.[0];
      if (!candidate || !candidate.content) {
        outputTokens = totalTokens > 0 ? Math.max(0, totalTokens - inputTokens) : (fallbackOutputTokens || 0);
        if (!usageMetadataReceived) generationStarted = false;
        return safeUnavailable();
      }
      generatedText = Array.isArray(candidate.content.parts) ? candidate.content.parts.map(part => typeof part.text === 'string' ? part.text : '').join('') : '';
      outputTokens = totalTokens > 0 ? Math.max(0, totalTokens - inputTokens) : (fallbackOutputTokens || (usageMetadataReceived ? Math.min(reservation.maxOutputTokens, estimateOutputTokens(generatedText)) : reservation.maxOutputTokens));
      outputTokens = Math.min(Math.max(0, outputTokens), reservation.maxOutputTokens, Math.max(0, reservation.reservedTokens - inputTokens));
      finishReason = toFinishReason(candidate.finishReason);
      status = 'success';
      res.set('X-Request-Id', requestId).json({
        id: requestId,
        object: 'chat.completion',
        created: Math.floor(startedAt / 1000),
        model: BLAZAR_MODEL_ID,
        choices: [{ index: 0, message: { role: 'assistant', content: generatedText }, finish_reason: finishReason }],
        usage: { prompt_tokens: inputTokens, completion_tokens: outputTokens, total_tokens: inputTokens + outputTokens }
      });
    }
  } catch (err) {
    if (clientClosed || (err.name === 'AbortError' && res.destroyed)) {
      status = 'cancelled';
    } else {
      status = 'error';
      if (!res.headersSent) {
        return safeUnavailable();
      }
      if (!res.writableEnded && !res.destroyed) {
        emitChunk({ error: { message: `${BLAZAR_MODEL_NAME} is temporarily unavailable. Please try again shortly.`, type: 'server_error', code: 'model_unavailable' } });
        res.write('data: [DONE]\n\n');
        res.end();
      }
    }
  } finally {
    activeGenerations = Math.max(0, activeGenerations - 1);
    res.removeListener('close', cancelIfDisconnected);
    if (reservedTokenBudget > 0) {
      if (generationStarted && !usageMetadataReceived) outputTokens = Math.max(outputTokens, reservedTokenBudget - Math.min(Math.max(0, inputTokens), reservedTokenBudget));
      inputTokens = Math.min(Math.max(0, inputTokens), reservedTokenBudget);
      outputTokens = Math.min(Math.max(0, outputTokens), Math.max(0, reservedTokenBudget - inputTokens));
    }
    const settle = db.transaction(() => {
      if (reservationId) db.prepare('DELETE FROM token_reservations WHERE id = ?').run(reservationId);
      if (status === 'success' || inputTokens || outputTokens) {
        recordUsage({ userId: identity.userId, apiKeyId: identity.apiKeyId, model: BLAZAR_MODEL_ID, status, latencyMs: Date.now() - startedAt, inputTokens, outputTokens, createdAt: startedAt });
      } else {
        recordUsage({ userId: identity.userId, apiKeyId: identity.apiKeyId, model: BLAZAR_MODEL_ID, status, latencyMs: Date.now() - startedAt, inputTokens: 0, outputTokens: 0, createdAt: startedAt });
      }
    });
    try { settle(); } catch (e) {}
  }
}

function createApp() {
  const app = express();
  app.disable('x-powered-by');
  if (String(process.env.TRUST_PROXY || '0') !== '0') app.set('trust proxy', Number(process.env.TRUST_PROXY || 1));
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"]
      }
    },
    crossOriginEmbedderPolicy: false
  }));
  app.use(express.json({ limit: '1mb', strict: true }));
  app.use(session({
    name: 'cosmos.sid',
    store: new SQLiteStore({ db: 'sessions.sqlite', dir: DATA_DIR, table: 'sessions', concurrentDB: true }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: SESSION_MAX_AGE_MS }
  }));

  const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: { message: 'Too many authentication attempts. Please try again later.', code: 'rate_limited' } } });
  const verifyLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: { message: 'Too many verification attempts. Please try again later.', code: 'rate_limited' } } });
  const apiIpLimiter = rateLimit({ windowMs: 60 * 1000, limit: 300, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: { message: 'Request rate temporarily limited. Please retry shortly.', code: 'rate_limited' } } });

  app.get('/api/health', (req, res) => res.json({ status: 'ok', name: APP_NAME, time: Date.now() }));
  app.get('/api/csrf', (req, res) => {
    if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    res.set('Cache-Control', 'no-store').json({ token: req.session.csrfToken });
  });

  app.post('/auth/register', authLimiter, csrfMiddleware, async (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const name = String(req.body?.name || '').trim().slice(0, 80);
    const password = String(req.body?.password || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return res.status(400).json({ error: { message: 'Enter a valid email address.', code: 'invalid_email' } });
    if (name.length < 2) return res.status(400).json({ error: { message: 'Enter a name with at least two characters.', code: 'invalid_name' } });
    if (password.length < 12 || password.length > 72 || Buffer.byteLength(password, 'utf8') > 72) return res.status(400).json({ error: { message: 'Use a password between 12 and 72 characters.', code: 'invalid_password' } });
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) return res.status(409).json({ error: { message: 'An account with this email may already exist. Try signing in.', code: 'account_exists' } });
    const user = { id: makeId(), email, name, password_hash: await bcrypt.hash(password, BCRYPT_ROUNDS), email_verified: EMAIL_VERIFICATION_REQUIRED ? 0 : 1, role: 'user', status: 'active', plan: 'free', created_at: Date.now() };
    try {
      db.prepare('INSERT INTO users (id,email,name,password_hash,email_verified,role,status,plan,created_at) VALUES (?,?,?,?,?,?,?,?,?)')
        .run(user.id, user.email, user.name, user.password_hash, user.email_verified, user.role, user.status, user.plan, user.created_at);
      if (EMAIL_VERIFICATION_REQUIRED) {
        try {
          await sendVerificationEmail(user);
        } catch (err) {
          db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
          return res.status(503).json({ error: { message: 'Email verification is temporarily unavailable. Please try again later.', code: 'email_unavailable' } });
        }
        return res.status(201).json({ requiresVerification: true, email: user.email, message: 'Check your email for a verification code.' });
      }
      regenerateSession(req, user, (err) => {
        if (err) return res.status(500).json({ error: { message: 'Unable to establish your session. Please sign in.', code: 'session_error' } });
        res.status(201).json({ user: safeUser(user), csrfToken: req.session.csrfToken });
      });
    } catch (err) {
      if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: { message: 'An account with this email may already exist. Try signing in.', code: 'account_exists' } });
      res.status(500).json({ error: { message: 'Unable to create your account right now.', code: 'registration_failed' } });
    }
  });

  app.post('/auth/verify-email', verifyLimiter, csrfMiddleware, (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const code = String(req.body?.code || '').trim();
    if (!EMAIL_VERIFICATION_REQUIRED) return res.status(400).json({ error: { message: 'Email verification is not enabled.', code: 'verification_disabled' } });
    if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: { message: 'Enter the six-digit code from your email.', code: 'invalid_code' } });
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user || user.email_verified) return res.status(400).json({ error: { message: 'This verification request is no longer valid. Try signing in.', code: 'invalid_code' } });
    const challenge = db.prepare('SELECT * FROM verification_codes WHERE user_id = ? AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1').get(user.id);
    if (!challenge || challenge.expires_at < Date.now() || challenge.attempts >= 5) return res.status(400).json({ error: { message: 'The code has expired or cannot be used. Request a new code.', code: 'code_expired' } });
    db.prepare('UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ?').run(challenge.id);
    const valid = timingSafeStringEqual(challenge.code_hash, sha256(`${email}:${code}:${SESSION_SECRET}`));
    if (!valid) return res.status(400).json({ error: { message: 'The code is incorrect.', code: 'invalid_code' } });
    const now = Date.now();
    db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(user.id);
    db.prepare('UPDATE verification_codes SET consumed_at = ? WHERE id = ?').run(now, challenge.id);
    user.email_verified = 1;
    regenerateSession(req, user, (err) => {
      if (err) return res.status(500).json({ error: { message: 'Unable to establish your session. Please sign in.', code: 'session_error' } });
      res.json({ user: safeUser(user), csrfToken: req.session.csrfToken });
    });
  });

  app.post('/auth/resend-code', verifyLimiter, csrfMiddleware, async (req, res) => {
    if (!EMAIL_VERIFICATION_REQUIRED) return res.status(400).json({ error: { message: 'Email verification is not enabled.', code: 'verification_disabled' } });
    const email = String(req.body?.email || '').trim().toLowerCase();
    const user = db.prepare('SELECT * FROM users WHERE email = ? AND email_verified = 0').get(email);
    if (user) {
      const latest = db.prepare('SELECT created_at FROM verification_codes WHERE user_id = ? ORDER BY created_at DESC LIMIT 1').get(user.id);
      if (latest && Date.now() - latest.created_at < 60000) return res.status(429).json({ error: { message: 'Wait a minute before requesting another code.', code: 'cooldown' } });
      try { await sendVerificationEmail(user); } catch (err) { return res.status(503).json({ error: { message: 'Email verification is temporarily unavailable.', code: 'email_unavailable' } }); }
    }
    res.json({ message: 'If this address requires verification, a new code will be sent.' });
  });

  app.post('/auth/login', authLimiter, csrfMiddleware, async (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (Buffer.byteLength(password, 'utf8') > 72 || !user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: { message: 'The email or password is incorrect.', code: 'invalid_credentials' } });
    if (user.status !== 'active') return res.status(403).json({ error: { message: 'This account is currently unavailable.', code: 'account_unavailable' } });
    if (EMAIL_VERIFICATION_REQUIRED && !user.email_verified) return res.status(403).json({ error: { message: 'Verify your email address before signing in.', code: 'email_not_verified' } });
    regenerateSession(req, user, (err) => {
      if (err) return res.status(500).json({ error: { message: 'Unable to establish your session.', code: 'session_error' } });
      res.json({ user: safeUser(user), csrfToken: req.session.csrfToken });
    });
  });

  app.post('/auth/logout', csrfMiddleware, (req, res) => {
    if (!req.session) return res.status(204).end();
    req.session.destroy(() => {
      res.clearCookie('cosmos.sid', { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' });
      res.status(204).end();
    });
  });

  app.get('/api/me', sessionRequired, (req, res) => {
    const sinceDay = new Date();
    sinceDay.setHours(0, 0, 0, 0);
    res.set('Cache-Control', 'no-store').json({ user: safeUser(req.user), usage: usageTotals(req.user.id, sinceDay.getTime()), blazarUsage: blazarDailyUsage(req.user.id), models: getModelList() });
  });

  app.get('/api/dashboard', sessionRequired, (req, res) => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const day = usageTotals(req.user.id, today.getTime());
    const month = usageTotals(req.user.id, Date.now() - 30 * 24 * 60 * 60 * 1000);
    const keys = db.prepare('SELECT COUNT(*) AS n FROM api_keys WHERE user_id = ? AND revoked_at IS NULL').get(req.user.id).n;
    const recent = db.prepare('SELECT id,model,status,latency_ms,created_at FROM usage_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 8').all(req.user.id);
    res.json({ today: day, month, activeKeys: Number(keys), blazarUsage: blazarDailyUsage(req.user.id), recent: recent.map(x => ({ id: x.id, model: displayModelName(x.model), status: x.status, latencyMs: x.latency_ms, createdAt: x.created_at })) });
  });

  app.get('/api/models', sessionRequired, (req, res) => res.json({ data: getModelList() }));

  app.get('/api/keys', sessionRequired, (req, res) => {
    const keys = db.prepare('SELECT id,label,prefix,last_four,created_at,last_used_at,revoked_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
    res.json({ data: keys.map(k => ({ id: k.id, name: k.label, prefix: k.prefix, lastFour: k.last_four, createdAt: k.created_at, lastUsedAt: k.last_used_at, revoked: Boolean(k.revoked_at) })) });
  });

  app.post('/api/keys', sessionRequired, csrfMiddleware, (req, res) => {
    const label = String(req.body?.name || 'Default key').trim().slice(0, 80) || 'Default key';
    const key = `cos_live_${crypto.randomBytes(32).toString('base64url')}`;
    const id = makeId();
    const now = Date.now();
    db.prepare('INSERT INTO api_keys (id,user_id,label,key_hash,prefix,last_four,created_at) VALUES (?,?,?,?,?,?,?)')
      .run(id, req.user.id, label, sha256(key), 'cos_live_', key.slice(-4), now);
    res.status(201).json({ data: { id, name: label, key, prefix: 'cos_live_', lastFour: key.slice(-4), createdAt: now } });
  });

  app.delete('/api/keys/:id', sessionRequired, csrfMiddleware, (req, res) => {
    const result = db.prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL').run(Date.now(), req.params.id, req.user.id);
    if (!result.changes) return res.status(404).json({ error: { message: 'API key not found.', code: 'key_not_found' } });
    res.status(204).end();
  });

  app.get('/api/usage', sessionRequired, (req, res) => {
    const days = Math.min(90, Math.max(1, Number(req.query.days || 30)));
    const since = Date.now() - days * 24 * 60 * 60 * 1000;
    const totals = usageTotals(req.user.id, since);
    const rows = db.prepare(`SELECT strftime('%Y-%m-%d', created_at / 1000, 'unixepoch', 'localtime') AS day,
      COUNT(*) AS requests, SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS successful,
      COALESCE(SUM(input_tokens),0) AS input_tokens, COALESCE(SUM(output_tokens),0) AS output_tokens
      FROM usage_logs WHERE user_id = ? AND created_at >= ? GROUP BY day ORDER BY day ASC`).all(req.user.id, since);
    res.json({ days, totals, blazarUsage: blazarDailyUsage(req.user.id), data: rows.map(r => ({ day: r.day, requests: Number(r.requests), successful: Number(r.successful || 0), inputTokens: Number(r.input_tokens || 0), outputTokens: Number(r.output_tokens || 0) })) });
  });

  app.patch('/api/account', sessionRequired, csrfMiddleware, (req, res) => {
    const name = String(req.body?.name || '').trim().slice(0, 80);
    if (name.length < 2) return res.status(400).json({ error: { message: 'Name must contain at least two characters.', code: 'invalid_name' } });
    db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, req.user.id);
    req.user.name = name;
    res.json({ user: safeUser(req.user) });
  });

  app.get('/api/service-status', sessionRequired, async (req, res) => {
    const baseConfigured = Boolean(process.env.PHOTON_API_BASE_URL || 'http://127.0.0.1:9655/v1');
    let reachable = false;
    let latencyMs = null;
    const started = Date.now();
    try {
      const base = String(process.env.PHOTON_API_BASE_URL || 'http://127.0.0.1:9655/v1').replace(/\/+$/, '') + '/';
      const response = await fetch(new URL('models', base), { signal: AbortSignal.timeout(2500), headers: process.env.PHOTON_API_KEY ? { Authorization: `Bearer ${process.env.PHOTON_API_KEY}` } : {} });
      reachable = response.ok;
      await response.body?.cancel();
      latencyMs = Date.now() - started;
    } catch (err) {
      reachable = false;
    }
    let blazarAvailable = false;
    if (process.env.GEMINI_API_KEY) {
      try {
        const modelUrl = new URL(`${GEMINI_API_BASE_URL}/models/${encodeURIComponent(GEMINI_MODEL)}`);
        modelUrl.searchParams.set('key', process.env.GEMINI_API_KEY);
        const modelResponse = await fetch(modelUrl, { signal: AbortSignal.timeout(3000) });
        blazarAvailable = modelResponse.ok;
        await modelResponse.body?.cancel();
      } catch (err) {
        blazarAvailable = false;
      }
    }
    res.json({ status: reachable ? 'available' : baseConfigured ? 'unavailable' : 'not_configured', model: PUBLIC_MODEL_NAME, latencyMs, blazarConfigured: Boolean(process.env.GEMINI_API_KEY), blazarAvailable, note: reachable ? 'Model service is responding.' : 'The model service could not be reached. Check the server configuration.' });
  });

  app.post('/api/playground', sessionRequired, csrfMiddleware, (req, res) => handleCompletion(req, res, { userId: req.user.id, apiKeyId: null }));
  app.get('/v1/models', apiIpLimiter, apiKeyRequired, (req, res) => res.json({ object: 'list', data: getModelList().map(model => ({ id: model.id, object: 'model', ...(process.env.PUBLIC_MODEL_CREATED_AT ? { created: Math.max(0, Number(process.env.PUBLIC_MODEL_CREATED_AT) || 0) } : {}), owned_by: 'cosmos' })) }));
  app.post('/v1/chat/completions', apiIpLimiter, apiKeyRequired, (req, res) => handleCompletion(req, res, { userId: req.apiUser.id, apiKeyId: req.apiKey.id }));

  app.use('/assets', express.static(path.join(__dirname, 'public'), { fallthrough: true, maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0 }));
  app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
  app.use((req, res) => {
    if (req.path.startsWith('/api/') || req.path.startsWith('/auth/') || req.path.startsWith('/v1/')) return res.status(404).json({ error: { message: 'Endpoint not found.', code: 'not_found' } });
    res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'));
  });
  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    const status = err.status === 413 ? 413 : 400;
    res.status(status).json({ error: { message: status === 413 ? 'The request is too large.' : 'The request could not be processed.', code: status === 413 ? 'payload_too_large' : 'bad_request' } });
  });
  return app;
}

const app = createApp();
if (require.main === module) {
  const server = app.listen(PORT, () => process.stdout.write(`${APP_NAME} API Platform listening on port ${PORT}\n`));
  const shutdown = () => server.close(() => {
    try { db.close(); } catch (e) {}
    process.exit(0);
  });
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

module.exports = { app, db, createApp, getModelList, sha256, PUBLIC_MODEL_ID, PUBLIC_MODEL_NAME, BLAZAR_MODEL_ID, BLAZAR_MODEL_NAME, BLAZAR_DAILY_TOKEN_LIMIT, blazarDailyUsage, reserveBlazarTokens };
