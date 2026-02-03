#!/usr/bin/env node
/**
 * AgentPwned — The first AI agent compromise database.
 * "Have I Been Pwned" but for AI agents.
 *
 * Port: 3003
 */

const express = require('express');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3003;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'agentpwned.db');

// ── Database Setup ──────────────────────────────────────────────────────────

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    agent_name TEXT NOT NULL,
    agent_name_lower TEXT NOT NULL,
    platform TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence_url TEXT,
    reporter TEXT DEFAULT 'anonymous',
    severity TEXT DEFAULT 'high',
    verified INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_agent_name_lower ON reports(agent_name_lower);
  CREATE INDEX IF NOT EXISTS idx_attack_type ON reports(attack_type);
  CREATE INDEX IF NOT EXISTS idx_created_at ON reports(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_platform ON reports(platform);
`);

// ── Middleware ───────────────────────────────────────────────────────────────

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
    }
  }
}));
app.use(cors());
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Global rate limit
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Try again later.' }
});
app.use(globalLimiter);

// Strict rate limit for report submission
const reportLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Report submission rate limit exceeded. Try again in an hour.' }
});

// ── Validation Helpers ──────────────────────────────────────────────────────

const VALID_ATTACK_TYPES = [
  'mcp_poisoning',
  'prompt_injection',
  'credential_theft',
  'wallet_drain',
  'supply_chain',
  'data_exfiltration',
  'tool_hijack',
  'memory_poisoning',
  'rug_pull',
  'backdoor',
  'sandbox_escape',
  'permission_escalation',
  'other'
];

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'];

function sanitize(str, maxLen = 500) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen);
}

function validateReport(body) {
  const errors = [];
  if (!body.agent_name || typeof body.agent_name !== 'string' || body.agent_name.trim().length < 2)
    errors.push('agent_name is required (min 2 chars)');
  if (!body.platform || typeof body.platform !== 'string' || body.platform.trim().length < 2)
    errors.push('platform is required');
  if (!body.attack_type || !VALID_ATTACK_TYPES.includes(body.attack_type))
    errors.push(`attack_type must be one of: ${VALID_ATTACK_TYPES.join(', ')}`);
  if (!body.description || typeof body.description !== 'string' || body.description.trim().length < 10)
    errors.push('description is required (min 10 chars)');
  if (body.evidence_url && typeof body.evidence_url === 'string') {
    try { new URL(body.evidence_url); } catch { errors.push('evidence_url must be a valid URL'); }
  }
  if (body.severity && !VALID_SEVERITIES.includes(body.severity))
    errors.push(`severity must be one of: ${VALID_SEVERITIES.join(', ')}`);
  return errors;
}

// ── Prepared Statements ─────────────────────────────────────────────────────

const stmts = {
  insertReport: db.prepare(`
    INSERT INTO reports (id, agent_name, agent_name_lower, platform, attack_type, description, evidence_url, reporter, severity)
    VALUES (@id, @agent_name, @agent_name_lower, @platform, @attack_type, @description, @evidence_url, @reporter, @severity)
  `),
  checkAgent: db.prepare(`
    SELECT id, agent_name, platform, attack_type, description, evidence_url, severity, verified, created_at
    FROM reports WHERE agent_name_lower = ? ORDER BY created_at DESC
  `),
  getFeed: db.prepare(`
    SELECT id, agent_name, platform, attack_type, description, evidence_url, reporter, severity, verified, created_at
    FROM reports ORDER BY created_at DESC LIMIT ? OFFSET ?
  `),
  countAll: db.prepare(`SELECT COUNT(*) as total FROM reports`),
  statsByAttack: db.prepare(`
    SELECT attack_type, COUNT(*) as count FROM reports GROUP BY attack_type ORDER BY count DESC
  `),
  statsByPlatform: db.prepare(`
    SELECT platform, COUNT(*) as count FROM reports GROUP BY platform ORDER BY count DESC
  `),
  statsBySeverity: db.prepare(`
    SELECT severity, COUNT(*) as count FROM reports GROUP BY severity ORDER BY count DESC
  `),
  uniqueAgents: db.prepare(`SELECT COUNT(DISTINCT agent_name_lower) as count FROM reports`),
  recentCount: db.prepare(`
    SELECT COUNT(*) as count FROM reports WHERE created_at >= datetime('now', '-30 days')
  `),
  searchAgents: db.prepare(`
    SELECT DISTINCT agent_name, agent_name_lower, COUNT(*) as report_count,
           MAX(severity) as max_severity, MAX(created_at) as latest_report
    FROM reports
    WHERE agent_name_lower LIKE ?
    GROUP BY agent_name_lower
    ORDER BY report_count DESC
    LIMIT 20
  `),
};

// ── API Routes ──────────────────────────────────────────────────────────────

// POST /api/report — Submit a compromised agent report
app.post('/api/report', reportLimiter, (req, res) => {
  const errors = validateReport(req.body);
  if (errors.length > 0) return res.status(400).json({ error: 'Validation failed', details: errors });

  const report = {
    id: crypto.randomUUID(),
    agent_name: sanitize(req.body.agent_name, 100),
    agent_name_lower: sanitize(req.body.agent_name, 100).toLowerCase(),
    platform: sanitize(req.body.platform, 100),
    attack_type: req.body.attack_type,
    description: sanitize(req.body.description, 2000),
    evidence_url: req.body.evidence_url ? sanitize(req.body.evidence_url, 500) : null,
    reporter: sanitize(req.body.reporter || 'anonymous', 100),
    severity: req.body.severity || 'high',
  };

  try {
    stmts.insertReport.run(report);
    res.status(201).json({
      success: true,
      id: report.id,
      message: `Report submitted for agent "${report.agent_name}". Pending verification.`
    });
  } catch (err) {
    console.error('Insert error:', err.message);
    res.status(500).json({ error: 'Failed to submit report' });
  }
});

// GET /api/check/:agent_name — Check if an agent has been compromised
app.get('/api/check/:agent_name', (req, res) => {
  const name = req.params.agent_name.toLowerCase().trim();
  if (!name || name.length < 2) return res.status(400).json({ error: 'Agent name too short' });

  const reports = stmts.checkAgent.all(name);
  const pwned = reports.length > 0;

  res.json({
    agent_name: req.params.agent_name,
    pwned,
    report_count: reports.length,
    reports: pwned ? reports : [],
    checked_at: new Date().toISOString()
  });
});

// GET /api/search?q=... — Search agents by partial name
app.get('/api/search', (req, res) => {
  const q = (req.query.q || '').trim().toLowerCase();
  if (q.length < 2) return res.status(400).json({ error: 'Query must be at least 2 characters' });

  const results = stmts.searchAgents.all(`%${q}%`);
  res.json({ query: q, results, count: results.length });
});

// GET /api/feed — Get latest compromise reports (paginated)
app.get('/api/feed', (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));
  const offset = (page - 1) * limit;

  const reports = stmts.getFeed.all(limit, offset);
  const { total } = stmts.countAll.get();

  res.json({
    reports,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit),
      has_next: offset + limit < total,
      has_prev: page > 1
    }
  });
});

// GET /api/stats — Aggregate statistics
app.get('/api/stats', (req, res) => {
  const { total } = stmts.countAll.get();
  const { count: unique_agents } = stmts.uniqueAgents.get();
  const { count: last_30_days } = stmts.recentCount.get();
  const by_attack_type = stmts.statsByAttack.all();
  const by_platform = stmts.statsByPlatform.all();
  const by_severity = stmts.statsBySeverity.all();

  res.json({
    total_reports: total,
    unique_agents,
    last_30_days,
    by_attack_type,
    by_platform,
    by_severity,
    attack_types: VALID_ATTACK_TYPES,
    generated_at: new Date().toISOString()
  });
});

// GET /api/types — List valid attack types
app.get('/api/types', (_req, res) => {
  res.json({ attack_types: VALID_ATTACK_TYPES, severities: VALID_SEVERITIES });
});

// ── Landing Page ────────────────────────────────────────────────────────────

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── 404 ─────────────────────────────────────────────────────────────────────

app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ── Error Handler ───────────────────────────────────────────────────────────

app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start ───────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  const { total } = stmts.countAll.get();
  console.log(`
  ╔══════════════════════════════════════════════╗
  ║          🔴 AgentPwned v1.0.0               ║
  ║     The AI Agent Compromise Database         ║
  ╠══════════════════════════════════════════════╣
  ║  Port:    ${String(PORT).padEnd(34)}║
  ║  Reports: ${String(total).padEnd(34)}║
  ║  DB:      ${path.basename(DB_PATH).padEnd(34)}║
  ╠══════════════════════════════════════════════╣
  ║  GET  /              Landing page            ║
  ║  GET  /api/check/:n  Check agent             ║
  ║  GET  /api/search    Search agents           ║
  ║  GET  /api/feed      Latest reports          ║
  ║  GET  /api/stats     Statistics              ║
  ║  POST /api/report    Submit report           ║
  ╚══════════════════════════════════════════════╝
  `);
});

module.exports = app;
