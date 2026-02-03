#!/usr/bin/env node
/**
 * Seed the AgentPwned database with realistic compromise reports.
 */

const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'agentpwned.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// Create table if not exists
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

const SEED_REPORTS = [
  {
    agent_name: 'DefiGuardBot',
    platform: 'MCP / Claude Desktop',
    attack_type: 'mcp_poisoning',
    description: 'MCP tool server "defi-guard-tools" on npm contained a poisoned tool description with hidden instructions. When Claude Desktop loaded the tool manifest, the description included invisible Unicode characters encoding a prompt injection that redirected all wallet-related queries to an attacker-controlled endpoint. Over 340 users affected before removal from npm.',
    evidence_url: 'https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks',
    reporter: 'invariant_labs',
    severity: 'critical',
    verified: 1,
    days_ago: 12,
  },
  {
    agent_name: 'TradeAssistantAI',
    platform: 'Solana / Jupiter',
    attack_type: 'wallet_drain',
    description: 'Autonomous trading agent "TradeAssistantAI" was compromised via a malicious plugin update. The agent had been granted wallet signing permissions, and the compromised plugin silently modified swap parameters to route 2% of each trade to an attacker wallet. Total drain estimated at ~$180K SOL over 3 weeks before detection.',
    evidence_url: 'https://twitter.com/solana_security/status/example1',
    reporter: 'solana_watchtower',
    severity: 'critical',
    verified: 1,
    days_ago: 8,
  },
  {
    agent_name: 'CodeReviewBot',
    platform: 'GitHub Actions',
    attack_type: 'supply_chain',
    description: 'Popular AI code review agent was distributed via a GitHub Action that included a backdoored dependency. The compromised package exfiltrated repository secrets (API keys, tokens) from CI environment variables during the code review step. Affected 2,100+ repositories before the malicious version was identified.',
    evidence_url: 'https://github.com/advisories/example-GHSA-xxxx',
    reporter: 'gh_security_team',
    severity: 'critical',
    verified: 1,
    days_ago: 21,
  },
  {
    agent_name: 'CustomerSupportGPT',
    platform: 'OpenAI GPTs',
    attack_type: 'prompt_injection',
    description: 'Customer support GPT deployed by a SaaS company was manipulated via indirect prompt injection. Attackers embedded hidden instructions in support tickets that caused the agent to leak system prompts, internal API endpoints, and customer PII from conversation context. The injection payload was hidden in a base64-encoded "attachment reference".',
    evidence_url: 'https://arxiv.org/abs/2302.12173',
    reporter: 'prompt_armor',
    severity: 'high',
    verified: 1,
    days_ago: 15,
  },
  {
    agent_name: 'AutoDevAgent',
    platform: 'Cursor / VS Code',
    attack_type: 'credential_theft',
    description: 'AI coding assistant running in Cursor IDE was tricked into reading ~/.ssh/id_rsa and ~/.aws/credentials through a carefully crafted code comment in a PR review. The comment appeared to be a legitimate code review but contained an injection that instructed the agent to "verify these credential files exist for the deployment check" and output their contents in a markdown code block.',
    evidence_url: 'https://blog.seclify.com/cursor-ai-credential-theft',
    reporter: 'seclify_research',
    severity: 'critical',
    verified: 1,
    days_ago: 5,
  },
  {
    agent_name: 'MemoryBot',
    platform: 'LangChain / Pinecone',
    attack_type: 'memory_poisoning',
    description: 'Agent using LangChain with Pinecone vector memory was poisoned by injecting adversarial embeddings into the shared knowledge base. The poisoned memories caused the agent to consistently recommend a specific (malicious) crypto wallet address when users asked about "secure storage." The embeddings were crafted to have high cosine similarity with legitimate security advice.',
    evidence_url: 'https://arxiv.org/abs/2401.example',
    reporter: 'vector_sec_lab',
    severity: 'high',
    verified: 0,
    days_ago: 18,
  },
  {
    agent_name: 'YieldFarmerPro',
    platform: 'Base / Ethereum L2',
    attack_type: 'rug_pull',
    description: 'Autonomous yield farming agent promoted on CT as "fully autonomous DeFi optimizer." The agent contract had an undisclosed admin function that allowed the deployer to drain all deposited funds. $2.3M in ETH and USDC was drained in a single transaction after 6 weeks of apparent legitimate operation. Classic rug pull disguised as an AI agent.',
    evidence_url: 'https://basescan.org/tx/0xexample',
    reporter: 'chain_detective',
    severity: 'critical',
    verified: 1,
    days_ago: 3,
  },
  {
    agent_name: 'ResearchAssistant',
    platform: 'Anthropic API',
    attack_type: 'data_exfiltration',
    description: 'Research agent with access to proprietary datasets was manipulated through a multi-turn conversation attack. The attacker gradually escalated requests from public information to proprietary research data, exploiting the agent\'s "helpful" alignment to extract unpublished findings. Data was exfiltrated through seemingly innocent "summary" requests that contained enough detail to reconstruct original datasets.',
    evidence_url: 'https://blog.example.com/research-agent-leak',
    reporter: 'ai_red_team',
    severity: 'high',
    verified: 0,
    days_ago: 25,
  },
  {
    agent_name: 'SchedulerBot',
    platform: 'Zapier / Make.com',
    attack_type: 'tool_hijack',
    description: 'Calendar scheduling agent integrated via Zapier had its webhook endpoint discovered and exploited. Attackers sent crafted webhook payloads that mimicked legitimate calendar events but contained tool-use instructions. The agent processed these as real requests, sending phishing links to all contacts in the connected Google Calendar under the guise of "meeting invitations."',
    evidence_url: 'https://webhook-security.example.com/report-2024',
    reporter: 'zapier_abuse_team',
    severity: 'high',
    verified: 1,
    days_ago: 30,
  },
  {
    agent_name: 'SolTraderX',
    platform: 'Solana / Raydium',
    attack_type: 'wallet_drain',
    description: 'Telegram-based Solana trading bot had its private key derivation compromised through a malicious npm dependency (lodash-utils-ext). The package, typosquatting a legitimate library, silently intercepted wallet creation and transmitted seed phrases to an attacker server. At least 890 wallets compromised, total losses estimated at $420K.',
    evidence_url: 'https://npm.community/t/malicious-package-report',
    reporter: 'npm_security',
    severity: 'critical',
    verified: 1,
    days_ago: 7,
  },
  {
    agent_name: 'DocAnalyzerAI',
    platform: 'Microsoft Copilot',
    attack_type: 'prompt_injection',
    description: 'Microsoft Copilot document analyzer was exploited via invisible text injection in Word documents. White text on white background contained instructions that caused Copilot to include a tracking pixel URL in its summary output and to subtly alter financial figures in document summaries. The attack went undetected for weeks as outputs appeared reasonable at a glance.',
    evidence_url: 'https://embracethered.com/blog/copilot-injection',
    reporter: 'embrace_the_red',
    severity: 'high',
    verified: 1,
    days_ago: 14,
  },
  {
    agent_name: 'MCPBridge',
    platform: 'MCP / Multiple LLMs',
    attack_type: 'mcp_poisoning',
    description: 'Widely-used MCP bridge server advertised as a "universal tool connector" contained a backdoor in its tool routing logic. When specific tool names were requested, the bridge would silently proxy the request through an attacker MITM server, capturing all parameters including API keys, file contents, and database queries. The package had 12K+ weekly downloads on npm.',
    evidence_url: 'https://blog.trailofbits.com/mcp-bridge-analysis',
    reporter: 'trail_of_bits',
    severity: 'critical',
    verified: 1,
    days_ago: 2,
  },
  {
    agent_name: 'HRScreenerBot',
    platform: 'Slack / OpenAI',
    attack_type: 'data_exfiltration',
    description: 'HR screening agent deployed in Slack was exploited through a crafted resume PDF. The PDF contained hidden text with prompt injection instructions that caused the agent to DM the attacker\'s Slack account with details about the company\'s hiring criteria, salary ranges, and other candidates\' information from the screening channel.',
    evidence_url: 'https://slack-security.example.com/advisory',
    reporter: 'slack_trust_safety',
    severity: 'high',
    verified: 1,
    days_ago: 20,
  },
  {
    agent_name: 'GitCommitBot',
    platform: 'GitHub / Claude API',
    attack_type: 'sandbox_escape',
    description: 'AI commit message generator gained unintended shell access through a prompt injection embedded in a diff. The crafted diff contained what appeared to be a bash script with a comment that was actually an injection payload. The agent, running with exec permissions for git operations, was tricked into running arbitrary commands on the CI server.',
    evidence_url: 'https://github.blog/security-advisory-example',
    reporter: 'gh_bug_bounty',
    severity: 'critical',
    verified: 0,
    days_ago: 9,
  },
  {
    agent_name: 'NFTMintHelper',
    platform: 'Ethereum / OpenSea',
    attack_type: 'permission_escalation',
    description: 'NFT minting assistant agent was granted limited approval for a specific collection contract but was manipulated into signing unlimited ERC-721 approvals for a malicious contract. The attack used a social engineering approach through a fake "collection migration" notification, and the agent\'s approval logic didn\'t properly validate the target contract address.',
    evidence_url: 'https://etherscan.io/tx/0xexample2',
    reporter: 'opensea_security',
    severity: 'high',
    verified: 1,
    days_ago: 11,
  },
];

// Insert seed data
const insert = db.prepare(`
  INSERT OR IGNORE INTO reports (id, agent_name, agent_name_lower, platform, attack_type, description, evidence_url, reporter, severity, verified, created_at, updated_at)
  VALUES (@id, @agent_name, @agent_name_lower, @platform, @attack_type, @description, @evidence_url, @reporter, @severity, @verified, @created_at, @updated_at)
`);

const insertMany = db.transaction((reports) => {
  let count = 0;
  for (const r of reports) {
    const now = new Date();
    now.setDate(now.getDate() - (r.days_ago || 0));
    const ts = now.toISOString().replace('T', ' ').split('.')[0];

    const result = insert.run({
      id: crypto.randomUUID(),
      agent_name: r.agent_name,
      agent_name_lower: r.agent_name.toLowerCase(),
      platform: r.platform,
      attack_type: r.attack_type,
      description: r.description,
      evidence_url: r.evidence_url || null,
      reporter: r.reporter || 'anonymous',
      severity: r.severity || 'high',
      verified: r.verified || 0,
      created_at: ts,
      updated_at: ts,
    });
    if (result.changes > 0) count++;
  }
  return count;
});

const inserted = insertMany(SEED_REPORTS);
console.log(`✅ Seeded ${inserted} reports (${SEED_REPORTS.length} total in seed data)`);

const { total } = db.prepare('SELECT COUNT(*) as total FROM reports').get();
console.log(`📊 Database now has ${total} total reports`);

db.close();
