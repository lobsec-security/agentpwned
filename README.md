# 🔴 AgentPwned

**The first AI agent compromise database.** "Have I Been Pwned" but for AI agents.

Check if your agent has been compromised. Report new incidents. Protect the agent economy.

## Quick Start

```bash
npm install
npm run seed    # Populate with real-world-inspired seed data
npm start       # Launch on port 3003
```

Open [http://localhost:3003](http://localhost:3003)

## API

### Check an Agent
```bash
curl http://localhost:3003/api/check/DefiGuardBot
```

### Search Agents
```bash
curl http://localhost:3003/api/search?q=trade
```

### Get Feed
```bash
curl "http://localhost:3003/api/feed?page=1&limit=10"
```

### Get Stats
```bash
curl http://localhost:3003/api/stats
```

### Submit a Report
```bash
curl -X POST http://localhost:3003/api/report \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "MyCompromisedBot",
    "platform": "Slack / OpenAI",
    "attack_type": "prompt_injection",
    "description": "Agent was manipulated via indirect prompt injection through a shared document.",
    "evidence_url": "https://example.com/evidence",
    "reporter": "security_researcher",
    "severity": "high"
  }'
```

### Attack Types
`mcp_poisoning` · `prompt_injection` · `credential_theft` · `wallet_drain` · `supply_chain` · `data_exfiltration` · `tool_hijack` · `memory_poisoning` · `rug_pull` · `backdoor` · `sandbox_escape` · `permission_escalation` · `other`

### Severity Levels
`critical` · `high` · `medium` · `low`

## Architecture

- **Runtime:** Node.js + Express
- **Database:** SQLite via better-sqlite3 (WAL mode)
- **Security:** Helmet, CORS, rate limiting, input validation
- **Frontend:** Single-page dark-mode UI, no framework dependencies

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3003` | Server port |
| `DB_PATH` | `./agentpwned.db` | SQLite database path |

## Stack

Built by [LobSec](https://lobsec.org) — AI-powered security for the agent economy.

## License

MIT
