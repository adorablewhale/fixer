-- Optional matcha fixer diagnostics, independent of script/dashboard/admin identities.
CREATE TABLE fixer_installations(id TEXT PRIMARY KEY, public_key TEXT NOT NULL, policy TEXT NOT NULL,
  created INTEGER NOT NULL, last_seen INTEGER NOT NULL);
CREATE INDEX fixer_installations_created ON fixer_installations(created);
CREATE TABLE fixer_nonces(installation TEXT NOT NULL, nonce TEXT NOT NULL, created INTEGER NOT NULL,
  PRIMARY KEY(installation,nonce));
CREATE INDEX fixer_nonces_created ON fixer_nonces(created);
CREATE TABLE fixer_runs(installation TEXT NOT NULL, run_id TEXT NOT NULL, seq INTEGER NOT NULL,
  started INTEGER NOT NULL, updated INTEGER NOT NULL, version TEXT NOT NULL, os TEXT NOT NULL,
  status TEXT NOT NULL, mode TEXT NOT NULL, update_result TEXT NOT NULL, tunnel TEXT NOT NULL,
  error TEXT NOT NULL, duration INTEGER NOT NULL, ended INTEGER NOT NULL,
  PRIMARY KEY(installation,run_id));
CREATE INDEX fixer_runs_updated ON fixer_runs(updated);
CREATE INDEX fixer_runs_started ON fixer_runs(installation,started);
CREATE TABLE fixer_releases(id INTEGER PRIMARY KEY CHECK(id=1), manifest TEXT NOT NULL);
