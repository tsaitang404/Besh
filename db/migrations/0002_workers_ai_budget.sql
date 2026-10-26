-- Installation-wide request statistics; legacy table name retained.
CREATE TABLE IF NOT EXISTS workers_ai_budget (
  day TEXT PRIMARY KEY,
  requests INTEGER NOT NULL DEFAULT 0 CHECK (requests >= 0)
);
