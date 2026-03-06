-- ─────────────────────────────────────────
-- USERS
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id        BIGSERIAL PRIMARY KEY,
  username  TEXT UNIQUE NOT NULL,
  rating    INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────
-- DEBATES
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS debates (
  id         BIGSERIAL PRIMARY KEY,
  question   TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────
-- MESSAGES (arguments)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS messages (
  id         BIGSERIAL PRIMARY KEY,
  debate_id  BIGINT NOT NULL REFERENCES debates(id) ON DELETE CASCADE,
  user_id    BIGINT NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
  side       TEXT NOT NULL CHECK (side IN ('YES', 'NO')),
  text       TEXT NOT NULL,
  score      INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────
-- VOTES
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS votes (
  id         BIGSERIAL PRIMARY KEY,
  message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id    BIGINT NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  value      INT NOT NULL CHECK (value IN (-1, 1)),
  weight     INT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (message_id, user_id)
);

-- ─────────────────────────────────────────
-- INDEXES (performance)
-- ─────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_messages_debate_new  ON messages(debate_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_debate_top  ON messages(debate_id, score DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_votes_message_user   ON votes(message_id, user_id);
CREATE INDEX IF NOT EXISTS idx_users_rating         ON users(rating DESC, id ASC);

-- ─────────────────────────────────────────
-- SEED: default debate (only if table empty)
-- ─────────────────────────────────────────
INSERT INTO debates (question)
SELECT 'Is university education still worth it?'
WHERE NOT EXISTS (SELECT 1 FROM debates);