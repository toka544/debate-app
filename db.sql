-- ─────────────────────────────────────────
-- USERS
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id         BIGSERIAL PRIMARY KEY,
  username   TEXT UNIQUE NOT NULL,
  rating     INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────
-- DEBATES
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS debates (
  id         BIGSERIAL PRIMARY KEY,
  question   TEXT NOT NULL,
  category   TEXT NOT NULL DEFAULT 'General',
  active     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────
-- MESSAGES
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
-- REACTIONS (🔥 🤔 💡 per message per user)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reactions (
  id         BIGSERIAL PRIMARY KEY,
  message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id    BIGINT NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  emoji      TEXT NOT NULL CHECK (emoji IN ('fire', 'think', 'idea')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (message_id, user_id, emoji)
);

-- ─────────────────────────────────────────
-- PAGE VIEWS (analytics)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS page_views (
  id         BIGSERIAL PRIMARY KEY,
  path       TEXT NOT NULL,
  visitor_id TEXT NOT NULL,  -- anonymous cookie id
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────
-- SAFE ALTER for old deployments
-- ─────────────────────────────────────────
ALTER TABLE votes   ADD COLUMN IF NOT EXISTS weight  INT     NOT NULL DEFAULT 1;
ALTER TABLE debates ADD COLUMN IF NOT EXISTS category TEXT   NOT NULL DEFAULT 'General';
ALTER TABLE debates ADD COLUMN IF NOT EXISTS active   BOOLEAN NOT NULL DEFAULT TRUE;

-- ─────────────────────────────────────────
-- INDEXES
-- ─────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_messages_debate_new  ON messages(debate_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_debate_top  ON messages(debate_id, score DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_votes_message_user   ON votes(message_id, user_id);
CREATE INDEX IF NOT EXISTS idx_users_rating         ON users(rating DESC, id ASC);
CREATE INDEX IF NOT EXISTS idx_reactions_message    ON reactions(message_id);
CREATE INDEX IF NOT EXISTS idx_page_views_created   ON page_views(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_page_views_path      ON page_views(path, created_at DESC);

-- ─────────────────────────────────────────
-- SEED: 20 debates (only if empty)
-- ─────────────────────────────────────────
DO $$
BEGIN
  IF (SELECT COUNT(*) FROM debates) = 0 THEN
    INSERT INTO debates (question, category) VALUES
      ('Is college a scam?',                              'Education'),
      ('Should billionaires exist?',                      'Economy'),
      ('Is democracy failing?',                           'Politics'),
      ('Will AI replace programmers?',                    'Technology'),
      ('Is remote work better than office work?',         'Work'),
      ('Is hustle culture toxic?',                        'Society'),
      ('Should governments regulate AI?',                 'Technology'),
      ('Is capitalism broken?',                           'Economy'),
      ('Will humans merge with AI in the future?',        'Technology'),
      ('Should social media be banned for kids?',         'Society'),
      ('Is happiness more important than success?',       'Life'),
      ('Are smartphones destroying attention spans?',     'Society'),
      ('Should AI have legal rights?',                    'Technology'),
      ('Is freedom of speech absolute?',                  'Politics'),
      ('Should universal basic income be implemented?',   'Economy'),
      ('Is social media doing more harm than good?',      'Society'),
      ('Should people be judged by their past mistakes?', 'Life'),
      ('Should privacy be sacrificed for security?',      'Politics'),
      ('Is discipline more important than talent?',       'Life'),
      ('Is modern society becoming weaker?',              'Society');
  END IF;
END $$;