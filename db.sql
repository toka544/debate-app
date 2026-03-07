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
  type       TEXT NOT NULL DEFAULT 'question',
  active     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────
-- MESSAGES (supports replies via parent_id)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS messages (
  id         BIGSERIAL PRIMARY KEY,
  debate_id  BIGINT NOT NULL REFERENCES debates(id) ON DELETE CASCADE,
  user_id    BIGINT NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
  parent_id  BIGINT REFERENCES messages(id) ON DELETE CASCADE,
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
-- REACTIONS
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
-- PAGE VIEWS
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS page_views (
  id         BIGSERIAL PRIMARY KEY,
  path       TEXT NOT NULL,
  visitor_id TEXT NOT NULL DEFAULT 'anon',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────
-- SAFE ALTERs
-- ─────────────────────────────────────────
ALTER TABLE votes      ADD COLUMN IF NOT EXISTS weight    INT     NOT NULL DEFAULT 1;
ALTER TABLE debates    ADD COLUMN IF NOT EXISTS category  TEXT    NOT NULL DEFAULT 'General';
ALTER TABLE debates    ADD COLUMN IF NOT EXISTS active    BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE debates    ADD COLUMN IF NOT EXISTS type      TEXT    NOT NULL DEFAULT 'question';
ALTER TABLE messages   ADD COLUMN IF NOT EXISTS parent_id BIGINT  REFERENCES messages(id) ON DELETE CASCADE;
ALTER TABLE page_views ADD COLUMN IF NOT EXISTS visitor_id TEXT   NOT NULL DEFAULT 'anon';

-- ─────────────────────────────────────────
-- INDEXES
-- ─────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_messages_debate_new    ON messages(debate_id, created_at DESC) WHERE parent_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_messages_debate_top    ON messages(debate_id, score DESC, created_at DESC) WHERE parent_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_messages_parent        ON messages(parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_votes_message_user     ON votes(message_id, user_id);
CREATE INDEX IF NOT EXISTS idx_users_rating           ON users(rating DESC, id ASC);
CREATE INDEX IF NOT EXISTS idx_reactions_message      ON reactions(message_id);
CREATE INDEX IF NOT EXISTS idx_page_views_created     ON page_views(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_page_views_path        ON page_views(path, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_debates_active         ON debates(active, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_debates_search         ON debates USING gin(to_tsvector('english', question));

-- ─────────────────────────────────────────
-- SEED
-- ─────────────────────────────────────────
DO $$
BEGIN
  IF (SELECT COUNT(*) FROM debates) = 0 THEN
    INSERT INTO debates (question, category, type) VALUES
      ('Is college a scam?',                               'Education',  'question'),
      ('Should billionaires exist?',                       'Economy',    'question'),
      ('Is democracy failing?',                            'Politics',   'question'),
      ('Will AI replace programmers?',                     'Technology', 'question'),
      ('Is remote work better than office work?',          'Work',       'question'),
      ('Is hustle culture toxic?',                         'Society',    'question'),
      ('Should governments regulate AI?',                  'Technology', 'question'),
      ('Is capitalism broken?',                            'Economy',    'question'),
      ('Will humans merge with AI in the future?',         'Technology', 'question'),
      ('Should social media be banned for kids?',          'Society',    'question'),
      ('Is happiness more important than success?',        'Life',       'question'),
      ('Are smartphones destroying attention spans?',      'Society',    'question'),
      ('Should AI have legal rights?',                     'Technology', 'question'),
      ('Is freedom of speech absolute?',                   'Politics',   'question'),
      ('Should universal basic income be implemented?',    'Economy',    'question'),
      ('Is social media doing more harm than good?',       'Society',    'question'),
      ('Should people be judged by their past mistakes?',  'Life',       'question'),
      ('Should privacy be sacrificed for security?',       'Politics',   'question'),
      ('Is discipline more important than talent?',        'Life',       'question'),
      ('Is modern society becoming weaker?',               'Society',    'question');
  END IF;
END $$;