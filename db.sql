-- USERS
create table if not exists users (
  id bigserial primary key,
  username text unique not null,
  rating int not null default 0,
  created_at timestamptz not null default now()
);

-- One debate for MVP (you can add more later)
create table if not exists debates (
  id bigserial primary key,
  question text not null,
  created_at timestamptz not null default now()
);

-- ARGUMENTS
create table if not exists messages (
  id bigserial primary key,
  debate_id bigint not null references debates(id) on delete cascade,
  user_id bigint not null references users(id) on delete cascade,
  side text not null check (side in ('YES','NO')),
  text text not null,
  score int not null default 0,
  created_at timestamptz not null default now()
);

-- VOTES (one vote per user per message)
create table if not exists votes (
  id bigserial primary key,
  message_id bigint not null references messages(id) on delete cascade,
  user_id bigint not null references users(id) on delete cascade,
  value int not null check (value in (-1, 1)),
  created_at timestamptz not null default now(),
  unique(message_id, user_id)
);

-- seed default debate (id=1) if empty
insert into debates (question)
select 'Is university education still worth it?'
where not exists (select 1 from debates);