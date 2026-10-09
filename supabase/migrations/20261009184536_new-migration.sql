create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  username text not null unique check (char_length(username) between 3 and 64),
  email text not null unique check (email = lower(email)),
  password_hash text,
  webauthn_user_id text not null unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.passkeys (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  credential_id text not null unique,
  credential_public_key text not null,
  credential_algorithm integer not null,
  counter bigint not null default 0 check (counter >= 0),
  transports text[] not null default '{}',
  device_name text not null default 'My Passkey'
    check (char_length(device_name) between 1 and 64),
  last_used_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists passkeys_user_id_idx on public.passkeys(user_id);

create table if not exists public.express_sessions (
  sid varchar not null primary key,
  sess json not null,
  expire timestamp(6) not null
);

create index if not exists express_sessions_expire_idx
  on public.express_sessions(expire);

alter table public.users enable row level security;
alter table public.passkeys enable row level security;
alter table public.express_sessions enable row level security;
