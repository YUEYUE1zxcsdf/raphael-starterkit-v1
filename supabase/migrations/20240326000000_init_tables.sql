-- ─────────────────────────────────────────────
-- 0) 前置扩展：启用 uuid-ossp（若已存在则跳过）
-- ─────────────────────────────────────────────
create extension if not exists "uuid-ossp";

-- ─────────────────────────────────────────────
-- 1) customers 表
-- ─────────────────────────────────────────────
create table if not exists public.customers (
  id                  uuid primary key default uuid_generate_v4(),
  user_id             uuid references auth.users(id) on delete cascade not null,
  creem_customer_id   text not null unique,
  email               text not null,
  name                text,
  country             text,
  credits             integer not null default 0,
  created_at          timestamptz not null default timezone('utc', now()),
  updated_at          timestamptz not null default timezone('utc', now()),
  metadata            jsonb not null default '{}'::jsonb,
  constraint customers_email_match  check (email = lower(email)),
  constraint credits_non_negative   check (credits >= 0)
);
alter table public.customers enable row level security;

-- ─────────────────────────────────────────────
-- 2) credits_history 表
-- ─────────────────────────────────────────────
create table if not exists public.credits_history (
  id            uuid primary key default uuid_generate_v4(),
  customer_id   uuid references public.customers(id) on delete cascade not null,
  amount        integer not null,
  type          text not null check (type in ('add', 'subtract')),
  description   text,
  creem_order_id text,
  created_at    timestamptz not null default timezone('utc', now()),
  metadata      jsonb not null default '{}'::jsonb
);
alter table public.credits_history enable row level security;

-- ─────────────────────────────────────────────
-- 3) subscriptions 表
-- ─────────────────────────────────────────────
create table if not exists public.subscriptions (
  id                    uuid primary key default uuid_generate_v4(),
  customer_id           uuid references public.customers(id) on delete cascade not null,
  creem_subscription_id text not null unique,
  creem_product_id      text not null,
  status                text not null check (
                          status in ('incomplete','expired','active','past_due',
                                     'canceled','unpaid','paused','trialing')),
  current_period_start  timestamptz not null,
  current_period_end    timestamptz not null,
  canceled_at           timestamptz,
  trial_end             timestamptz,
  metadata              jsonb not null default '{}'::jsonb,
  created_at            timestamptz not null default timezone('utc', now()),
  updated_at            timestamptz not null default timezone('utc', now())
);
alter table public.subscriptions enable row level security;

-- ─────────────────────────────────────────────
-- 4) 索引
-- ─────────────────────────────────────────────
create index if not exists customers_user_id_idx           on public.customers(user_id);
create index if not exists customers_creem_customer_id_idx on public.customers(creem_customer_id);

create index if not exists subscriptions_customer_id_idx   on public.subscriptions(customer_id);
create index if not exists subscriptions_status_idx        on public.subscriptions(status);

create index if not exists credits_history_customer_id_idx on public.credits_history(customer_id);
create index if not exists credits_history_created_at_idx  on public.credits_history(created_at);

-- ─────────────────────────────────────────────
-- 5) updated_at 触发器
-- ─────────────────────────────────────────────
create or replace function public.handle_updated_at()
returns trigger
language plpgsql
security definer
as $$
begin
  new.updated_at := timezone('utc', now());
  return new;
end;
$$;

create trigger handle_customers_updated_at
  before update on public.customers
  for each row
  execute function public.handle_updated_at();

create trigger handle_subscriptions_updated_at
  before update on public.subscriptions
  for each row
  execute function public.handle_updated_at();

-- ─────────────────────────────────────────────
-- 6) RLS 策略  (DROP‑IF‑EXISTS → CREATE)
-- ─────────────────────────────────────────────
-- customers
drop policy if exists "Users can view their own customer data"
  on public.customers;
create policy "Users can view their own customer data"
  on public.customers
  for select
  using (auth.uid() = user_id);

drop policy if exists "Users can update their own customer data"
  on public.customers;
create policy "Users can update their own customer data"
  on public.customers
  for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "Service role can manage customer data"
  on public.customers;
create policy "Service role can manage customer data"
  on public.customers
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

-- subscriptions
drop policy if exists "Users can view their own subscriptions"
  on public.subscriptions;
create policy "Users can view their own subscriptions"
  on public.subscriptions
  for select
  using (exists (
          select 1
          from public.customers c
          where c.id = subscriptions.customer_id
            and c.user_id = auth.uid()
        ));

drop policy if exists "Service role can manage subscriptions"
  on public.subscriptions;
create policy "Service role can manage subscriptions"
  on public.subscriptions
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

-- credits_history
drop policy if exists "Users can view their own credits history"
  on public.credits_history;
create policy "Users can view their own credits history"
  on public.credits_history
  for select
  using (exists (
          select 1
          from public.customers c
          where c.id = credits_history.customer_id
            and c.user_id = auth.uid()
        ));

drop policy if exists "Service role can manage credits history"
  on public.credits_history;
create policy "Service role can manage credits history"
  on public.credits_history
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

-- ─────────────────────────────────────────────
-- 7) 授权给 service_role
-- ─────────────────────────────────────────────
grant all privileges on table public.customers       to service_role;
grant all privileges on table public.subscriptions   to service_role;
grant all privileges on table public.credits_history to service_role;

-- 序列使用权（如果未来有自增列再用得到）
grant usage, select on all sequences in schema public to service_role;
