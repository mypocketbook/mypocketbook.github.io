-- Pocketbook: multi-person setup. Run once in Supabase → SQL Editor → New query → Run.
-- Safe to run more than once.

-- 1) Every person only sees and changes their own rows
alter table public.pocketbook_items enable row level security;
do $$ declare r record; begin
  for r in select policyname from pg_policies where schemaname='public' and tablename='pocketbook_items' loop
    execute format('drop policy %I on public.pocketbook_items', r.policyname);
  end loop;
end $$;
create policy "own rows" on public.pocketbook_items
  for all to authenticated
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- 2) The same item id can exist for different people (key = person + id)
do $$ declare c text; begin
  select conname into c from pg_constraint where conrelid='public.pocketbook_items'::regclass and contype='p';
  if c is not null then execute format('alter table public.pocketbook_items drop constraint %I', c); end if;
end $$;
alter table public.pocketbook_items alter column user_id set not null;
alter table public.pocketbook_items add primary key (user_id, id);

-- 3) Usernames (no emails stored here)
create table if not exists public.pocketbook_usernames(
  username   text primary key check (username ~ '^[a-z0-9_.]{3,20}$'),
  user_id    uuid not null unique references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.pocketbook_usernames enable row level security;
drop policy if exists "own username" on public.pocketbook_usernames;
create policy "own username" on public.pocketbook_usernames
  for all to authenticated
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- 4) "Is this username free?" — answers yes/no only, reveals nothing else
create or replace function public.pocketbook_username_free(u text)
returns boolean language sql security definer set search_path = public as $$
  select not exists (select 1 from public.pocketbook_usernames where username = lower(u));
$$;
revoke all on function public.pocketbook_username_free(text) from public;
grant execute on function public.pocketbook_username_free(text) to anon, authenticated;
