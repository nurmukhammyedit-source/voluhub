-- VoluHub full Supabase migration v8 — v7 baseline plus final requested changes
-- For Supabase SQL Editor. Back up the database and compare existing table/policy names before production use.
-- This migration is designed to be rerunnable and explicitly repairs missing columns in an existing help_requests table. It does not configure OAuth providers,
-- bucket secrets, Supabase URL/anon key, or external payment-provider integrations.

create extension if not exists pgcrypto;

-- -----------------------------------------------------------------------------
-- Profiles / roles / verification
-- -----------------------------------------------------------------------------
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  first_name text,
  last_name text,
  middle_name text,
  date_of_birth date,
  social_status text,
  phone text,
  city text,
  is_verified boolean not null default false,
  role text not null default 'user',
  avatar_url text,
  profile_consent_at timestamptz,
  verification_requested_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.profiles add column if not exists full_name text;
alter table public.profiles add column if not exists first_name text;
alter table public.profiles add column if not exists last_name text;
alter table public.profiles add column if not exists middle_name text;
alter table public.profiles add column if not exists date_of_birth date;
alter table public.profiles add column if not exists social_status text;
alter table public.profiles add column if not exists phone text;
alter table public.profiles add column if not exists city text;
alter table public.profiles add column if not exists is_verified boolean not null default false;
alter table public.profiles add column if not exists role text not null default 'user';
alter table public.profiles add column if not exists avatar_url text;
alter table public.profiles add column if not exists profile_consent_at timestamptz;
alter table public.profiles add column if not exists verification_requested_at timestamptz;
alter table public.profiles add column if not exists created_at timestamptz not null default now();
alter table public.profiles add column if not exists updated_at timestamptz not null default now();

update public.profiles set is_verified = false where is_verified is null;
update public.profiles set role = 'user' where role is null;

create or replace function public.voluhub_current_user_is_admin()
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.role::text = 'admin'
  );
$$;

create or replace function public.voluhub_current_user_is_verified()
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and coalesce(p.is_verified, false) = true
  );
$$;

create or replace function public.voluhub_set_updated_at()
returns trigger language plpgsql
set search_path = public
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists voluhub_profiles_updated_at on public.profiles;
create trigger voluhub_profiles_updated_at before update on public.profiles
for each row execute function public.voluhub_set_updated_at();

-- Users may update their ordinary profile fields, but may not grant themselves admin or verified status.
create or replace function public.voluhub_protect_profile_privileges()
returns trigger language plpgsql security definer
set search_path = public
as $$
begin
  if current_setting('voluhub.allow_profile_privilege_change', true) is distinct from 'on'
     and auth.uid() is not null
     and auth.uid() = old.id then
    new.role := old.role;
    new.is_verified := old.is_verified;
    new.verification_requested_at := old.verification_requested_at;
  end if;
  return new;
end;
$$;

drop trigger if exists voluhub_profiles_protect_privileges on public.profiles;
create trigger voluhub_profiles_protect_privileges before update on public.profiles
for each row execute function public.voluhub_protect_profile_privileges();

alter table public.profiles enable row level security;
drop policy if exists "profiles_select_own_or_admin" on public.profiles;
create policy "profiles_select_own_or_admin" on public.profiles
for select to authenticated using (id = auth.uid() or public.voluhub_current_user_is_admin());
drop policy if exists "profiles_insert_own" on public.profiles;
create policy "profiles_insert_own" on public.profiles
for insert to authenticated
with check (id = auth.uid() and coalesce(role::text, 'user') <> 'admin' and coalesce(is_verified, false) = false);
drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own" on public.profiles
for update to authenticated using (id = auth.uid()) with check (id = auth.uid());
grant select, insert, update on public.profiles to authenticated;

create or replace function public.request_profile_verification()
returns void language plpgsql security definer
set search_path = public
as $$
declare v_uid uuid := auth.uid();
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  if not exists (select 1 from public.profiles p where p.id = v_uid) then
    raise exception 'Profile not found';
  end if;
  if exists (select 1 from public.profiles p where p.id = v_uid and p.is_verified = true) then
    return;
  end if;
  perform set_config('voluhub.allow_profile_privilege_change', 'on', true);
  update public.profiles
    set verification_requested_at = coalesce(verification_requested_at, now())
    where id = v_uid and coalesce(is_verified, false) = false;
  perform set_config('voluhub.allow_profile_privilege_change', 'off', true);
end;
$$;

create or replace function public.admin_set_profile_verified(p_user_id uuid, p_verified boolean)
returns void language plpgsql security definer
set search_path = public
as $$
begin
  if auth.uid() is null or not public.voluhub_current_user_is_admin() then
    raise exception 'Administrator permission required';
  end if;
  if p_user_id is null or p_verified is null then raise exception 'User and verification status are required'; end if;
  perform set_config('voluhub.allow_profile_privilege_change', 'on', true);
  update public.profiles
    set is_verified = p_verified,
        verification_requested_at = case when p_verified then coalesce(verification_requested_at, now()) else null end
    where id = p_user_id;
  perform set_config('voluhub.allow_profile_privilege_change', 'off', true);
  if not found then raise exception 'Profile not found'; end if;
end;
$$;
revoke all on function public.request_profile_verification() from public, anon;
revoke all on function public.admin_set_profile_verified(uuid, boolean) from public, anon;
grant execute on function public.request_profile_verification() to authenticated;
grant execute on function public.admin_set_profile_verified(uuid, boolean) to authenticated;

-- -----------------------------------------------------------------------------
-- Help requests. Add all HTML-required columns even if the table existed already.
-- Address and phone are intentionally excluded from the public feed.
-- -----------------------------------------------------------------------------
create table if not exists public.help_requests (
  id uuid primary key default gen_random_uuid(),
  requester_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  city text not null,
  category text not null,
  address text not null,
  phone text not null,
  images text[] not null default '{}',
  description text not null,
  urgency text not null default 'medium',
  vulnerability text[] not null default '{}',
  status text not null default 'pending',
  helper_id uuid references auth.users(id) on delete set null,
  helper_signature text,
  reviewed_by uuid references auth.users(id) on delete set null,
  reviewed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Older installations may have an incomplete table. Add each field used by the HTML.
alter table public.help_requests add column if not exists id uuid default gen_random_uuid();
alter table public.help_requests add column if not exists requester_id uuid references auth.users(id) on delete cascade;
alter table public.help_requests add column if not exists name text default 'Көмек сұрауы';
alter table public.help_requests add column if not exists city text default 'Көрсетілмеген';
alter table public.help_requests add column if not exists category text default 'Басқа';
alter table public.help_requests add column if not exists address text default 'Көрсетілмеген';
alter table public.help_requests add column if not exists phone text default 'Көрсетілмеген';
alter table public.help_requests add column if not exists images text[] not null default '{}';
alter table public.help_requests add column if not exists description text default '';
alter table public.help_requests add column if not exists urgency text not null default 'medium';
alter table public.help_requests add column if not exists vulnerability text[] not null default '{}';
alter table public.help_requests add column if not exists status text not null default 'pending';
alter table public.help_requests add column if not exists helper_id uuid references auth.users(id) on delete set null;
alter table public.help_requests add column if not exists helper_signature text;
alter table public.help_requests add column if not exists reviewed_by uuid references auth.users(id) on delete set null;
alter table public.help_requests add column if not exists reviewed_at timestamptz;
alter table public.help_requests add column if not exists created_at timestamptz not null default now();
alter table public.help_requests add column if not exists updated_at timestamptz not null default now();

-- Existing legacy rows are not assigned to a different user. New submissions include requester_id.

update public.help_requests set id = gen_random_uuid() where id is null;
update public.help_requests set name = 'Көмек сұрауы' where name is null or btrim(name) = '';
update public.help_requests set city = 'Көрсетілмеген' where city is null or btrim(city) = '';
update public.help_requests set category = 'Басқа' where category is null or btrim(category) = '';
update public.help_requests set address = 'Көрсетілмеген' where address is null or btrim(address) = '';
update public.help_requests set phone = 'Көрсетілмеген' where phone is null or btrim(phone) = '';
update public.help_requests set description = '' where description is null;
update public.help_requests set images = '{}' where images is null;
update public.help_requests set vulnerability = '{}' where vulnerability is null;
update public.help_requests set urgency = 'medium' where urgency is null or urgency not in ('critical','high','medium','low');
update public.help_requests set created_at = now() where created_at is null;
update public.help_requests set updated_at = now() where updated_at is null;

-- Replace stale status checks before normalizing values, so old checks won't reject the update.
do $$
declare c record;
begin
  for c in
    select conname from pg_constraint
    where conrelid = 'public.help_requests'::regclass
      and contype = 'c'
      and pg_get_constraintdef(oid) ilike '%status%'
  loop
    execute format('alter table public.help_requests drop constraint %I', c.conname);
  end loop;
end $$;
update public.help_requests
set status = 'pending'
where status is null or status not in ('pending','approved','rejected','in_progress','awaiting_verification','completed');

alter table public.help_requests alter column id set default gen_random_uuid();
alter table public.help_requests alter column id set not null;
alter table public.help_requests alter column name set default 'Көмек сұрауы';
alter table public.help_requests alter column name set not null;
alter table public.help_requests alter column city set default 'Көрсетілмеген';
alter table public.help_requests alter column city set not null;
alter table public.help_requests alter column category set default 'Басқа';
alter table public.help_requests alter column category set not null;
alter table public.help_requests alter column address set default 'Көрсетілмеген';
alter table public.help_requests alter column address set not null;
alter table public.help_requests alter column phone set default 'Көрсетілмеген';
alter table public.help_requests alter column phone set not null;
alter table public.help_requests alter column images set default '{}';
alter table public.help_requests alter column images set not null;
alter table public.help_requests alter column description set default '';
alter table public.help_requests alter column description set not null;
alter table public.help_requests alter column urgency set default 'medium';
alter table public.help_requests alter column urgency set not null;
alter table public.help_requests alter column vulnerability set default '{}';
alter table public.help_requests alter column vulnerability set not null;
alter table public.help_requests alter column status set default 'pending';
alter table public.help_requests alter column status set not null;
alter table public.help_requests alter column created_at set default now();
alter table public.help_requests alter column created_at set not null;
alter table public.help_requests alter column updated_at set default now();
alter table public.help_requests alter column updated_at set not null;

-- If a legacy table had no id key, create a unique index so its ids remain stable.
create unique index if not exists help_requests_id_uidx on public.help_requests(id);
create index if not exists help_requests_status_created_idx on public.help_requests(status, created_at desc);
create index if not exists help_requests_requester_idx on public.help_requests(requester_id);
create index if not exists help_requests_helper_idx on public.help_requests(helper_id);


do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conrelid = 'public.help_requests'::regclass
      and conname = 'voluhub_help_requests_status_check'
  ) then
    execute 'alter table public.help_requests add constraint voluhub_help_requests_status_check check (status in (''pending'',''approved'',''rejected'',''in_progress'',''awaiting_verification'',''completed''))';
  end if;
end $$;

drop trigger if exists voluhub_help_requests_updated_at on public.help_requests;
create trigger voluhub_help_requests_updated_at before update on public.help_requests
for each row execute function public.voluhub_set_updated_at();

alter table public.help_requests enable row level security;
-- Remove legacy permissive policies on this sensitive table so they cannot override the new rules.
do $$
declare p record;
begin
  for p in select policyname from pg_policies where schemaname='public' and tablename='help_requests'
  loop
    execute format('drop policy if exists %I on public.help_requests', p.policyname);
  end loop;
end $$;
create policy "help_requests_insert_own_pending" on public.help_requests
for insert to authenticated
with check (requester_id::text = auth.uid()::text and status = 'pending' and helper_id is null);
create policy "help_requests_select_owner_helper_admin" on public.help_requests
for select to authenticated
using (requester_id::text = auth.uid()::text or helper_id::text = auth.uid()::text or public.voluhub_current_user_is_admin());
create policy "help_requests_admin_update_only" on public.help_requests
for update to authenticated
using (public.voluhub_current_user_is_admin())
with check (public.voluhub_current_user_is_admin());
grant select, insert, update on public.help_requests to authenticated;

-- Public feed deliberately omits the private address and phone fields.
drop view if exists public.help_requests_feed;
create view public.help_requests_feed as
select id, requester_id, name, city, category, images, description, urgency,
       vulnerability, status, helper_id, created_at, updated_at
from public.help_requests
where status in ('approved','in_progress','awaiting_verification','completed');
grant select on public.help_requests_feed to anon, authenticated;

-- -----------------------------------------------------------------------------
-- Giveaways; public feed excludes address and phone. Full contact fields are
-- readable only by verified accounts (or the owner/admin) through the base table.
-- -----------------------------------------------------------------------------
create table if not exists public.giveaways (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  city text not null,
  category text not null,
  address text not null,
  phone text not null,
  images text[] not null default '{}',
  description text not null,
  status text not null default 'open' check (status in ('open','reserved','closed','rejected')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists giveaways_status_created_idx on public.giveaways(status, created_at desc);
create index if not exists giveaways_owner_idx on public.giveaways(owner_id);
alter table public.giveaways add column if not exists updated_at timestamptz not null default now();
drop trigger if exists voluhub_giveaways_updated_at on public.giveaways;
create trigger voluhub_giveaways_updated_at before update on public.giveaways
for each row execute function public.voluhub_set_updated_at();
alter table public.giveaways enable row level security;
drop policy if exists "giveaways_verified_read" on public.giveaways;
drop policy if exists "giveaways_insert_own" on public.giveaways;
drop policy if exists "giveaways_update_owner_or_admin" on public.giveaways;
create policy "giveaways_verified_read" on public.giveaways
for select to authenticated using (
  (status = 'open' and public.voluhub_current_user_is_verified())
  or owner_id = auth.uid() or public.voluhub_current_user_is_admin()
);
create policy "giveaways_insert_own" on public.giveaways
for insert to authenticated with check (owner_id = auth.uid() and public.voluhub_current_user_is_verified());
create policy "giveaways_update_owner_or_admin" on public.giveaways
for update to authenticated using (owner_id = auth.uid() or public.voluhub_current_user_is_admin())
with check (owner_id = auth.uid() or public.voluhub_current_user_is_admin());
grant select, insert, update on public.giveaways to authenticated;
create or replace view public.giveaways_public_feed as
select id, owner_id, title, city, category, images, description, status, created_at
from public.giveaways where status = 'open';
grant select on public.giveaways_public_feed to anon, authenticated;

-- -----------------------------------------------------------------------------
-- Partners and partnership applications
-- -----------------------------------------------------------------------------
create table if not exists public.partners (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  website text,
  description text not null,
  logo_url text,
  image_urls text[] not null default '{}',
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);
-- Additive changes keep existing partner records intact.
alter table public.partners add column if not exists logo_url text;
alter table public.partners add column if not exists image_urls text[] not null default '{}';
alter table public.partners enable row level security;
drop policy if exists "partners_public_read" on public.partners;
drop policy if exists "partners_admin_write" on public.partners;
create policy "partners_public_read" on public.partners
for select to anon, authenticated using (true);
create policy "partners_admin_write" on public.partners
for all to authenticated using (public.voluhub_current_user_is_admin())
with check (public.voluhub_current_user_is_admin());
grant select on public.partners to anon, authenticated;
grant insert, update on public.partners to authenticated;

create table if not exists public.partnership_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  company_name text not null,
  bin text not null check (bin ~ '^[0-9]{12}$'),
  contact text not null,
  contact_email text,
  message text not null,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now()
);
alter table public.partnership_requests add column if not exists contact_email text;
alter table public.partnership_requests enable row level security;
drop policy if exists "partnership_requests_insert_own" on public.partnership_requests;
drop policy if exists "partnership_requests_read_owner_or_admin" on public.partnership_requests;
drop policy if exists "partnership_requests_admin_update" on public.partnership_requests;
create policy "partnership_requests_insert_own" on public.partnership_requests
for insert to authenticated with check (user_id = auth.uid());
create policy "partnership_requests_read_owner_or_admin" on public.partnership_requests
for select to authenticated using (user_id = auth.uid() or public.voluhub_current_user_is_admin());
create policy "partnership_requests_admin_update" on public.partnership_requests
for update to authenticated using (public.voluhub_current_user_is_admin())
with check (public.voluhub_current_user_is_admin());
grant select, insert, update on public.partnership_requests to authenticated;

-- -----------------------------------------------------------------------------
-- Notifications. Admins may create a notification for another user's action;
-- ordinary users can read/update only their own notifications.
-- -----------------------------------------------------------------------------
create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  message text not null default '',
  type text not null default 'info',
  is_read boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists notifications_user_created_idx on public.notifications(user_id, created_at desc);
alter table public.notifications enable row level security;
drop policy if exists "notifications_select_own_or_admin" on public.notifications;
drop policy if exists "notifications_insert_own_or_admin" on public.notifications;
drop policy if exists "notifications_update_own" on public.notifications;
create policy "notifications_select_own_or_admin" on public.notifications
for select to authenticated using (user_id = auth.uid() or public.voluhub_current_user_is_admin());
create policy "notifications_insert_own_or_admin" on public.notifications
for insert to authenticated with check (user_id = auth.uid() or public.voluhub_current_user_is_admin());
create policy "notifications_update_own" on public.notifications
for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
grant select, insert, update on public.notifications to authenticated;

-- -----------------------------------------------------------------------------
-- Demo donations and goal counter. This is only a database demo record, never a payment.
-- -----------------------------------------------------------------------------
create table if not exists public.fundraising_goals (
  id integer primary key,
  target_amount numeric(14,2) not null default 25000000,
  raised_amount numeric(14,2) not null default 0,
  updated_at timestamptz not null default now(),
  check (target_amount >= 0), check (raised_amount >= 0)
);
alter table public.fundraising_goals add column if not exists updated_at timestamptz not null default now();
insert into public.fundraising_goals(id,target_amount,raised_amount)
values (1,25000000,0) on conflict (id) do nothing;
create table if not exists public.donations (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  amount numeric(12,2) not null check (amount >= 500 and amount <= 500000),
  payment_mode text not null default 'demo' check (payment_mode = 'demo'),
  donor_name text,
  donor_email text,
  created_at timestamptz not null default now()
);
alter table public.donations add column if not exists payment_mode text not null default 'demo';
alter table public.donations add column if not exists donor_name text;
alter table public.donations add column if not exists donor_email text;
create index if not exists donations_user_created_idx on public.donations(user_id, created_at desc);
alter table public.fundraising_goals enable row level security;
alter table public.donations enable row level security;
drop policy if exists "fundraising_goals_public_read" on public.fundraising_goals;
drop policy if exists "donations_read_own_or_admin" on public.donations;
create policy "fundraising_goals_public_read" on public.fundraising_goals
for select to anon, authenticated using (true);
create policy "donations_read_own_or_admin" on public.donations
for select to authenticated using (user_id = auth.uid() or public.voluhub_current_user_is_admin());
grant select on public.fundraising_goals to anon, authenticated;
grant select on public.donations to authenticated;

-- The demo-donation RPC is defined once in the final targeted-fixes section below.


-- -----------------------------------------------------------------------------
-- Ecology campaigns and participants
-- -----------------------------------------------------------------------------
create table if not exists public.eco_campaigns (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  city text not null,
  location text not null,
  event_date date not null,
  time_text text not null,
  description text not null,
  agenda text[] not null default '{}',
  bring text not null default '',
  rules text not null default '',
  image_url text,
  status text not null default 'draft' check (status in ('draft','published','archived')),
  created_by uuid references auth.users(id) on delete set null,
  participant_count integer not null default 0 check (participant_count >= 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.eco_campaigns add column if not exists participant_count integer not null default 0;
alter table public.eco_campaigns enable row level security;
drop policy if exists "eco_campaigns_public_read_published" on public.eco_campaigns;
drop policy if exists "eco_campaigns_admin_write" on public.eco_campaigns;
create policy "eco_campaigns_public_read_published" on public.eco_campaigns
for select to anon, authenticated using (status = 'published' or public.voluhub_current_user_is_admin());
create policy "eco_campaigns_admin_write" on public.eco_campaigns
for all to authenticated using (public.voluhub_current_user_is_admin())
with check (public.voluhub_current_user_is_admin());
grant select on public.eco_campaigns to anon, authenticated;
grant insert, update on public.eco_campaigns to authenticated;

create table if not exists public.eco_participants (
  campaign_id uuid not null references public.eco_campaigns(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  status text not null default 'registered' check (status in ('registered','cancelled','attended')),
  created_at timestamptz not null default now(),
  primary key (campaign_id, user_id)
);
alter table public.eco_participants enable row level security;
drop policy if exists "eco_participants_read_own_or_admin" on public.eco_participants;
drop policy if exists "eco_participants_insert_own_verified" on public.eco_participants;
drop policy if exists "eco_participants_update_own" on public.eco_participants;
create policy "eco_participants_read_own_or_admin" on public.eco_participants
for select to authenticated using (user_id = auth.uid() or public.voluhub_current_user_is_admin());
create policy "eco_participants_insert_own_verified" on public.eco_participants
for insert to authenticated with check (user_id = auth.uid() and public.voluhub_current_user_is_verified());
create policy "eco_participants_update_own" on public.eco_participants
for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
grant select, insert, update on public.eco_participants to authenticated;

create or replace function public.voluhub_adjust_eco_participant_count()
returns trigger language plpgsql security definer
set search_path = public
as $$
begin
  if tg_op = 'INSERT' then
    update public.eco_campaigns set participant_count = participant_count + 1 where id = new.campaign_id;
    return new;
  elsif tg_op = 'DELETE' then
    update public.eco_campaigns set participant_count = greatest(0, participant_count - 1) where id = old.campaign_id;
    return old;
  end if;
  return null;
end;
$$;
drop trigger if exists voluhub_eco_participant_count on public.eco_participants;
create trigger voluhub_eco_participant_count after insert or delete on public.eco_participants
for each row execute function public.voluhub_adjust_eco_participant_count();

-- -----------------------------------------------------------------------------
-- Privacy consent, private help reports, and validated help workflow RPCs
-- -----------------------------------------------------------------------------
create table if not exists public.privacy_consents (
  request_id uuid not null references public.help_requests(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  signature text not null,
  consent_text text not null,
  signed_at timestamptz not null default now(),
  primary key (request_id, user_id)
);
alter table public.privacy_consents enable row level security;
drop policy if exists "privacy_consents_insert_own" on public.privacy_consents;
drop policy if exists "privacy_consents_select_own_or_admin" on public.privacy_consents;
drop policy if exists "privacy_consents_update_own" on public.privacy_consents;
create policy "privacy_consents_insert_own" on public.privacy_consents
for insert to authenticated with check (user_id = auth.uid());
create policy "privacy_consents_select_own_or_admin" on public.privacy_consents
for select to authenticated using (user_id = auth.uid() or public.voluhub_current_user_is_admin());
create policy "privacy_consents_update_own" on public.privacy_consents
for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
grant select, insert, update on public.privacy_consents to authenticated;

create table if not exists public.help_reports (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null references public.help_requests(id) on delete cascade,
  helper_id uuid not null references auth.users(id) on delete cascade,
  description text not null,
  images text[] not null default '{}',
  status text not null default 'pending' check (status in ('pending','approved','revision_requested')),
  reviewed_by uuid references auth.users(id) on delete set null,
  review_note text,
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists help_reports_status_created_idx on public.help_reports(status, created_at desc);
create index if not exists help_reports_request_idx on public.help_reports(request_id);
alter table public.help_reports enable row level security;
drop policy if exists "help_reports_read_owner_helper_admin" on public.help_reports;
create policy "help_reports_read_owner_helper_admin" on public.help_reports
for select to authenticated using (helper_id = auth.uid() or public.voluhub_current_user_is_admin());
grant select on public.help_reports to authenticated;

create or replace function public.get_help_request_contact(p_request_id uuid)
returns table(address text, phone text)
language plpgsql security definer
set search_path = public
as $$
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if not public.voluhub_current_user_is_verified() then raise exception 'Verified profile required'; end if;
  if not exists (select 1 from public.privacy_consents c where c.request_id = p_request_id and c.user_id = auth.uid()) then
    raise exception 'Privacy consent is required';
  end if;
  return query
    select h.address, h.phone from public.help_requests h
    where h.id = p_request_id
      and h.status in ('approved','in_progress')
      and (h.helper_id is null or h.helper_id = auth.uid());
end;
$$;

create or replace function public.start_help_assignment(p_request_id uuid, p_signature text)
returns boolean language plpgsql security definer
set search_path = public
as $$
declare v_count integer;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if not public.voluhub_current_user_is_verified() then raise exception 'Verified profile required'; end if;
  if p_signature is null or length(btrim(p_signature)) < 3 then raise exception 'A full-name signature is required'; end if;
  if not exists (select 1 from public.privacy_consents c where c.request_id = p_request_id and c.user_id = auth.uid()) then
    raise exception 'Privacy consent is required';
  end if;
  update public.help_requests h
    set helper_id = auth.uid(), helper_signature = btrim(p_signature), status = 'in_progress'
    where h.id = p_request_id and h.status = 'approved' and h.helper_id is null;
  get diagnostics v_count = row_count;
  return v_count = 1;
end;
$$;

create or replace function public.submit_help_report(p_request_id uuid, p_description text, p_image_paths text[])
returns uuid language plpgsql security definer
set search_path = public
as $$
declare v_report_id uuid;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if p_description is null or length(btrim(p_description)) < 3 then raise exception 'Report description is required'; end if;
  if p_image_paths is null or cardinality(p_image_paths) < 1 then raise exception 'At least one report image is required'; end if;
  update public.help_requests h set status = 'awaiting_verification'
    where h.id = p_request_id and h.helper_id = auth.uid() and h.status = 'in_progress';
  if not found then raise exception 'This help request is not assigned to you'; end if;
  insert into public.help_reports(request_id, helper_id, description, images, status)
    values (p_request_id, auth.uid(), btrim(p_description), p_image_paths, 'pending')
    returning id into v_report_id;
  return v_report_id;
end;
$$;

create or replace function public.review_help_report(p_report_id uuid, p_approve boolean, p_note text default null)
returns void language plpgsql security definer
set search_path = public
as $$
declare v_request_id uuid;
begin
  if auth.uid() is null or not public.voluhub_current_user_is_admin() then raise exception 'Administrator permission required'; end if;
  select r.request_id into v_request_id from public.help_reports r where r.id = p_report_id and r.status = 'pending';
  if v_request_id is null then raise exception 'Pending report not found'; end if;
  update public.help_reports
    set status = case when p_approve then 'approved' else 'revision_requested' end,
        reviewed_by = auth.uid(), review_note = p_note, reviewed_at = now()
    where id = p_report_id and status = 'pending';
  update public.help_requests
    set status = case when p_approve then 'completed' else 'in_progress' end
    where id = v_request_id;
end;
$$;
revoke all on function public.get_help_request_contact(uuid) from public, anon;
revoke all on function public.start_help_assignment(uuid, text) from public, anon;
revoke all on function public.submit_help_report(uuid, text, text[]) from public, anon;
revoke all on function public.review_help_report(uuid, boolean, text) from public, anon;
grant execute on function public.get_help_request_contact(uuid) to authenticated;
grant execute on function public.start_help_assignment(uuid, text) to authenticated;
grant execute on function public.submit_help_report(uuid, text, text[]) to authenticated;
grant execute on function public.review_help_report(uuid, boolean, text) to authenticated;

-- -----------------------------------------------------------------------------
-- Supabase Storage buckets used by this HTML: public-images and private case-photos
-- -----------------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values
  ('public-images', 'public-images', true, 8388608, array['image/jpeg','image/png','image/webp','image/gif']),
  ('case-photos', 'case-photos', false, 8388608, array['image/jpeg','image/png','image/webp','image/gif'])
on conflict (id) do update set
  public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

-- Create policies only for the two buckets above; do not make case-photos public.
drop policy if exists "voluhub_public_images_read" on storage.objects;
drop policy if exists "voluhub_public_images_insert_own" on storage.objects;
drop policy if exists "voluhub_public_images_update_own" on storage.objects;
drop policy if exists "voluhub_case_photos_insert_own" on storage.objects;
drop policy if exists "voluhub_case_photos_read_owner_or_admin" on storage.objects;
create policy "voluhub_public_images_read" on storage.objects
for select to anon, authenticated using (bucket_id = 'public-images');
create policy "voluhub_public_images_insert_own" on storage.objects
for insert to authenticated with check (bucket_id = 'public-images' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "voluhub_public_images_update_own" on storage.objects
for update to authenticated using (bucket_id = 'public-images' and (storage.foldername(name))[1] = auth.uid()::text)
with check (bucket_id = 'public-images' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "voluhub_case_photos_insert_own" on storage.objects
for insert to authenticated with check (bucket_id = 'case-photos' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "voluhub_case_photos_read_owner_or_admin" on storage.objects
for select to authenticated using (
  bucket_id = 'case-photos' and (
    (storage.foldername(name))[1] = auth.uid()::text or public.voluhub_current_user_is_admin()
  )
);

-- The functions above validate auth.uid() and role/verification server-side.
-- Review existing permissive legacy RLS policies in Supabase before using this on a live database:
-- PostgreSQL combines permissive policies with OR, so a previous broad policy can override these policies.

-- ----------------------------------------------------------------------------
-- VoluHub targeted fixes: private giveaway claiming and demo-donation ambiguity repair
-- Re-runnable migration section.
-- ----------------------------------------------------------------------------

-- A giveaway becomes reserved when one recipient claims it, and disappears from
-- the public feed immediately. Only the recipient can read the phone via RPC.
alter table public.giveaways add column if not exists claimed_by uuid references auth.users(id) on delete set null;

-- Keep the base table private; public users must read the column-limited view.
-- Drop both the earlier read policy and this target policy so reruns are safe.
drop policy if exists "giveaways_verified_read" on public.giveaways;
drop policy if exists "giveaways_owner_or_admin_read" on public.giveaways;
create policy "giveaways_owner_or_admin_read" on public.giveaways
for select to authenticated using (owner_id = auth.uid() or public.voluhub_current_user_is_admin());
revoke select on public.giveaways from anon;
grant select on public.giveaways to authenticated;

create or replace view public.giveaways_public_feed as
select id, owner_id, title, city, category, images, description, status, created_at
from public.giveaways
where status = 'open';
grant select on public.giveaways_public_feed to anon, authenticated;

create or replace function public.claim_giveaway(p_giveaway_id uuid)
returns table(id uuid, phone text, address text)
language plpgsql security definer
set search_path = public
as $$
declare v_uid uuid := auth.uid();
begin
  if v_uid is null then raise exception 'Алдымен жүйеге кіріңіз.'; end if;
  if not public.voluhub_current_user_is_verified() then raise exception 'Расталған аккаунт қажет.'; end if;
  return query
  update public.giveaways g
     set status = 'reserved', claimed_by = v_uid, updated_at = now()
   where g.id = p_giveaway_id and g.status = 'open' and g.owner_id <> v_uid
  returning g.id, g.phone, g.address;
  if not found then raise exception 'Бұл зат қолжетімсіз немесе басқа адам алып қойған.'; end if;
end;
$$;
revoke all on function public.claim_giveaway(uuid) from public, anon;
grant execute on function public.claim_giveaway(uuid) to authenticated;

create or replace function public.get_my_claimed_giveaways()
returns table(id uuid, owner_id uuid, title text, city text, category text, images text[], description text, status text, phone text, address text)
language sql security definer
set search_path = public
as $$
  select g.id, g.owner_id, g.title, g.city, g.category, g.images, g.description, g.status, g.phone, g.address
  from public.giveaways g
  where g.claimed_by = auth.uid() and g.status = 'reserved';
$$;
revoke all on function public.get_my_claimed_giveaways() from public, anon;
grant execute on function public.get_my_claimed_giveaways() to authenticated;

create or replace function public.complete_giveaway(p_giveaway_id uuid)
returns boolean
language plpgsql security definer
set search_path = public
as $$
declare v_rows integer;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  update public.giveaways g set status = 'closed', updated_at = now()
   where g.id = p_giveaway_id and g.claimed_by = auth.uid() and g.status = 'reserved';
  get diagnostics v_rows = row_count;
  if v_rows = 0 then raise exception 'Бұл зат сізге бекітілмеген немесе бұрын жабылған.'; end if;
  return true;
end;
$$;
revoke all on function public.complete_giveaway(uuid) from public, anon;
grant execute on function public.complete_giveaway(uuid) to authenticated;

-- Rebuild the demo-donation RPC so no OUT parameter named `id` can shadow
-- fundraising_goals.id in ON CONFLICT (id). The UI does not consume row.id;
-- it consumes raised_amount. The result field is therefore named donation_id.
drop function if exists public.create_demo_donation(numeric);
create function public.create_demo_donation(p_amount numeric)
returns table(
  donation_id uuid,
  user_id uuid,
  amount numeric,
  payment_mode text,
  donor_name text,
  donor_email text,
  created_at timestamptz,
  raised_amount numeric
)
language plpgsql security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_donation_id uuid;
  v_raised numeric(14,2);
begin
  if v_uid is null then raise exception 'Алдымен жүйеге кіріңіз.'; end if;
  if not public.voluhub_current_user_is_verified() then raise exception 'Расталған профиль қажет.'; end if;
  if p_amount is null or p_amount < 500 or p_amount > 500000 or p_amount <> trunc(p_amount) then
    raise exception 'Демо сомасы 500–500000 ₸ аралығындағы бүтін сан болуы керек.';
  end if;

  insert into public.fundraising_goals as goal (id, target_amount, raised_amount)
    values (1, 25000000, 0)
    on conflict (id) do nothing;

  -- Lock the single fundraising-goal row so concurrent donations do not overwrite
  -- each other's raised_amount update.
  perform 1
    from public.fundraising_goals as locked_goal
    where locked_goal.id = 1
    for update;

  insert into public.donations as inserted_donation
    (user_id, amount, payment_mode, donor_name, donor_email)
    select v_uid, p_amount, 'demo', profile_row.full_name, auth_user.email
      from auth.users as auth_user
      left join public.profiles as profile_row
        on profile_row.id = auth_user.id
     where auth_user.id = v_uid
    returning inserted_donation.id into v_donation_id;

  if v_donation_id is null then
    raise exception 'Демо донатты сақтау мүмкін болмады.';
  end if;

  update public.fundraising_goals as updated_goal
     set raised_amount = updated_goal.raised_amount + p_amount,
         updated_at = now()
   where updated_goal.id = 1
   returning updated_goal.raised_amount into v_raised;

  return query
    select donation_row.id as donation_id,
           donation_row.user_id,
           donation_row.amount,
           donation_row.payment_mode,
           donation_row.donor_name,
           donation_row.donor_email,
           donation_row.created_at,
           v_raised as raised_amount
      from public.donations as donation_row
     where donation_row.id = v_donation_id;
end;
$$;
revoke all on function public.create_demo_donation(numeric) from public, anon;
grant execute on function public.create_demo_donation(numeric) to authenticated;
notify pgrst, 'reload schema';

-- -----------------------------------------------------------------------------
-- VoluHub v7 targeted fixes: partnership media/contact fields + unambiguous donation RPC
-- Safe to rerun; no existing tables or user data are dropped.
-- -----------------------------------------------------------------------------
alter table public.partners add column if not exists logo_url text;
alter table public.partners add column if not exists image_urls text[] not null default '{}';
alter table public.partnership_requests add column if not exists contact_email text;

-- Refresh grants for the newly added columns, preserving existing RLS rules.
grant select on public.partners to anon, authenticated;
grant insert, update on public.partners to authenticated;
grant select, insert, update on public.partnership_requests to authenticated;


-- ============================================================================
-- VoluHub v8 completion migration
-- Safe/additive additions for admin tools, help assignment deadline, giveaways,
-- fundraising controls and durable historical stats. No application tables are dropped.
-- ============================================================================

-- Attempt to enable pg_cron where the Supabase project supports the extension.
-- Failure is non-fatal; the migration continues and the website also invokes the cleaner.
do $cron_enable$
begin
  if to_regclass('cron.job') is null then
    begin
      execute 'create extension if not exists pg_cron';
    exception when others then
      raise notice 'pg_cron could not be enabled in this project: %', sqlerrm;
    end;
  end if;
end;
$cron_enable$;

begin;

-- 1) Admin delete capabilities are granted at the SQL layer as well as checked by RLS.
grant delete on public.partners to authenticated;
grant delete on public.eco_campaigns to authenticated;

-- 2) Record when a helper accepted the request. Existing assignments are given a
-- conservative start time based on their last update so they do not remain locked forever.
alter table public.help_requests
  add column if not exists helper_assigned_at timestamptz;
update public.help_requests
   set helper_assigned_at = coalesce(updated_at, created_at, now())
 where status = 'in_progress'
   and helper_id is not null
   and helper_assigned_at is null;
create index if not exists help_requests_assignment_timeout_idx
  on public.help_requests(status, helper_assigned_at)
  where status = 'in_progress' and helper_id is not null;

-- Keep the public view limited to non-contact fields while exposing the assignment time
-- needed for the 24-hour client-side warning. This column is appended to preserve the
-- existing view's prior column order.
create or replace view public.help_requests_feed as
select id, requester_id, name, city, category, images, description, urgency,
       vulnerability, status, helper_id, created_at, updated_at, helper_assigned_at
from public.help_requests
where status in ('approved','in_progress','awaiting_verification','completed');
grant select on public.help_requests_feed to anon, authenticated;

create or replace function public.start_help_assignment(p_request_id uuid, p_signature text)
returns boolean
language plpgsql security definer
set search_path = public
as $$
declare
  v_count integer;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if not public.voluhub_current_user_is_verified() then raise exception 'Verified profile required'; end if;
  if p_signature is null or length(btrim(p_signature)) < 3 then raise exception 'A full-name signature is required'; end if;
  if not exists (
    select 1 from public.privacy_consents as consent_row
    where consent_row.request_id = p_request_id and consent_row.user_id = auth.uid()
  ) then
    raise exception 'Privacy consent is required';
  end if;

  update public.help_requests as help_row
     set helper_id = auth.uid(),
         helper_signature = btrim(p_signature),
         helper_assigned_at = now(),
         status = 'in_progress',
         updated_at = now()
   where help_row.id = p_request_id
     and help_row.status = 'approved'
     and help_row.helper_id is null;
  get diagnostics v_count = row_count;
  return v_count = 1;
end;
$$;

create or replace function public.release_expired_help_assignments()
returns integer
language plpgsql security definer
set search_path = public
as $$
declare
  v_count integer;
begin
  update public.help_requests as help_row
     set status = 'approved',
         helper_id = null,
         helper_signature = null,
         helper_assigned_at = null,
         updated_at = now()
   where help_row.status = 'in_progress'
     and help_row.helper_id is not null
     and help_row.helper_assigned_at is not null
     and help_row.helper_assigned_at <= now() - interval '24 hours';
  get diagnostics v_count = row_count;
  return v_count;
end;
$$;
revoke all on function public.release_expired_help_assignments() from public, anon;
grant execute on function public.release_expired_help_assignments() to authenticated;

create or replace function public.submit_help_report(p_request_id uuid, p_description text, p_image_paths text[])
returns uuid
language plpgsql security definer
set search_path = public
as $$
declare
  v_report_id uuid;
  v_count integer;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if p_description is null or length(btrim(p_description)) < 3 then raise exception 'Report description is required'; end if;
  if p_image_paths is null or cardinality(p_image_paths) < 1 then raise exception 'At least one report image is required'; end if;

  update public.help_requests as help_row
     set status = 'awaiting_verification', updated_at = now()
   where help_row.id = p_request_id
     and help_row.helper_id = auth.uid()
     and help_row.status = 'in_progress'
     and help_row.helper_assigned_at >= now() - interval '24 hours';
  get diagnostics v_count = row_count;
  if v_count <> 1 then
    raise exception 'The 24-hour report window has expired or this request is not assigned to you. Refresh the page; expired requests are made public again.';
  end if;

  insert into public.help_reports(request_id, helper_id, description, images, status)
  values (p_request_id, auth.uid(), btrim(p_description), p_image_paths, 'pending')
  returning id into v_report_id;
  return v_report_id;
end;
$$;

create or replace function public.review_help_report(p_report_id uuid, p_approve boolean, p_note text default null)
returns void
language plpgsql security definer
set search_path = public
as $$
declare
  v_request_id uuid;
begin
  if auth.uid() is null or not public.voluhub_current_user_is_admin() then
    raise exception 'Administrator permission required';
  end if;
  if p_approve is null then raise exception 'Report decision is required'; end if;
  select report_row.request_id into v_request_id
    from public.help_reports as report_row
   where report_row.id = p_report_id and report_row.status = 'pending';
  if v_request_id is null then raise exception 'Pending report not found'; end if;

  update public.help_reports as report_row
     set status = case when p_approve then 'approved' else 'revision_requested' end,
         reviewed_by = auth.uid(),
         review_note = p_note,
         reviewed_at = now()
   where report_row.id = p_report_id and report_row.status = 'pending';

  -- If the administrator decides the promised help was not delivered, release
  -- the request and remove the assignment so another volunteer can accept it.
  update public.help_requests as help_row
     set status = case when p_approve then 'completed' else 'approved' end,
         helper_id = case when p_approve then help_row.helper_id else null end,
         helper_signature = case when p_approve then help_row.helper_signature else null end,
         helper_assigned_at = case when p_approve then help_row.helper_assigned_at else null end,
         updated_at = now()
   where help_row.id = v_request_id;
end;
$$;
revoke all on function public.start_help_assignment(uuid, text) from public, anon;
revoke all on function public.submit_help_report(uuid, text, text[]) from public, anon;
revoke all on function public.review_help_report(uuid, boolean, text) from public, anon;
grant execute on function public.start_help_assignment(uuid, text) to authenticated;
grant execute on function public.submit_help_report(uuid, text, text[]) to authenticated;
grant execute on function public.review_help_report(uuid, boolean, text) to authenticated;

-- If pg_cron is enabled in this Supabase project, run the deadline cleaner every 15 minutes.
-- When pg_cron is unavailable, the client also invokes the same restricted RPC on page loads.
do $schedule$
declare
  v_job record;
begin
  if to_regclass('cron.job') is not null then
    for v_job in execute 'select jobid from cron.job where jobname = $1' using 'voluhub-help-assignment-timeout'
    loop
      execute 'select cron.unschedule($1)' using v_job.jobid;
    end loop;
    execute $q$select cron.schedule('voluhub-help-assignment-timeout', '*/15 * * * *', 'select public.release_expired_help_assignments();')$q$;
  end if;
exception when others then
  raise notice 'Could not schedule pg_cron deadline cleanup; on-visit cleanup remains available: %', sqlerrm;
end;
$schedule$;

-- 3) Giveaway signature and return-to-public flow.
alter table public.giveaways add column if not exists claimed_by uuid references auth.users(id) on delete set null;
alter table public.giveaways add column if not exists claimer_signature text;
alter table public.giveaways add column if not exists claimed_at timestamptz;

drop function if exists public.claim_giveaway(uuid, text);
drop function if exists public.claim_giveaway(uuid);
create function public.claim_giveaway(p_giveaway_id uuid, p_signature text)
returns table(giveaway_id uuid, phone text, address text)
language plpgsql security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_giveaway_id uuid;
  v_phone text;
  v_address text;
begin
  if v_uid is null then raise exception 'Алдымен жүйеге кіріңіз.'; end if;
  if not public.voluhub_current_user_is_verified() then raise exception 'Расталған аккаунт қажет.'; end if;
  if p_signature is null or length(btrim(p_signature)) < 3 then
    raise exception 'Затты алу үшін толық аты-жөні қолтаңба ретінде қажет.';
  end if;

  update public.giveaways as giveaway_row
     set status = 'reserved',
         claimed_by = v_uid,
         claimer_signature = btrim(p_signature),
         claimed_at = now(),
         updated_at = now()
   where giveaway_row.id = p_giveaway_id
     and giveaway_row.status = 'open'
     and giveaway_row.owner_id <> v_uid
  returning giveaway_row.id, giveaway_row.phone, giveaway_row.address
       into v_giveaway_id, v_phone, v_address;
  if not found then raise exception 'Бұл зат қолжетімсіз немесе басқа адам алып қойған.'; end if;
  return query select v_giveaway_id, v_phone, v_address;
end;
$$;
revoke all on function public.claim_giveaway(uuid, text) from public, anon;
grant execute on function public.claim_giveaway(uuid, text) to authenticated;

create or replace function public.complete_giveaway(p_giveaway_id uuid)
returns boolean
language plpgsql security definer
set search_path = public
as $$
declare
  v_count integer;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  update public.giveaways as giveaway_row
     set status = 'closed', updated_at = now()
   where giveaway_row.id = p_giveaway_id
     and giveaway_row.claimed_by = auth.uid()
     and giveaway_row.status = 'reserved';
  get diagnostics v_count = row_count;
  if v_count = 0 then raise exception 'Бұл зат сізге бекітілмеген немесе бұрын жабылған.'; end if;
  return true;
end;
$$;
revoke all on function public.complete_giveaway(uuid) from public, anon;
grant execute on function public.complete_giveaway(uuid) to authenticated;

create or replace function public.release_giveaway(p_giveaway_id uuid)
returns boolean
language plpgsql security definer
set search_path = public
as $$
declare
  v_count integer;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  update public.giveaways as giveaway_row
     set status = 'open',
         claimed_by = null,
         claimer_signature = null,
         claimed_at = null,
         updated_at = now()
   where giveaway_row.id = p_giveaway_id
     and giveaway_row.claimed_by = auth.uid()
     and giveaway_row.status = 'reserved';
  get diagnostics v_count = row_count;
  if v_count = 0 then raise exception 'Бұл зат сізге бекітілмеген немесе бұрын жабылған.'; end if;
  return true;
end;
$$;
revoke all on function public.release_giveaway(uuid) from public, anon;
grant execute on function public.release_giveaway(uuid) to authenticated;

-- 4) Fundraising goal admin settings. The UI has no direct write access to this table.
alter table public.fundraising_goals
  add column if not exists donations_enabled boolean not null default true;
insert into public.fundraising_goals(id, target_amount, raised_amount, donations_enabled)
values (1, 25000000, 0, true)
on conflict (id) do nothing;

create or replace function public.admin_update_fundraising_goal(
  p_target_amount numeric,
  p_donations_enabled boolean,
  p_reset_raised boolean default false
)
returns table(target_amount numeric, raised_amount numeric, donations_enabled boolean)
language plpgsql security definer
set search_path = public
as $$
declare
  v_target numeric(14,2);
  v_raised numeric(14,2);
  v_enabled boolean;
begin
  if auth.uid() is null or not public.voluhub_current_user_is_admin() then
    raise exception 'Administrator permission required';
  end if;
  if p_target_amount is null or p_target_amount < 0 or p_target_amount > 100000000000 then
    raise exception 'Target amount must be between 0 and 100000000000';
  end if;
  if p_donations_enabled is null then raise exception 'Donation status is required'; end if;

  insert into public.fundraising_goals as goal_row(id, target_amount, raised_amount, donations_enabled)
  values (1, p_target_amount, 0, p_donations_enabled)
  on conflict (id) do nothing;

  update public.fundraising_goals as goal_row
     set target_amount = p_target_amount,
         donations_enabled = p_donations_enabled,
         raised_amount = case when coalesce(p_reset_raised, false) then 0 else goal_row.raised_amount end,
         updated_at = now()
   where goal_row.id = 1
   returning goal_row.target_amount, goal_row.raised_amount, goal_row.donations_enabled
        into v_target, v_raised, v_enabled;
  return query select v_target, v_raised, v_enabled;
end;
$$;
revoke all on function public.admin_update_fundraising_goal(numeric, boolean, boolean) from public, anon;
grant execute on function public.admin_update_fundraising_goal(numeric, boolean, boolean) to authenticated;

-- Donations are checked server-side too: disabling fundraising cannot be bypassed
-- by calling the RPC manually or with a stale browser tab.
create or replace function public.create_demo_donation(p_amount numeric)
returns table(
  donation_id uuid,
  user_id uuid,
  amount numeric,
  payment_mode text,
  donor_name text,
  donor_email text,
  created_at timestamptz,
  raised_amount numeric
)
language plpgsql security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_donation_id uuid;
  v_raised numeric(14,2);
  v_enabled boolean;
begin
  if v_uid is null then raise exception 'Алдымен жүйеге кіріңіз.'; end if;
  if not public.voluhub_current_user_is_verified() then raise exception 'Расталған профиль қажет.'; end if;
  if p_amount is null or p_amount < 500 or p_amount > 500000 or p_amount <> trunc(p_amount) then
    raise exception 'Демо сомасы 500–500000 ₸ аралығындағы бүтін сан болуы керек.';
  end if;

  insert into public.fundraising_goals as seed_goal(id, target_amount, raised_amount, donations_enabled)
  values (1, 25000000, 0, true)
  on conflict (id) do nothing;

  select goal_row.donations_enabled into v_enabled
    from public.fundraising_goals as goal_row
   where goal_row.id = 1
   for update;
  if coalesce(v_enabled, true) = false then raise exception 'Қаражат жинау уақытша жабық.'; end if;

  insert into public.donations as inserted_donation(user_id, amount, payment_mode, donor_name, donor_email)
  select v_uid, p_amount, 'demo', profile_row.full_name, auth_user.email
    from auth.users as auth_user
    left join public.profiles as profile_row on profile_row.id = auth_user.id
   where auth_user.id = v_uid
  returning inserted_donation.id into v_donation_id;
  if v_donation_id is null then raise exception 'Демо донатты сақтау мүмкін болмады.'; end if;

  update public.fundraising_goals as goal_row
     set raised_amount = goal_row.raised_amount + p_amount,
         updated_at = now()
   where goal_row.id = 1
   returning goal_row.raised_amount into v_raised;

  return query
  select donation_row.id, donation_row.user_id, donation_row.amount,
         donation_row.payment_mode, donation_row.donor_name, donation_row.donor_email,
         donation_row.created_at, v_raised
    from public.donations as donation_row
   where donation_row.id = v_donation_id;
end;
$$;
revoke all on function public.create_demo_donation(numeric) from public, anon;
grant execute on function public.create_demo_donation(numeric) to authenticated;

-- 5) Durable historical event log. Existing rows are backfilled once, and future
-- inserts are recorded by triggers. The log contains only IDs/date/amount, not names,
-- phone numbers, emails, addresses or report contents. Deletes do not erase history.
create table if not exists public.voluhub_stats_events (
  id bigint generated by default as identity primary key,
  source_table text not null check (source_table in (
    'auth.users', 'public.help_requests', 'public.giveaways', 'public.donations',
    'public.partners', 'public.eco_campaigns'
  )),
  source_id text not null,
  event_date date not null,
  amount numeric(14,2) not null default 0 check (amount >= 0),
  recorded_at timestamptz not null default now(),
  unique(source_table, source_id)
);
create index if not exists voluhub_stats_events_date_idx on public.voluhub_stats_events(event_date, source_table);
alter table public.voluhub_stats_events enable row level security;
revoke all on public.voluhub_stats_events from public, anon, authenticated;

create or replace function public.voluhub_capture_stats_event()
returns trigger
language plpgsql security definer
set search_path = public
as $$
declare
  v_row jsonb := to_jsonb(new);
  v_id text;
  v_event_date date;
  v_amount numeric(14,2) := 0;
  v_source text := tg_table_schema || '.' || tg_table_name;
begin
  v_id := v_row ->> 'id';
  if v_id is null then return new; end if;
  v_event_date := coalesce(nullif(v_row ->> 'created_at', '')::timestamptz::date, current_date);
  if tg_table_name = 'donations' then
    v_amount := coalesce(nullif(v_row ->> 'amount', '')::numeric, 0);
  end if;
  insert into public.voluhub_stats_events(source_table, source_id, event_date, amount)
  values (v_source, v_id, v_event_date, v_amount)
  on conflict (source_table, source_id) do nothing;
  return new;
end;
$$;
revoke all on function public.voluhub_capture_stats_event() from public, anon, authenticated;

-- Log events created after this migration. Triggers are safe to recreate.
drop trigger if exists voluhub_stats_capture_user on auth.users;
create trigger voluhub_stats_capture_user after insert on auth.users
for each row execute function public.voluhub_capture_stats_event();
drop trigger if exists voluhub_stats_capture_help_request on public.help_requests;
create trigger voluhub_stats_capture_help_request after insert on public.help_requests
for each row execute function public.voluhub_capture_stats_event();
drop trigger if exists voluhub_stats_capture_giveaway on public.giveaways;
create trigger voluhub_stats_capture_giveaway after insert on public.giveaways
for each row execute function public.voluhub_capture_stats_event();
drop trigger if exists voluhub_stats_capture_donation on public.donations;
create trigger voluhub_stats_capture_donation after insert on public.donations
for each row execute function public.voluhub_capture_stats_event();
drop trigger if exists voluhub_stats_capture_partner on public.partners;
create trigger voluhub_stats_capture_partner after insert on public.partners
for each row execute function public.voluhub_capture_stats_event();
drop trigger if exists voluhub_stats_capture_eco on public.eco_campaigns;
create trigger voluhub_stats_capture_eco after insert on public.eco_campaigns
for each row execute function public.voluhub_capture_stats_event();

-- Initial history from existing rows is preserved even if a partner or eco program is deleted later.
insert into public.voluhub_stats_events(source_table, source_id, event_date, amount)
select 'auth.users', u.id::text, coalesce(u.created_at, now())::date, 0 from auth.users as u
on conflict (source_table, source_id) do nothing;
insert into public.voluhub_stats_events(source_table, source_id, event_date, amount)
select 'public.help_requests', h.id::text, coalesce(h.created_at, now())::date, 0 from public.help_requests as h
on conflict (source_table, source_id) do nothing;
insert into public.voluhub_stats_events(source_table, source_id, event_date, amount)
select 'public.giveaways', g.id::text, coalesce(g.created_at, now())::date, 0 from public.giveaways as g
on conflict (source_table, source_id) do nothing;
insert into public.voluhub_stats_events(source_table, source_id, event_date, amount)
select 'public.donations', d.id::text, coalesce(d.created_at, now())::date, coalesce(d.amount, 0) from public.donations as d
on conflict (source_table, source_id) do nothing;
insert into public.voluhub_stats_events(source_table, source_id, event_date, amount)
select 'public.partners', p.id::text, coalesce(p.created_at, now())::date, 0 from public.partners as p
on conflict (source_table, source_id) do nothing;
insert into public.voluhub_stats_events(source_table, source_id, event_date, amount)
select 'public.eco_campaigns', e.id::text, coalesce(e.created_at, now())::date, 0 from public.eco_campaigns as e
on conflict (source_table, source_id) do nothing;

create or replace function public.get_admin_stats_history()
returns table(
  stat_date date,
  users_created bigint,
  help_requests_created bigint,
  giveaways_created bigint,
  donations_count bigint,
  donations_amount numeric,
  partners_created bigint,
  eco_programs_created bigint
)
language sql stable security definer
set search_path = public
as $$
  with first_event as (
    select coalesce(min(e.event_date), current_date) as first_date
      from public.voluhub_stats_events as e
  ), calendar as (
    select generate_series(first_event.first_date, current_date, interval '1 day')::date as stat_date
      from first_event
  ), daily as (
    select e.event_date as stat_date,
           count(*) filter (where e.source_table = 'auth.users')::bigint as users_created,
           count(*) filter (where e.source_table = 'public.help_requests')::bigint as help_requests_created,
           count(*) filter (where e.source_table = 'public.giveaways')::bigint as giveaways_created,
           count(*) filter (where e.source_table = 'public.donations')::bigint as donations_count,
           coalesce(sum(e.amount) filter (where e.source_table = 'public.donations'), 0)::numeric as donations_amount,
           count(*) filter (where e.source_table = 'public.partners')::bigint as partners_created,
           count(*) filter (where e.source_table = 'public.eco_campaigns')::bigint as eco_programs_created
      from public.voluhub_stats_events as e
     group by e.event_date
  )
  select calendar.stat_date,
         coalesce(daily.users_created, 0)::bigint,
         coalesce(daily.help_requests_created, 0)::bigint,
         coalesce(daily.giveaways_created, 0)::bigint,
         coalesce(daily.donations_count, 0)::bigint,
         coalesce(daily.donations_amount, 0)::numeric,
         coalesce(daily.partners_created, 0)::bigint,
         coalesce(daily.eco_programs_created, 0)::bigint
    from calendar
    left join daily on daily.stat_date = calendar.stat_date
   where public.voluhub_current_user_is_admin()
   order by calendar.stat_date;
$$;
revoke all on function public.get_admin_stats_history() from public, anon;
grant execute on function public.get_admin_stats_history() to authenticated;


-- -----------------------------------------------------------------------------
-- VoluHub review access note (v8)
-- No additional schema change is required for the expanded administrator detail
-- dialogs in the companion HTML: the policies above already grant administrators
-- access to full help_requests, profiles, help_reports, and private case-photos.
-- These remain administrator-only; public feeds continue to omit private address
-- and phone fields. Profile review remains a manual platform decision; this migration does not add
-- automated facial matching or identity checks.
-- -----------------------------------------------------------------------------

commit;
notify pgrst, 'reload schema';
