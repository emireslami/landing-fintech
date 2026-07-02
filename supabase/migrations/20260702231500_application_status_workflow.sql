-- Five-step admission workflow shared by the management dashboard and the
-- privacy-preserving public status lookup.
alter table public.bootcamp_applications
  drop constraint if exists bootcamp_applications_status_check;

update public.bootcamp_applications set status = case status
  when 'pending' then 'unreviewed'
  when 'contacted' then 'initial_contact'
  when 'accepted' then 'awaiting_payment'
  when 'rejected' then 'unreviewed'
  else status
end;

alter table public.bootcamp_applications
  alter column status set default 'unreviewed';

alter table public.bootcamp_applications
  add constraint bootcamp_applications_status_check check (
    status in ('unreviewed', 'initial_contact', 'awaiting_payment', 'scheduled', 'attended')
  );

drop policy if exists "Visitors can submit an application" on public.bootcamp_applications;
create policy "Visitors can submit an application"
on public.bootcamp_applications for insert to anon
with check (
  user_id is null
  and status = 'unreviewed'
  and phone ~ '^\+989[0-9]{9}$'
);

create table if not exists public.application_status_rate_limits (
  lookup_key text primary key,
  window_started_at timestamptz not null default now(),
  attempts integer not null default 1
);

alter table public.application_status_rate_limits enable row level security;
revoke all on public.application_status_rate_limits from anon, authenticated;

create or replace function public.lookup_application_status(p_phone text, p_lookup_key text)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  current_attempts integer;
  current_status text;
begin
  insert into public.application_status_rate_limits as limits (lookup_key, window_started_at, attempts)
  values (p_lookup_key, now(), 1)
  on conflict (lookup_key) do update set
    attempts = case
      when limits.window_started_at < now() - interval '15 minutes' then 1
      else limits.attempts + 1
    end,
    window_started_at = case
      when limits.window_started_at < now() - interval '15 minutes' then now()
      else limits.window_started_at
    end
  returning attempts into current_attempts;

  if current_attempts > 10 then
    raise exception 'rate_limit' using errcode = 'P0001';
  end if;

  select applications.status into current_status
  from public.bootcamp_applications as applications
  where applications.phone = p_phone
  order by applications.created_at desc
  limit 1;

  return current_status;
end;
$$;

revoke all on function public.lookup_application_status(text, text) from public, anon, authenticated;
grant execute on function public.lookup_application_status(text, text) to service_role;
