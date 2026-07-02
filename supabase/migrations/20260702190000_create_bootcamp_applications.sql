-- Bootcamp admission requests. Personal data is accessible only to the applicant
-- through RLS; administrators should review it from the Supabase dashboard.
create table if not exists public.bootcamp_applications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  first_name text not null check (char_length(first_name) between 2 and 80),
  last_name text not null check (char_length(last_name) between 2 and 120),
  phone text not null check (phone ~ '^\+989[0-9]{9}$'),
  resume_path text,
  status text not null default 'pending' check (status in ('pending', 'contacted', 'accepted', 'rejected')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (user_id)
);

alter table public.bootcamp_applications enable row level security;
revoke all on public.bootcamp_applications from anon;
grant insert, select, update on public.bootcamp_applications to authenticated;

drop policy if exists "Applicants can create their request" on public.bootcamp_applications;
create policy "Applicants can create their request"
on public.bootcamp_applications for insert to authenticated
with check (auth.uid() = user_id);

drop policy if exists "Applicants can view their request" on public.bootcamp_applications;
create policy "Applicants can view their request"
on public.bootcamp_applications for select to authenticated
using (auth.uid() = user_id);

drop policy if exists "Applicants can update their pending request" on public.bootcamp_applications;
create policy "Applicants can update their pending request"
on public.bootcamp_applications for update to authenticated
using (auth.uid() = user_id and status = 'pending')
with check (auth.uid() = user_id and status = 'pending');

-- Private PDF bucket. Paths begin with the authenticated user's UUID.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('bootcamp-resumes', 'bootcamp-resumes', false, 52428800, array['application/pdf'])
on conflict (id) do update set
  public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "Applicants can upload their resume" on storage.objects;
create policy "Applicants can upload their resume"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'bootcamp-resumes'
  and (storage.foldername(name))[1] = auth.uid()::text
);

drop policy if exists "Applicants can replace their resume" on storage.objects;
create policy "Applicants can replace their resume"
on storage.objects for update to authenticated
using (
  bucket_id = 'bootcamp-resumes'
  and (storage.foldername(name))[1] = auth.uid()::text
)
with check (
  bucket_id = 'bootcamp-resumes'
  and (storage.foldername(name))[1] = auth.uid()::text
);
