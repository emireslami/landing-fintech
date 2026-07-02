-- Applications can be submitted without OTP. Anonymous visitors may only create
-- records and upload private resumes; they cannot read or modify either resource.
alter table public.bootcamp_applications
  alter column user_id drop not null;

revoke all on public.bootcamp_applications from anon;
grant insert on public.bootcamp_applications to anon;

drop policy if exists "Visitors can submit an application" on public.bootcamp_applications;
create policy "Visitors can submit an application"
on public.bootcamp_applications for insert to anon
with check (
  user_id is null
  and status = 'pending'
  and phone ~ '^\+989[0-9]{9}$'
);

drop policy if exists "Visitors can upload a private resume" on storage.objects;
create policy "Visitors can upload a private resume"
on storage.objects for insert to anon
with check (
  bucket_id = 'bootcamp-resumes'
  and (storage.foldername(name))[1] = 'applications'
  and lower(storage.extension(name)) = 'pdf'
);
