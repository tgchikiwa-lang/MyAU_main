create or replace function public.au_request_alumni_access(
  p_student_number text,
  p_university_email text,
  p_personal_email text
) returns void
language plpgsql security definer
set search_path = public, pg_temp
as $$
declare
  target_id uuid;
  match_count integer;
  v_student_number text := btrim(coalesce(p_student_number, ''));
  v_university_email text := lower(btrim(coalesce(p_university_email, '')));
  v_personal_email text := lower(btrim(coalesce(p_personal_email, '')));
begin
  if char_length(v_student_number) not between 1 and 40
     or char_length(v_university_email) not between 3 and 200
     or char_length(v_personal_email) not between 3 and 200
     or position('@' in v_university_email) < 2
     or position('@' in v_personal_email) < 2
     or v_university_email = v_personal_email then
    raise exception 'Enter your student number, current university email, and a different personal email.';
  end if;

  select count(*), (array_agg(r.student_id))[1] into match_count, target_id
    from public.student_registry r
    join auth.users u on u.id = r.student_id
   where r.student_number = v_student_number
     and lower(u.email) = v_university_email;
  if match_count <> 1 then target_id := null; end if;

  if exists (
    select 1 from public.alumni_access_requests r
     where r.created_at > now() - interval '24 hours'
       and lower(r.student_number) = lower(v_student_number)
       and lower(r.university_email) = v_university_email
  ) or (target_id is not null and exists (
    select 1 from public.alumni_access_requests r
     where r.student_id = target_id
       and r.status in ('pending', 'awaiting_confirmation')
  )) then
    return;
  end if;

  insert into public.alumni_access_requests(
    student_id, student_number, university_email, personal_email
  ) values (
    target_id, v_student_number, v_university_email, v_personal_email
  );
exception when unique_violation then
  return;
end $$;

revoke all on function public.au_request_alumni_access(text, text, text) from public;
grant execute on function public.au_request_alumni_access(text, text, text) to anon, authenticated;
