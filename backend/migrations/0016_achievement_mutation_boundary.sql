-- Additive, transactional achievement writes shared by MyAU and IADS.
-- This migration intentionally does not alter existing MyAU tables, policies,
-- constraints, triggers, recommendation logic, or global default privileges.

do $preflight$
declare
  v_index text;
  v_constraint_count integer;
  v_trigger_count integer;
begin
  if to_regclass('public.achievement_mutation_keys') is not null
     or to_regprocedure('public.au_achievement_hash(jsonb)') is not null
     or to_regprocedure('public.au_save_profile_data(jsonb,timestamptz)') is not null
     or to_regprocedure('public.au_commit_achievement(uuid,text,uuid,jsonb,text)') is not null
     or to_regprocedure('public.au_submit_manual_achievement(uuid,jsonb)') is not null
     or to_regprocedure('public.au_request_achievement_verification(uuid,uuid)') is not null then
    raise exception 'IADS preflight failed: a reserved achievement-boundary object already exists; inspect it before proceeding.';
  end if;
  if to_regclass('public.profiles') is null
     or to_regclass('public.verifications') is null then
    raise exception 'IADS preflight failed: public.profiles and public.verifications must exist.';
  end if;
  if not exists (
    select 1 from information_schema.columns
     where table_schema = 'public' and table_name = 'profiles'
       and column_name = 'id' and data_type = 'uuid'
  ) or not exists (
    select 1 from information_schema.columns
     where table_schema = 'public' and table_name = 'profiles'
       and column_name = 'data' and data_type = 'jsonb'
  ) or not exists (
    select 1 from information_schema.columns
     where table_schema = 'public' and table_name = 'profiles'
       and column_name = 'updated_at' and data_type = 'timestamp with time zone'
  ) then
    raise exception 'IADS preflight failed: public.profiles has an incompatible deployed definition.';
  end if;
  if (
    select count(*) from information_schema.columns
     where table_schema = 'public' and table_name = 'verifications'
       and (column_name, data_type) in (
         ('id','uuid'), ('student_id','uuid'), ('student_name','text'),
         ('student_number','text'), ('item_type','text'), ('item_id','text'),
         ('item_title','text'), ('item_snapshot','jsonb'), ('item_hash','text'),
         ('evidence','ARRAY'), ('status','text')
       )
  ) <> 11 then
    raise exception 'IADS preflight failed: public.verifications has an incompatible deployed definition.';
  end if;
  if not exists (
    select 1 from pg_constraint c
    join pg_class t on t.oid = c.conrelid
    join pg_namespace n on n.oid = t.relnamespace
    where n.nspname = 'public' and t.relname = 'verifications'
      and c.contype = 'p' and pg_get_constraintdef(c.oid) ilike '%(id)%'
  ) then
    raise exception 'IADS preflight failed: verifications primary key is missing or incompatible.';
  end if;
  select pg_get_indexdef(to_regclass('public.verifications_open_uq')) into v_index;
  if v_index is null or v_index not ilike '%student_id, item_type, item_id, item_hash%'
     or v_index not ilike '%pending%' or v_index not ilike '%verified%' then
    raise exception 'IADS preflight failed: verifications_open_uq is missing or incompatible.';
  end if;
  select count(*) into v_constraint_count
    from pg_constraint c
    join pg_class t on t.oid = c.conrelid
    join pg_namespace n on n.oid = t.relnamespace
   where n.nspname = 'public' and t.relname = 'verifications'
     and c.contype = 'c'
     and (
       (pg_get_constraintdef(c.oid) ilike '%item_type%' and pg_get_constraintdef(c.oid) ilike '%achievement%')
       or (pg_get_constraintdef(c.oid) ilike '%status%' and pg_get_constraintdef(c.oid) ilike '%pending%'
           and pg_get_constraintdef(c.oid) ilike '%verified%' and pg_get_constraintdef(c.oid) ilike '%rejected%')
       or (pg_get_constraintdef(c.oid) ilike '%item_hash%' and pg_get_constraintdef(c.oid) ilike '%64%')
       or (pg_get_constraintdef(c.oid) ilike '%student_name%' and pg_get_constraintdef(c.oid) ilike '%120%')
       or (pg_get_constraintdef(c.oid) ilike '%student_number%' and pg_get_constraintdef(c.oid) ilike '%40%')
     );
  if v_constraint_count < 5 then
    raise exception 'IADS preflight failed: deployed verification checks differ from the expected MyAU contract.';
  end if;
  if not (select relrowsecurity from pg_class where oid = 'public.profiles'::regclass)
     or not (select relrowsecurity from pg_class where oid = 'public.verifications'::regclass) then
    raise exception 'IADS preflight failed: profile and verification RLS must remain enabled.';
  end if;
  if not exists (
    select 1 from pg_policies
     where schemaname = 'public' and tablename = 'profiles'
       and cmd in ('UPDATE','ALL') and 'authenticated' = any(roles)
       and coalesce(qual,'') ilike '%auth.uid%'
       and coalesce(with_check,qual,'') ilike '%auth.uid%'
  ) or not exists (
    select 1 from pg_policies
     where schemaname = 'public' and tablename = 'verifications'
       and cmd = 'INSERT' and 'authenticated' = any(roles)
       and coalesce(with_check,'') ilike '%auth.uid%'
       and coalesce(with_check,'') ilike '%pending%'
  ) then
    raise exception 'IADS preflight failed: existing owner-scoped profile or pending verification RLS policy is missing.';
  end if;
  select count(*) into v_trigger_count
    from pg_trigger tr
    join pg_class t on t.oid = tr.tgrelid
    join pg_namespace n on n.oid = t.relnamespace
   where n.nspname = 'public' and not tr.tgisinternal
     and tr.tgenabled <> 'D'
     and ((t.relname = 'profiles' and tr.tgname in (
              'au_guard_achievement_category',
              'au_guard_verified_profile_items',
              'au_log_achievement_history'))
       or (t.relname = 'verifications' and tr.tgname = 'au_verifications_guard'));
  if v_trigger_count <> 4 then
    raise exception 'IADS preflight failed: required profile or verification protection triggers are missing or disabled.';
  end if;
  if to_regprocedure('public.au_can_verify(uuid,text)') is null
     or to_regprocedure('public.au_is_staff()') is null
     or to_regprocedure('public.au_mfa_verified()') is null then
    raise exception 'IADS preflight failed: existing verification and MFA authorization functions are required.';
  end if;
  if not exists (
    select 1 from pg_proc p
     where p.oid = to_regprocedure('public.au_mfa_verified()')
       and p.prorettype = 'boolean'::regtype
       and not p.prosecdef
  ) then
    raise exception 'IADS preflight failed: public.au_mfa_verified() must be a SECURITY INVOKER boolean function.';
  end if;
  if (select prosecdef from pg_proc where oid = to_regprocedure('public.au_can_verify(uuid,text)'))
     or (select prosecdef from pg_proc where oid = to_regprocedure('public.au_is_staff()')) then
    raise exception 'IADS preflight failed: existing authorization helpers must remain SECURITY INVOKER.';
  end if;
  if (
       position('au_mfa_verified' in lower(pg_get_functiondef(to_regprocedure('public.au_is_staff()')))) = 0
       and (
         to_regprocedure('public.au_role()') is null
         or position('au_mfa_verified' in lower(pg_get_functiondef(to_regprocedure('public.au_role()')))) = 0
       )
     )
     or position('verifier_assignments' in lower(pg_get_functiondef(to_regprocedure('public.au_can_verify(uuid,text)')))) = 0 then
    raise exception 'IADS preflight failed: existing staff MFA or scoped verifier behavior differs from the expected definition.';
  end if;
  if not has_function_privilege('authenticated', to_regprocedure('public.au_can_verify(uuid,text)'), 'EXECUTE') then
    raise exception 'IADS preflight failed: authenticated users cannot execute au_can_verify.';
  end if;
  if not has_function_privilege('authenticated', to_regprocedure('public.au_mfa_verified()'), 'EXECUTE') then
    raise exception 'IADS preflight failed: authenticated users cannot execute the existing MFA helper.';
  end if;
  if to_regprocedure('extensions.hmac(bytea,bytea,text)') is null then
    raise exception 'IADS preflight failed: extensions.hmac(bytea,bytea,text) is unavailable.';
  end if;
  if exists (select 1 from pg_roles where rolname = 'iads_receipt_owner') then
    raise exception 'IADS preflight failed: reserved role iads_receipt_owner already exists; inspect it before proceeding.';
  end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then
    raise exception 'IADS preflight failed: service_role is missing.';
  end if;
  if exists (
    select 1 from pg_roles where rolname = 'service_role'
      and (rolsuper or rolcreaterole)
  ) then
    raise exception 'IADS preflight failed: service_role is a superuser or can administer roles and cannot be isolated from the HMAC key.';
  end if;
end
$preflight$;

do $role$
begin
  create role iads_receipt_owner
    nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls;
end
$role$;

create table public.achievement_mutation_keys (
  student_id uuid not null references auth.users(id) on delete cascade,
  source text not null check (source in ('manual_add', 'manual_verify', 'iads')),
  request_id uuid not null,
  request_fingerprint text not null check (request_fingerprint ~ '^[0-9a-f]{64}$'),
  result jsonb not null,
  created_at timestamptz not null default now(),
  primary key (student_id, source, request_id)
);
alter table public.achievement_mutation_keys enable row level security;
revoke all on table public.achievement_mutation_keys from public, anon, authenticated, service_role;

create or replace function public.au_achievement_hash(p_achievement jsonb)
returns text
language plpgsql
immutable
strict
set search_path = pg_catalog
as $function$
declare
  v_json text;
begin
  if jsonb_typeof(p_achievement) is distinct from 'object' then
    raise exception 'Achievement must be an object.';
  end if;
  v_json := '["achievement",'
    || to_json(coalesce(p_achievement ->> 'title', ''))::text || ','
    || to_json(coalesce(p_achievement ->> 'category', ''))::text || ','
    || to_json(coalesce(p_achievement ->> 'date', ''))::text || ','
    || to_json(coalesce(p_achievement ->> 'issuer', ''))::text || ','
    || to_json(coalesce(p_achievement ->> 'description', ''))::text || ']';
  return encode(extensions.digest(convert_to(v_json, 'UTF8'), 'sha256'), 'hex');
end
$function$;
revoke all on function public.au_achievement_hash(jsonb) from public, anon, authenticated, service_role;

create or replace function public.au_save_profile_data(
  p_data jsonb,
  p_expected_updated_at timestamptz
) returns timestamptz
language plpgsql
security invoker
set search_path = pg_catalog
as $function$
declare
  v_student_id uuid := auth.uid();
  v_updated_at timestamptz;
begin
  if v_student_id is null or p_data is null or jsonb_typeof(p_data) <> 'object' then
    raise exception 'A signed-in student and valid profile data are required.';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_student_id::text, 0));
  select p.updated_at into v_updated_at
    from public.profiles p where p.id = v_student_id for update;
  if not found then raise exception 'Student profile not found.'; end if;
  if v_updated_at is distinct from p_expected_updated_at then
    raise exception using errcode = '40001',
      message = 'Your profile changed in another session. Reload the page and retry.';
  end if;
  update public.profiles
     set data = p_data, updated_at = clock_timestamp()
   where id = v_student_id
   returning updated_at into v_updated_at;
  return v_updated_at;
end
$function$;
revoke all on function public.au_save_profile_data(jsonb,timestamptz) from public, anon;
grant execute on function public.au_save_profile_data(jsonb,timestamptz) to authenticated;

create or replace function public.au_commit_achievement(
  p_student_id uuid,
  p_source text,
  p_request_id uuid,
  p_achievement jsonb,
  p_evidence_ref text
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog
as $function$
declare
  v_profile public.profiles%rowtype;
  v_existing_result jsonb;
  v_existing_item jsonb;
  v_items jsonb;
  v_item_id uuid;
  v_hash text;
  v_fingerprint text;
  v_name text;
  v_number text;
  v_effective_evidence text;
  v_verification_id uuid;
  v_result jsonb;
  v_append boolean := true;
begin
  if p_student_id is null or p_request_id is null or p_source is null
     or p_source not in ('manual_add', 'iads')
     or jsonb_typeof(p_achievement) is distinct from 'object' then
    raise exception 'A valid achievement submission is required.';
  end if;
  if jsonb_typeof(p_achievement -> 'id') is distinct from 'string'
     or jsonb_typeof(p_achievement -> 'title') is distinct from 'string'
     or jsonb_typeof(p_achievement -> 'category') is distinct from 'string' then
    raise exception 'Achievement ID, title, and category are required.';
  end if;
  if exists (
    select 1 from jsonb_object_keys(p_achievement) as keys(key)
     where keys.key not in ('id','title','category','date','issuer','description','file')
  ) or exists (
    select 1 from jsonb_object_keys(p_achievement) as keys(key)
     where jsonb_typeof(p_achievement -> keys.key) is distinct from 'string'
  ) then
    raise exception 'Achievement contains an unsupported field or value.';
  end if;
  if (p_achievement ->> 'id') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
    raise exception 'Achievement ID must be a UUID.';
  end if;
  if p_achievement ->> 'category' not in (
    'Academic', 'Leadership', 'Research', 'Community Service',
    'Sports', 'Arts & Culture', 'Other'
  ) then raise exception 'Choose a valid achievement category.'; end if;
  if char_length(p_achievement ->> 'title') not between 1 and 160
     or char_length(coalesce(p_achievement ->> 'date', '')) > 40
     or char_length(coalesce(p_achievement ->> 'issuer', '')) > 160
     or char_length(coalesce(p_achievement ->> 'description', '')) > 800
     or char_length(p_achievement ->> 'title') > 200 then
    raise exception 'Achievement details exceed the allowed length.';
  end if;
  if p_evidence_ref is not null and (
    p_achievement ->> 'file' is distinct from p_evidence_ref
    or p_evidence_ref !~ '^storage://[0-9a-fA-F-]{36}/[A-Za-z0-9._/-]+$'
    or left(p_evidence_ref, length('storage://' || p_student_id::text || '/'))
         <> 'storage://' || p_student_id::text || '/'
  ) then raise exception 'Evidence must be a private Storage reference.'; end if;

  perform pg_advisory_xact_lock(hashtextextended(p_student_id::text, 0));
  select * into v_profile from public.profiles where id = p_student_id for update;
  if not found then raise exception 'Student profile not found.'; end if;
  if jsonb_typeof(coalesce(v_profile.data -> 'achievements', '[]'::jsonb)) <> 'array' then
    raise exception 'The saved achievement list has an unsupported format.';
  end if;
  v_items := coalesce(v_profile.data -> 'achievements', '[]'::jsonb);
  v_hash := public.au_achievement_hash(p_achievement);
  v_fingerprint := encode(extensions.digest(
    convert_to(p_source || ':' || p_achievement::text || ':' || coalesce(p_evidence_ref, ''), 'UTF8'),
    'sha256'), 'hex');
  if exists (
    select 1 from jsonb_array_elements(v_items) as a(item)
     where a.item ->> 'id' = p_achievement ->> 'id'
       and public.au_achievement_hash(a.item) <> v_hash
  ) then
    raise exception 'Achievement ID already belongs to different details.';
  end if;

  select k.result into v_existing_result
    from public.achievement_mutation_keys k
   where k.student_id = p_student_id and k.source = p_source and k.request_id = p_request_id;
  if found then
    if v_existing_result ->> 'request_fingerprint' is distinct from v_fingerprint then
      raise exception using errcode = '22023',
        message = 'This request ID was already used with different achievement details.';
    end if;
    return v_existing_result - 'request_fingerprint';
  end if;

  v_item_id := (p_achievement ->> 'id')::uuid;
  if to_regclass('public.iads_candidates') is not null then
    execute $query$
      select c.verification_id
        from public.iads_candidates c
       where c.student_id = $1 and c.status = 'accepted'
         and public.au_achievement_hash(jsonb_build_object(
           'title', c.title, 'category', c.category, 'date', c.date,
           'issuer', c.issuer, 'description', c.description
         )) = $2
       order by c.created_at
       limit 1
    $query$ into v_verification_id using p_student_id, v_hash;
    if v_verification_id is not null then
      v_result := jsonb_build_object(
        'outcome', 'duplicate', 'achievement', null,
        'verification_id', v_verification_id, 'updated_at', v_profile.updated_at);
      insert into public.achievement_mutation_keys
        (student_id, source, request_id, request_fingerprint, result)
      values (p_student_id, p_source, p_request_id, v_fingerprint,
        v_result || jsonb_build_object('request_fingerprint', v_fingerprint));
      return v_result;
    end if;
  end if;
  select a.item into v_existing_item
    from jsonb_array_elements(v_items) with ordinality as a(item, ordinality)
   where public.au_achievement_hash(a.item) = v_hash
   order by a.ordinality
   limit 1;
  if v_existing_item is not null then
    if p_source = 'iads' then
      v_result := jsonb_build_object(
        'outcome', 'duplicate', 'achievement', v_existing_item,
        'verification_id', null, 'updated_at', v_profile.updated_at);
      insert into public.achievement_mutation_keys
        (student_id, source, request_id, request_fingerprint, result)
      values (p_student_id, p_source, p_request_id, v_fingerprint,
        v_result || jsonb_build_object('request_fingerprint', v_fingerprint));
      return v_result;
    end if;
    v_item_id := (v_existing_item ->> 'id')::uuid;
    v_effective_evidence := nullif(v_existing_item ->> 'file', '');
    v_append := false;
    select v.id into v_verification_id from public.verifications v
     where v.student_id = p_student_id and v.item_type = 'achievement'
       and v.item_hash = v_hash
       and v.status in ('pending', 'verified')
     order by case v.status when 'verified' then 0 else 1 end, v.created_at
     limit 1;
    if found then
      v_result := jsonb_build_object(
        'outcome', 'duplicate', 'achievement', v_existing_item,
        'verification_id', v_verification_id, 'updated_at', v_profile.updated_at);
      insert into public.achievement_mutation_keys
        (student_id, source, request_id, request_fingerprint, result)
      values (p_student_id, p_source, p_request_id, v_fingerprint,
        v_result || jsonb_build_object('request_fingerprint', v_fingerprint));
      return v_result;
    end if;
  else
    v_effective_evidence := p_evidence_ref;
    select v.id into v_verification_id from public.verifications v
     where v.student_id = p_student_id and v.item_type = 'achievement'
       and v.item_hash = v_hash and v.status in ('pending', 'verified')
     order by case v.status when 'verified' then 0 else 1 end, v.created_at
     limit 1;
    if found then
      v_result := jsonb_build_object(
        'outcome', 'duplicate', 'achievement', null,
        'verification_id', v_verification_id, 'updated_at', v_profile.updated_at);
      insert into public.achievement_mutation_keys
        (student_id, source, request_id, request_fingerprint, result)
      values (p_student_id, p_source, p_request_id, v_fingerprint,
        v_result || jsonb_build_object('request_fingerprint', v_fingerprint));
      return v_result;
    end if;
  end if;
  if v_effective_evidence is not null and
     left(v_effective_evidence, length('storage://' || p_student_id::text || '/'))
       <> 'storage://' || p_student_id::text || '/' then
    raise exception 'Evidence must belong to the authenticated student.';
  end if;

  select nullif(btrim(v_profile.data #>> '{profile,name}'), ''),
         nullif(btrim(v_profile.data #>> '{profile,studentId}'), '')
    into v_name, v_number;
  if v_name is null or v_number is null then
    raise exception 'Add your full name and student ID to your profile before submitting an achievement.';
  end if;
  if char_length(v_name) > 120 or char_length(v_number) > 40 then
    raise exception 'Your saved name or student ID exceeds the verification field limits. Contact the Records Office.';
  end if;

  insert into public.verifications (
    student_id, student_name, student_number, item_type, item_id, item_title,
    item_snapshot, item_hash, evidence, status
  ) values (
    p_student_id, v_name, v_number, 'achievement', v_item_id::text,
    p_achievement ->> 'title',
    jsonb_build_object(
      'title', coalesce(p_achievement ->> 'title', ''),
      'category', coalesce(p_achievement ->> 'category', ''),
      'date', coalesce(p_achievement ->> 'date', ''),
      'issuer', coalesce(p_achievement ->> 'issuer', ''),
      'description', coalesce(p_achievement ->> 'description', '')
    ),
    v_hash,
    case when v_effective_evidence is null then '{}'::text[] else array[v_effective_evidence] end,
    'pending'
  )
  on conflict (student_id, item_type, item_id, item_hash)
    where status in ('pending', 'verified') do nothing
  returning id into v_verification_id;

  if v_verification_id is null then
    select v.id into v_verification_id from public.verifications v
     where v.student_id = p_student_id and v.item_type = 'achievement'
       and v.item_id = v_item_id::text and v.item_hash = v_hash
       and v.status in ('pending', 'verified')
     order by v.created_at limit 1;
    v_result := jsonb_build_object(
      'outcome', 'duplicate', 'achievement', v_existing_item,
      'verification_id', v_verification_id, 'updated_at', v_profile.updated_at);
  else
    if v_append then
      update public.profiles
         set data = jsonb_set(coalesce(data, '{}'::jsonb), '{achievements}',
               v_items || jsonb_build_array(p_achievement), true),
             updated_at = clock_timestamp()
       where id = p_student_id
       returning updated_at into v_profile.updated_at;
    end if;
    v_result := jsonb_build_object(
      'outcome', 'submitted',
      'achievement', case when v_append then p_achievement else v_existing_item end,
      'verification_id', v_verification_id,
      'updated_at', v_profile.updated_at);
  end if;

  insert into public.achievement_mutation_keys
    (student_id, source, request_id, request_fingerprint, result)
  values (p_student_id, p_source, p_request_id, v_fingerprint,
    v_result || jsonb_build_object('request_fingerprint', v_fingerprint));
  return v_result;
end
$function$;
revoke all on function public.au_commit_achievement(uuid,text,uuid,jsonb,text)
  from public, anon, authenticated, service_role;

create or replace function public.au_submit_manual_achievement(
  p_request_id uuid,
  p_achievement jsonb
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog
as $function$
begin
  if auth.uid() is null then raise exception 'Sign in is required.'; end if;
  return public.au_commit_achievement(auth.uid(), 'manual_add', p_request_id,
    p_achievement, nullif(p_achievement ->> 'file', ''));
end
$function$;
revoke all on function public.au_submit_manual_achievement(uuid,jsonb) from public, anon;
grant execute on function public.au_submit_manual_achievement(uuid,jsonb) to authenticated;

create or replace function public.au_request_achievement_verification(
  p_request_id uuid,
  p_item_id uuid
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog
as $function$
declare
  v_profile public.profiles%rowtype;
  v_item jsonb;
  v_hash text;
  v_fingerprint text;
  v_result jsonb;
  v_verification_id uuid;
  v_name text;
  v_number text;
begin
  if auth.uid() is null or p_request_id is null or p_item_id is null then
    raise exception 'A signed-in student and achievement are required.';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(auth.uid()::text, 0));
  select * into v_profile from public.profiles where id = auth.uid() for update;
  if not found then raise exception 'Student profile not found.'; end if;
  select a.item into v_item
    from jsonb_array_elements(coalesce(v_profile.data -> 'achievements', '[]'::jsonb)) as a(item)
   where a.item ->> 'id' = p_item_id::text limit 1;
  if v_item is null then raise exception 'This achievement is no longer in your profile.'; end if;
  v_hash := public.au_achievement_hash(v_item);
  v_fingerprint := encode(extensions.digest(
    convert_to(p_item_id::text || ':' || v_hash, 'UTF8'), 'sha256'), 'hex');
  select k.result into v_result from public.achievement_mutation_keys k
   where k.student_id = auth.uid() and k.source = 'manual_verify' and k.request_id = p_request_id;
  if found then
    if v_result ->> 'request_fingerprint' is distinct from v_fingerprint then
      raise exception using errcode = '22023',
        message = 'This request ID was already used for a different achievement.';
    end if;
    return v_result - 'request_fingerprint';
  end if;
  select v.id into v_verification_id from public.verifications v
   where v.student_id = auth.uid() and v.item_type = 'achievement'
     and v.item_hash = v_hash
     and v.status in ('pending', 'verified')
   order by case v.status when 'verified' then 0 else 1 end, v.created_at
   limit 1;
  if not found then
    if exists (
      select 1 from jsonb_array_elements(coalesce(v_profile.data -> 'achievements', '[]'::jsonb)) as a(item)
       where a.item ->> 'id' <> p_item_id::text
         and public.au_achievement_hash(a.item) = v_hash
    ) then
      v_result := jsonb_build_object('outcome', 'duplicate', 'verification_id', null);
    else
      select nullif(btrim(v_profile.data #>> '{profile,name}'), ''),
             nullif(btrim(v_profile.data #>> '{profile,studentId}'), '')
        into v_name, v_number;
      if v_name is null or v_number is null then
        raise exception 'Add your full name and student ID to your profile first.';
      end if;
      if char_length(v_name) > 120 or char_length(v_number) > 40 then
        raise exception 'Your saved name or student ID exceeds the verification field limits. Contact the Records Office.';
      end if;
      insert into public.verifications (
        student_id, student_name, student_number, item_type, item_id, item_title,
        item_snapshot, item_hash, evidence, status
      ) values (
        auth.uid(), v_name, v_number, 'achievement', p_item_id::text,
        coalesce(v_item ->> 'title', ''),
        jsonb_build_object(
          'title', coalesce(v_item ->> 'title', ''),
          'category', coalesce(v_item ->> 'category', ''),
          'date', coalesce(v_item ->> 'date', ''),
          'issuer', coalesce(v_item ->> 'issuer', ''),
          'description', coalesce(v_item ->> 'description', '')
        ),
        v_hash,
        case when nullif(v_item ->> 'file', '') is null then '{}'::text[]
             else array[v_item ->> 'file'] end,
        'pending'
      )
      on conflict (student_id, item_type, item_id, item_hash)
        where status in ('pending', 'verified') do nothing
      returning id into v_verification_id;
      v_result := jsonb_build_object(
        'outcome', case when v_verification_id is null then 'duplicate' else 'submitted' end,
        'verification_id', v_verification_id);
    end if;
  else
    v_result := jsonb_build_object('outcome', 'duplicate', 'verification_id', v_verification_id);
  end if;
  insert into public.achievement_mutation_keys
    (student_id, source, request_id, request_fingerprint, result)
  values (auth.uid(), 'manual_verify', p_request_id, v_fingerprint,
    v_result || jsonb_build_object('request_fingerprint', v_fingerprint));
  return v_result;
end
$function$;
revoke all on function public.au_request_achievement_verification(uuid,uuid) from public, anon;
grant execute on function public.au_request_achievement_verification(uuid,uuid) to authenticated;
