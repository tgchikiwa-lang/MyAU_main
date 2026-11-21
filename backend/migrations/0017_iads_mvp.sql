-- IADS MVP tables, receipt verifier, candidate lifecycle, and a private evidence bucket.
-- Existing MyAU verification/profile objects and student-content policies are not changed.

do $preflight$
declare
  v_bucket record;
  v_student_content record;
  v_service record;
begin
  if to_regclass('public.achievement_mutation_keys') is null
     or to_regprocedure('public.au_achievement_hash(jsonb)') is null
     or to_regprocedure('public.au_commit_achievement(uuid,text,uuid,jsonb,text)') is null
     or not (select prosecdef from pg_proc
              where oid = to_regprocedure('public.au_commit_achievement(uuid,text,uuid,jsonb,text)'))
     or has_function_privilege('authenticated',
          to_regprocedure('public.au_commit_achievement(uuid,text,uuid,jsonb,text)'), 'EXECUTE')
     or has_function_privilege('service_role',
          to_regprocedure('public.au_commit_achievement(uuid,text,uuid,jsonb,text)'), 'EXECUTE') then
    raise exception 'IADS preflight failed: migration 0016 achievement mutation boundary is missing or unsafe.';
  end if;
  if to_regprocedure('public.au_can_verify(uuid,text)') is null
     or to_regprocedure('public.au_mfa_verified()') is null
     or (select prosecdef from pg_proc
          where oid = to_regprocedure('public.au_can_verify(uuid,text)'))
     or not has_function_privilege('authenticated',
          to_regprocedure('public.au_can_verify(uuid,text)'), 'EXECUTE')
     or not has_function_privilege('authenticated',
          to_regprocedure('public.au_mfa_verified()'), 'EXECUTE') then
    raise exception 'IADS preflight failed: existing staff verification or MFA authorization is missing or incompatible.';
  end if;
  if to_regclass('public.iads_candidates') is not null
     or to_regclass('public.iads_achievement_provenance') is not null
     or to_regclass('iads_private.hmac_keys') is not null
     or to_regclass('iads_private.evidence_receipts') is not null
     or exists (
       select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public' and c.relname like 'iads\_%' escape '\'
     )
     or exists (
       select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public' and p.proname like 'iads\_%' escape '\'
     )
     or to_regclass('public.iads_candidates_student_status_idx') is not null
     or to_regclass('public.iads_candidates_active_fingerprint_uq') is not null
     or exists (select 1 from pg_namespace where nspname = 'iads_private') then
    raise exception 'IADS preflight failed: an IADS object already exists; inspect partial deployment before proceeding.';
  end if;
  if to_regclass('storage.objects') is null or to_regclass('storage.buckets') is null then
    raise exception 'IADS preflight failed: Supabase Storage is unavailable.';
  end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then
    raise exception 'IADS preflight failed: service_role is missing.';
  end if;
  select * into v_service from pg_roles where rolname = 'service_role';
  if v_service.rolsuper then
    raise exception 'IADS preflight failed: service_role must not be a superuser.';
  end if;
  select * into v_bucket from pg_roles where rolname = 'iads_receipt_owner';
  if not found or v_bucket.rolcanlogin or v_bucket.rolsuper
     or v_bucket.rolbypassrls or v_bucket.rolcreaterole or v_bucket.rolcreatedb
     or v_bucket.rolreplication or v_bucket.rolinherit
     or v_service.rolcreaterole
     or has_schema_privilege('iads_receipt_owner','public','CREATE')
     or pg_has_role('service_role', 'iads_receipt_owner', 'MEMBER')
     or pg_has_role('iads_receipt_owner', 'service_role', 'MEMBER')
     or pg_has_role('service_role', 'postgres', 'MEMBER')
     or exists (
       select 1 from pg_auth_members m
        where m.roleid = 'iads_receipt_owner'::regrole
           or m.member = 'iads_receipt_owner'::regrole
     ) then
    raise exception 'IADS preflight failed: the dedicated receipt role or its service-role isolation is incompatible.';
  end if;
  select id, name, public, file_size_limit, allowed_mime_types
    into v_bucket from storage.buckets where id = 'iads-evidence';
  if found and (
    v_bucket.name <> 'iads-evidence' or v_bucket.public
    or v_bucket.file_size_limit <> 5242880
    or v_bucket.allowed_mime_types is distinct from
      array['application/pdf','image/jpeg','image/png','image/webp']::text[]
  ) then
    raise exception 'IADS preflight failed: an existing iads-evidence bucket has incompatible settings; inspect it manually.';
  end if;
  select id, public, file_size_limit, allowed_mime_types
    into v_student_content from storage.buckets where id = 'student-content';
  if not found or v_student_content.public
     or v_student_content.file_size_limit <> 5242880
     or v_student_content.allowed_mime_types is not null then
    raise exception 'IADS preflight failed: student-content must remain private, capped at 5 MiB, and without a bucket MIME allowlist.';
  end if;
  if not (select relrowsecurity from pg_class where oid = 'storage.objects'::regclass) then
    raise exception 'IADS preflight failed: Storage object RLS must be enabled.';
  end if;
  if not exists (
    select 1 from pg_policies
     where schemaname = 'storage' and tablename = 'objects'
       and cmd in ('INSERT','ALL') and 'authenticated' = any(roles)
       and coalesce(with_check,'') ilike '%student-content%'
       and coalesce(with_check,'') ilike '%storage.foldername%'
       and coalesce(with_check,'') ilike '%auth.uid%'
  ) or not exists (
    select 1 from pg_policies
     where schemaname = 'storage' and tablename = 'objects'
       and cmd in ('SELECT','ALL') and 'authenticated' = any(roles)
       and coalesce(qual,'') ilike '%student-content%'
       and coalesce(qual,'') ilike '%storage.foldername%'
       and coalesce(qual,'') ilike '%auth.uid%'
  ) or not exists (
    select 1 from pg_policies
     where schemaname = 'storage' and tablename = 'objects'
       and cmd in ('DELETE','ALL') and 'authenticated' = any(roles)
       and coalesce(qual,'') ilike '%student-content%'
       and coalesce(qual,'') ilike '%storage.foldername%'
       and coalesce(qual,'') ilike '%auth.uid%'
  ) then
    raise exception 'IADS preflight failed: existing student-content student ownership policies are missing or incompatible.';
  end if;
  if not exists (
    select 1 from pg_policies
     where schemaname = 'storage' and tablename = 'objects'
       and permissive = 'RESTRICTIVE' and 'authenticated' = any(roles)
       and (coalesce(qual,'') || coalesce(with_check,'')) ilike '%au_mfa_verified%'
  ) or not exists (
    select 1 from pg_policies
     where schemaname = 'storage' and tablename = 'objects'
       and cmd in ('SELECT','ALL') and 'authenticated' = any(roles)
       and coalesce(qual,'') ilike '%student-content%'
       and coalesce(qual,'') ilike '%au_is_staff%'
  ) then
    raise exception 'IADS preflight failed: existing MFA enforcement or staff Storage read policy is missing.';
  end if;
  if exists (
    select 1 from pg_policies
     where schemaname = 'storage' and tablename = 'objects'
       and policyname in (
         'iads_evidence_student_select', 'iads_evidence_student_insert',
         'iads_evidence_staff_select', 'iads_evidence_mfa_fence',
         'iads_evidence_select_fence', 'iads_evidence_insert_fence',
         'iads_evidence_update_fence', 'iads_evidence_delete_fence'
       )
  ) then
    raise exception 'IADS preflight failed: an IADS Storage policy name already exists; inspect it before proceeding.';
  end if;
end
$preflight$;

create schema iads_private authorization iads_receipt_owner;
revoke all on schema iads_private from public, anon, authenticated, service_role;
grant usage on schema public, extensions to iads_receipt_owner;
grant execute on function extensions.hmac(bytea,bytea,text) to iads_receipt_owner;

create table public.iads_candidates (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references auth.users(id) on delete cascade,
  request_id uuid not null,
  request_fingerprint text not null check (request_fingerprint ~ '^[0-9a-f]{64}$'),
  source_kind text not null check (source_kind in ('upload','url')),
  requested_evidence_sha256 text check (
    requested_evidence_sha256 is null or requested_evidence_sha256 ~ '^[0-9a-f]{64}$'
  ),
  title text not null check (char_length(title) between 1 and 160),
  category text not null check (category in (
    'Academic','Leadership','Research','Community Service','Sports','Arts & Culture','Other'
  )),
  date text not null default '' check (char_length(date) <= 40),
  issuer text not null default '' check (char_length(issuer) <= 160),
  description text not null default '' check (char_length(description) <= 800),
  source_url text,
  source_storage_ref text,
  canonical_storage_ref text,
  evidence_size_bytes bigint check (evidence_size_bytes between 1 and 5242880),
  evidence_mime_type text check (evidence_mime_type in (
    'application/pdf','image/jpeg','image/png','image/webp'
  )),
  evidence_sha256 text check (evidence_sha256 is null or evidence_sha256 ~ '^[0-9a-f]{64}$'),
  submit_receipt_id uuid,
  submit_operation_id uuid,
  submit_operation_expires_ms bigint,
  accept_operation_id uuid,
  accept_operation_expires_ms bigint,
  status text not null default 'awaiting_evidence'
    check (status in ('awaiting_evidence','awaiting_review','accepted','declined','duplicate')),
  verification_id uuid references public.verifications(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  decided_at timestamptz,
  unique (student_id, request_id),
  unique (id, student_id),
  check (
    (source_kind = 'url' and source_url is not null and source_storage_ref is null)
    or (source_kind = 'upload' and source_url is null)
  ),
  check (
    (source_kind = 'url' and requested_evidence_sha256 is null)
    or (source_kind = 'upload' and requested_evidence_sha256 is not null)
  ),
  check (
    status not in ('awaiting_review','accepted')
    or source_kind = 'url'
    or (source_storage_ref is not null and canonical_storage_ref is not null
        and evidence_size_bytes is not null and evidence_mime_type is not null
        and evidence_sha256 is not null)
  ),
  check (status <> 'accepted' or verification_id is not null)
);
create index iads_candidates_student_status_idx
  on public.iads_candidates(student_id, status, created_at desc);
create unique index iads_candidates_active_fingerprint_uq
  on public.iads_candidates(student_id, request_fingerprint)
  where status in ('awaiting_evidence','awaiting_review','accepted','duplicate');
alter table public.iads_candidates enable row level security;
revoke all on table public.iads_candidates from public, anon, authenticated, service_role;
grant select on table public.iads_candidates to authenticated, iads_receipt_owner;
create policy iads_candidates_owner_select on public.iads_candidates
  for select to authenticated using (student_id = auth.uid());
create policy iads_candidates_receipt_owner_select on public.iads_candidates
  for select to iads_receipt_owner using (true);

create table public.iads_achievement_provenance (
  candidate_id uuid primary key,
  student_id uuid not null references auth.users(id) on delete cascade,
  verification_id uuid not null unique references public.verifications(id),
  item_id text not null check (char_length(item_id) <= 64),
  source_kind text not null check (source_kind in ('upload','url')),
  source_url text,
  source_storage_ref text,
  canonical_storage_ref text,
  evidence_size_bytes bigint,
  evidence_mime_type text,
  evidence_sha256 text,
  created_at timestamptz not null default now(),
  foreign key (candidate_id, student_id)
    references public.iads_candidates(id, student_id) on delete restrict,
  check (
    (source_kind = 'url' and source_url is not null and canonical_storage_ref is null)
    or (source_kind = 'upload' and source_url is null and canonical_storage_ref is not null)
  )
);
alter table public.iads_achievement_provenance enable row level security;
revoke all on table public.iads_achievement_provenance from public, anon, authenticated, service_role;
grant select on table public.iads_achievement_provenance to authenticated;
create policy iads_provenance_owner_select on public.iads_achievement_provenance
  for select to authenticated using (student_id = auth.uid());
create policy iads_provenance_staff_select on public.iads_achievement_provenance
  for select to authenticated using (
    public.au_can_verify(student_id, 'achievement')
    and public.au_mfa_verified()
  );

create table iads_private.hmac_keys (
  key_id text primary key check (key_id ~ '^[a-zA-Z0-9_-]{1,32}$'),
  key_material bytea not null check (octet_length(key_material) = 32),
  not_before timestamptz not null,
  not_after timestamptz,
  created_at timestamptz not null default now(),
  check (not_after is null or not_after > not_before)
);
alter table iads_private.hmac_keys owner to iads_receipt_owner;
revoke all on table iads_private.hmac_keys from public, anon, authenticated, service_role;

create table iads_private.evidence_receipts (
  id uuid primary key,
  operation_id uuid not null,
  student_id uuid not null,
  candidate_id uuid not null,
  purpose text not null check (purpose in ('submit','accept')),
  key_id text not null references iads_private.hmac_keys(key_id),
  source_bucket text not null check (source_bucket = 'student-content'),
  source_path text not null,
  canonical_bucket text not null check (canonical_bucket = 'iads-evidence'),
  canonical_path text not null,
  file_size_bytes bigint not null check (file_size_bytes between 1 and 5242880),
  detected_mime_type text not null check (detected_mime_type in (
    'application/pdf','image/jpeg','image/png','image/webp'
  )),
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  expires_ms bigint not null,
  signature bytea not null check (octet_length(signature) = 32),
  state text not null default 'pending' check (state in ('pending','consumed')),
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  foreign key (candidate_id, student_id)
    references public.iads_candidates(id, student_id) on delete cascade,
  unique (student_id, candidate_id, purpose, operation_id),
  check ((state = 'pending' and consumed_at is null)
      or (state = 'consumed' and consumed_at is not null))
);
alter table iads_private.evidence_receipts owner to iads_receipt_owner;
revoke all on table iads_private.evidence_receipts from public, anon, authenticated, service_role;
grant select, insert, update on table iads_private.evidence_receipts to iads_receipt_owner;
grant select on table public.iads_candidates to iads_receipt_owner;
create index evidence_receipts_expiry_idx
  on iads_private.evidence_receipts(expires_ms) where state = 'pending';

create or replace function iads_private.receipt_payload(
  p_key_id text, p_receipt_id uuid, p_student_id uuid, p_candidate_id uuid,
  p_purpose text, p_operation_id uuid, p_source_bucket text, p_source_path text,
  p_canonical_bucket text, p_canonical_path text, p_size bigint, p_mime text,
  p_sha256 text, p_expires_ms bigint
) returns bytea
language plpgsql immutable
set search_path = pg_catalog
as $function$
declare
  v_payload bytea := convert_to('IADS-RECEIPT','UTF8') || decode('00','hex') || decode('01','hex');
  v_field text;
  v_bytes bytea;
begin
  foreach v_field in array array[
    p_key_id, p_receipt_id::text, p_student_id::text, p_candidate_id::text,
    p_purpose, p_operation_id::text, p_source_bucket, p_source_path,
    p_canonical_bucket, p_canonical_path, p_size::text, lower(p_mime),
    lower(p_sha256), p_expires_ms::text
  ] loop
    v_bytes := convert_to(v_field,'UTF8');
    v_payload := v_payload || int4send(octet_length(v_bytes)) || v_bytes;
  end loop;
  return v_payload;
end
$function$;
alter function iads_private.receipt_payload(text,uuid,uuid,uuid,text,uuid,text,text,text,text,bigint,text,text,bigint)
  owner to iads_receipt_owner;
revoke all on function iads_private.receipt_payload(text,uuid,uuid,uuid,text,uuid,text,text,text,text,bigint,text,text,bigint)
  from public, anon, authenticated, service_role;

create or replace function iads_private.constant_time_equal(p_left bytea, p_right bytea)
returns boolean
language plpgsql immutable strict
set search_path = pg_catalog
as $function$
declare
  i integer;
  v_diff integer := 0;
begin
  if octet_length(p_left) <> 32 or octet_length(p_right) <> 32 then return false; end if;
  for i in 0..31 loop
    v_diff := v_diff | (get_byte(p_left, i) # get_byte(p_right, i));
  end loop;
  return v_diff = 0;
end
$function$;
alter function iads_private.constant_time_equal(bytea,bytea) owner to iads_receipt_owner;
revoke all on function iads_private.constant_time_equal(bytea,bytea)
  from public, anon, authenticated, service_role;

create or replace function public.iads_record_evidence_receipt(
  p_receipt_id uuid,
  p_operation_id uuid,
  p_student_id uuid,
  p_candidate_id uuid,
  p_purpose text,
  p_key_id text,
  p_source_bucket text,
  p_source_path text,
  p_canonical_bucket text,
  p_canonical_path text,
  p_file_size_bytes bigint,
  p_detected_mime_type text,
  p_content_sha256 text,
  p_expires_ms bigint,
  p_signature bytea
) returns uuid
language plpgsql
security definer
set search_path = pg_catalog
as $function$
declare
  v_candidate public.iads_candidates%rowtype;
  v_key bytea;
  v_expected bytea;
  v_existing iads_private.evidence_receipts%rowtype;
  v_ext text;
  v_now_ms bigint := floor(extract(epoch from clock_timestamp()) * 1000)::bigint;
begin
  if p_receipt_id is null or p_operation_id is null or p_student_id is null
     or p_candidate_id is null or p_purpose is null or p_key_id is null
     or p_source_bucket is null or p_source_path is null
     or p_canonical_bucket is null or p_canonical_path is null
     or p_file_size_bytes is null or p_detected_mime_type is null or p_content_sha256 is null
     or p_expires_ms is null or p_signature is null
     or p_purpose not in ('submit','accept')
     or p_file_size_bytes not between 1 and 5242880
     or p_detected_mime_type not in ('application/pdf','image/jpeg','image/png','image/webp')
     or p_content_sha256 !~ '^[0-9a-f]{64}$'
     or octet_length(p_signature) <> 32
     or p_receipt_id <> p_operation_id
     or p_expires_ms <= v_now_ms or p_expires_ms > v_now_ms + 300000 then
    raise exception 'Receipt rejected.';
  end if;
  select * into v_candidate from public.iads_candidates c
   where c.id = p_candidate_id and c.student_id = p_student_id;
  if not found or p_source_bucket <> 'student-content'
     or p_canonical_bucket <> 'iads-evidence'
     or v_candidate.source_kind <> 'upload'
     or v_candidate.source_storage_ref is distinct from 'storage://' || p_source_path
     or p_source_path <> p_student_id::text || '/iads-source/' || p_candidate_id::text then
    raise exception 'Receipt rejected.';
  end if;
  v_ext := case p_detected_mime_type
    when 'application/pdf' then 'pdf' when 'image/jpeg' then 'jpg'
    when 'image/png' then 'png' when 'image/webp' then 'webp' end;
  if p_purpose = 'submit' then
    if v_candidate.status <> 'awaiting_evidence'
       or v_candidate.submit_operation_id is distinct from p_operation_id
       or v_candidate.submit_operation_expires_ms is distinct from p_expires_ms
       or v_candidate.requested_evidence_sha256 is distinct from p_content_sha256
       or p_canonical_path <> p_student_id::text || '/iads-evidence/' || p_candidate_id::text || '.' || v_ext then
      raise exception 'Receipt rejected.';
    end if;
  elsif v_candidate.status <> 'awaiting_review'
     or v_candidate.accept_operation_id is distinct from p_operation_id
     or v_candidate.accept_operation_expires_ms is distinct from p_expires_ms
     or v_candidate.canonical_storage_ref is distinct from 'storage://' || p_canonical_path
     or v_candidate.evidence_size_bytes <> p_file_size_bytes
     or v_candidate.evidence_mime_type <> p_detected_mime_type
     or v_candidate.evidence_sha256 <> p_content_sha256 then
    raise exception 'Receipt rejected.';
  end if;
  select r.* into v_existing from iads_private.evidence_receipts r
   where r.student_id = p_student_id and r.candidate_id = p_candidate_id
     and r.purpose = p_purpose and r.operation_id = p_operation_id;
  if found then
    if v_existing.id <> p_receipt_id or v_existing.key_id <> p_key_id
       or v_existing.source_path <> p_source_path or v_existing.canonical_path <> p_canonical_path
       or v_existing.file_size_bytes <> p_file_size_bytes
       or v_existing.detected_mime_type <> p_detected_mime_type
       or v_existing.content_sha256 <> p_content_sha256
       or v_existing.expires_ms <> p_expires_ms
       or not iads_private.constant_time_equal(v_existing.signature, p_signature) then
      raise exception 'Receipt rejected.';
    end if;
    return v_existing.id;
  end if;
  select k.key_material into v_key from iads_private.hmac_keys k
   where k.key_id = p_key_id and k.not_before <= clock_timestamp()
     and (k.not_after is null or k.not_after > clock_timestamp());
  if v_key is null then raise exception 'Receipt rejected.'; end if;
  v_expected := extensions.hmac(
    iads_private.receipt_payload(
      p_key_id, p_receipt_id, p_student_id, p_candidate_id, p_purpose,
      p_operation_id, p_source_bucket, p_source_path, p_canonical_bucket,
      p_canonical_path, p_file_size_bytes, p_detected_mime_type,
      p_content_sha256, p_expires_ms
    ), v_key, 'sha256');
  if not iads_private.constant_time_equal(v_expected, p_signature) then
    raise exception 'Receipt rejected.';
  end if;
  insert into iads_private.evidence_receipts (
    id, operation_id, student_id, candidate_id, purpose, key_id,
    source_bucket, source_path, canonical_bucket, canonical_path,
    file_size_bytes, detected_mime_type, content_sha256, expires_ms, signature
  ) values (
    p_receipt_id, p_operation_id, p_student_id, p_candidate_id, p_purpose, p_key_id,
    p_source_bucket, p_source_path, p_canonical_bucket, p_canonical_path,
    p_file_size_bytes, p_detected_mime_type, p_content_sha256, p_expires_ms, p_signature
  ) on conflict (student_id, candidate_id, purpose, operation_id) do nothing;
  if not found then
    select * into v_existing from iads_private.evidence_receipts r
     where r.student_id = p_student_id and r.candidate_id = p_candidate_id
       and r.purpose = p_purpose and r.operation_id = p_operation_id
     for update;
    if not found or v_existing.id <> p_receipt_id or v_existing.key_id <> p_key_id
       or v_existing.source_path <> p_source_path
       or v_existing.canonical_path <> p_canonical_path
       or v_existing.file_size_bytes <> p_file_size_bytes
       or v_existing.detected_mime_type <> p_detected_mime_type
       or v_existing.content_sha256 <> p_content_sha256
       or v_existing.expires_ms <> p_expires_ms
       or not iads_private.constant_time_equal(v_existing.signature, p_signature) then
      raise exception 'Receipt rejected.';
    end if;
    return v_existing.id;
  end if;
  return p_receipt_id;
end
$function$;
grant create on schema public to iads_receipt_owner;
alter function public.iads_record_evidence_receipt(uuid,uuid,uuid,uuid,text,text,text,text,text,text,bigint,text,text,bigint,bytea)
  owner to iads_receipt_owner;
revoke create on schema public from iads_receipt_owner;
do $acl_check$
begin
  if has_schema_privilege('iads_receipt_owner','public','CREATE') then
    raise exception 'IADS permission check failed: receipt owner retains effective CREATE on public.';
  end if;
end
$acl_check$;
revoke all on function public.iads_record_evidence_receipt(uuid,uuid,uuid,uuid,text,text,text,text,text,text,bigint,text,text,bigint,bytea)
  from public, anon, authenticated;
revoke all on function public.iads_record_evidence_receipt(uuid,uuid,uuid,uuid,text,text,text,text,text,text,bigint,text,text,bigint,bytea)
  from service_role;
grant execute on function public.iads_record_evidence_receipt(uuid,uuid,uuid,uuid,text,text,text,text,text,text,bigint,text,text,bigint,bytea)
  to service_role;

create or replace function public.iads_create_candidate(
  p_request_id uuid, p_source_kind text, p_title text, p_category text,
  p_date text, p_issuer text, p_description text, p_source_url text default null,
  p_evidence_sha256 text default null
) returns uuid
language plpgsql
security definer
set search_path = pg_catalog
as $function$
declare
  v_student uuid := auth.uid();
  v_fingerprint text;
  v_id uuid;
  v_existing public.iads_candidates%rowtype;
begin
  if v_student is null or p_request_id is null or p_source_kind is null
     or p_source_kind not in ('upload','url')
     or p_title is null or char_length(btrim(p_title)) not between 1 and 160
     or p_category is null
     or p_category not in ('Academic','Leadership','Research','Community Service','Sports','Arts & Culture','Other')
     or char_length(coalesce(p_date,'')) > 40 or char_length(coalesce(p_issuer,'')) > 160
     or char_length(coalesce(p_description,'')) > 800 then
    raise exception 'Enter valid achievement details.';
  end if;
  if p_source_kind = 'url' and (
    p_source_url is null or char_length(p_source_url) > 2048
    or p_source_url !~* '^https://[^@[:space:]/?#]+([/?#].*)?$'
    or p_source_url ~ '[[:space:]]'
    or p_evidence_sha256 is not null
  ) then raise exception 'Enter a valid external HTTPS URL.'; end if;
  if p_source_kind = 'upload' and (
    p_source_url is not null or p_evidence_sha256 is null
    or p_evidence_sha256 !~ '^[0-9a-f]{64}$'
  ) then
    raise exception 'Choose one source and provide a valid certificate fingerprint.';
  end if;
  v_fingerprint := encode(extensions.digest(convert_to(jsonb_build_array(
    p_source_kind, btrim(p_title), p_category, coalesce(p_date,''), coalesce(p_issuer,''),
    coalesce(p_description,''), coalesce(p_source_url,''), coalesce(p_evidence_sha256,'')
  )::text,'UTF8'),'sha256'),'hex');
  perform pg_advisory_xact_lock(hashtextextended(v_student::text, 0));
  select * into v_existing from public.iads_candidates
   where student_id = v_student and request_id = p_request_id for update;
  if found then
    if v_existing.request_fingerprint <> v_fingerprint then
      raise exception using errcode = '22023',
        message = 'This request ID was already used with different details.';
    end if;
    return v_existing.id;
  end if;
  select c.id into v_id from public.iads_candidates c
   where c.student_id = v_student and c.request_fingerprint = v_fingerprint
     and c.status in ('awaiting_evidence','awaiting_review','accepted','duplicate')
   order by c.created_at limit 1 for update;
  if found then return v_id; end if;
  insert into public.iads_candidates (
    student_id, request_id, request_fingerprint, source_kind, title, category,
    date, issuer, description, source_url, requested_evidence_sha256, status
  ) values (
    v_student, p_request_id, v_fingerprint, p_source_kind, btrim(p_title), p_category,
    coalesce(p_date,''), coalesce(p_issuer,''), coalesce(p_description,''),
    p_source_url, p_evidence_sha256,
    case when p_source_kind = 'url' then 'awaiting_review' else 'awaiting_evidence' end
  ) returning id into v_id;
  return v_id;
end
$function$;

create or replace function public.iads_attach_source(p_candidate_id uuid, p_source_ref text)
returns void
language plpgsql
security definer
set search_path = pg_catalog
as $function$
declare
  v_candidate public.iads_candidates%rowtype;
  v_expected text;
begin
  if auth.uid() is null or p_candidate_id is null then raise exception 'Sign in is required.'; end if;
  perform pg_advisory_xact_lock(hashtextextended(auth.uid()::text, 0));
  select * into v_candidate from public.iads_candidates
   where id = p_candidate_id and student_id = auth.uid() for update;
  if not found or v_candidate.source_kind <> 'upload'
     or v_candidate.status <> 'awaiting_evidence' then
    raise exception 'This candidate cannot accept a source upload.';
  end if;
  v_expected := 'storage://' || auth.uid()::text || '/iads-source/' || p_candidate_id::text;
  if p_source_ref is null or p_source_ref <> v_expected then
    raise exception 'Unexpected source object path.';
  end if;
  if v_candidate.source_storage_ref is not null
     and v_candidate.source_storage_ref <> p_source_ref then
    raise exception 'The source evidence is already fixed and cannot be replaced.';
  end if;
  update public.iads_candidates set source_storage_ref = p_source_ref, updated_at = clock_timestamp()
   where id = p_candidate_id;
end
$function$;

create or replace function public.iads_update_candidate(
  p_candidate_id uuid, p_expected_updated_at timestamptz,
  p_title text, p_category text, p_date text, p_issuer text, p_description text
) returns timestamptz
language plpgsql
security definer
set search_path = pg_catalog
as $function$
declare
  v_candidate public.iads_candidates%rowtype;
begin
  if auth.uid() is null then raise exception 'Sign in is required.'; end if;
  perform pg_advisory_xact_lock(hashtextextended(auth.uid()::text, 0));
  select * into v_candidate from public.iads_candidates
   where id = p_candidate_id and student_id = auth.uid() for update;
  if not found or v_candidate.status <> 'awaiting_review' then
    raise exception 'This candidate is no longer editable.';
  end if;
  if v_candidate.updated_at is distinct from p_expected_updated_at then
    raise exception using errcode = '40001',
      message = 'This candidate changed in another session. Refresh and retry.';
  end if;
  if p_title is null or char_length(btrim(p_title)) not between 1 and 160
     or p_category not in ('Academic','Leadership','Research','Community Service','Sports','Arts & Culture','Other')
     or char_length(coalesce(p_date,'')) > 40 or char_length(coalesce(p_issuer,'')) > 160
     or char_length(coalesce(p_description,'')) > 800 then
    raise exception 'Enter valid achievement details.';
  end if;
  update public.iads_candidates set
    title = btrim(p_title), category = p_category, date = coalesce(p_date,''),
    issuer = coalesce(p_issuer,''), description = coalesce(p_description,''),
    updated_at = clock_timestamp()
  where id = p_candidate_id returning updated_at into v_candidate.updated_at;
  return v_candidate.updated_at;
end
$function$;

create or replace function public.iads_begin_evidence_operation(
  p_candidate_id uuid, p_purpose text
) returns table(operation_id uuid, expires_ms bigint)
language plpgsql
security definer
set search_path = pg_catalog
as $function$
declare
  v_candidate public.iads_candidates%rowtype;
  v_id uuid;
  v_exp bigint;
  v_receipt iads_private.evidence_receipts%rowtype;
begin
  if auth.uid() is null or p_purpose is null or p_purpose not in ('submit','accept') then
    raise exception 'A valid evidence operation is required.';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(auth.uid()::text, 0));
  select * into v_candidate from public.iads_candidates
   where id = p_candidate_id and student_id = auth.uid() for update;
  if not found or v_candidate.source_kind <> 'upload'
     or (p_purpose = 'submit' and v_candidate.status <> 'awaiting_evidence')
     or (p_purpose = 'accept' and v_candidate.status <> 'awaiting_review') then
    raise exception 'This candidate is not ready for that evidence operation.';
  end if;
  if p_purpose = 'submit' then
    v_id := v_candidate.submit_operation_id;
    v_exp := v_candidate.submit_operation_expires_ms;
  else
    v_id := v_candidate.accept_operation_id;
    v_exp := v_candidate.accept_operation_expires_ms;
  end if;
  if v_id is not null and v_exp > floor(extract(epoch from clock_timestamp()) * 1000)::bigint then
    return query select v_id, v_exp;
    return;
  end if;
  v_id := gen_random_uuid();
  v_exp := floor(extract(epoch from clock_timestamp()) * 1000)::bigint + 300000;
  if p_purpose = 'submit' then
    update public.iads_candidates set submit_operation_id = v_id,
      submit_operation_expires_ms = v_exp where id = p_candidate_id;
  else
    update public.iads_candidates set accept_operation_id = v_id,
      accept_operation_expires_ms = v_exp where id = p_candidate_id;
  end if;
  return query select v_id, v_exp;
end
$function$;

create or replace function public.iads_finalize_evidence(p_candidate_id uuid, p_receipt_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog
as $function$
declare
  v_candidate public.iads_candidates%rowtype;
  v_receipt iads_private.evidence_receipts%rowtype;
begin
  if auth.uid() is null then raise exception 'Sign in is required.'; end if;
  perform pg_advisory_xact_lock(hashtextextended(auth.uid()::text, 0));
  select * into v_candidate from public.iads_candidates
   where id = p_candidate_id and student_id = auth.uid() for update;
  if not found then raise exception 'Candidate not found.'; end if;
  if v_candidate.status = 'awaiting_review'
     and v_candidate.submit_receipt_id = p_receipt_id then
    return to_jsonb(v_candidate);
  end if;
  if v_candidate.status <> 'awaiting_evidence' then
    raise exception 'This candidate is not awaiting evidence.';
  end if;
  select * into v_receipt from iads_private.evidence_receipts
   where id = p_receipt_id and student_id = auth.uid()
     and candidate_id = p_candidate_id and purpose = 'submit'
   for update;
  if not found or v_receipt.state <> 'pending'
     or v_receipt.expires_ms <= floor(extract(epoch from clock_timestamp()) * 1000)::bigint
     or v_candidate.submit_operation_id is distinct from v_receipt.operation_id
     or v_candidate.submit_operation_expires_ms is distinct from v_receipt.expires_ms
     or v_candidate.source_storage_ref <> 'storage://' || v_receipt.source_path then
    raise exception 'Evidence receipt is invalid or expired.';
  end if;
  update iads_private.evidence_receipts set state = 'consumed', consumed_at = clock_timestamp()
   where id = p_receipt_id and state = 'pending';
  if not found then raise exception 'Evidence receipt was already consumed.'; end if;
  update public.iads_candidates set
    canonical_storage_ref = 'storage://' || v_receipt.canonical_path,
    evidence_size_bytes = v_receipt.file_size_bytes,
    evidence_mime_type = v_receipt.detected_mime_type,
    evidence_sha256 = v_receipt.content_sha256,
    submit_receipt_id = p_receipt_id,
    status = 'awaiting_review', updated_at = clock_timestamp()
   where id = p_candidate_id
   returning * into v_candidate;
  return to_jsonb(v_candidate);
end
$function$;

create or replace function public.iads_accept_candidate(
  p_candidate_id uuid, p_accept_receipt_id uuid,
  p_expected_updated_at timestamptz
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog
as $function$
declare
  v_candidate public.iads_candidates%rowtype;
  v_receipt iads_private.evidence_receipts%rowtype;
  v_achievement jsonb;
  v_result jsonb;
  v_verification_id uuid;
  v_outcome text;
  v_profile_updated_at timestamptz;
begin
  if auth.uid() is null then raise exception 'Sign in is required.'; end if;
  perform pg_advisory_xact_lock(hashtextextended(auth.uid()::text, 0));
  select * into v_candidate from public.iads_candidates
   where id = p_candidate_id and student_id = auth.uid() for update;
  if not found then raise exception 'Candidate not found.'; end if;
  if v_candidate.status = 'accepted' then
    return jsonb_build_object('outcome','accepted','verification_id',v_candidate.verification_id);
  end if;
  if v_candidate.status = 'duplicate' then
    return jsonb_build_object('outcome','duplicate','verification_id',null);
  end if;
  if v_candidate.status <> 'awaiting_review' then
    raise exception 'This candidate is not ready for acceptance.';
  end if;
  if p_expected_updated_at is null
     or v_candidate.updated_at is distinct from p_expected_updated_at then
    raise exception using errcode = '40001',
      message = 'This candidate changed in another session. Refresh and review it again.';
  end if;
  if v_candidate.source_kind = 'upload' then
    select * into v_receipt from iads_private.evidence_receipts
     where id = p_accept_receipt_id and student_id = auth.uid()
       and candidate_id = p_candidate_id and purpose = 'accept'
     for update;
    if not found or v_receipt.state <> 'pending'
       or v_receipt.expires_ms <= floor(extract(epoch from clock_timestamp()) * 1000)::bigint
       or v_candidate.accept_operation_id is distinct from v_receipt.operation_id
       or v_candidate.accept_operation_expires_ms is distinct from v_receipt.expires_ms
       or v_receipt.canonical_path <> substring(v_candidate.canonical_storage_ref from 11)
       or v_receipt.file_size_bytes <> v_candidate.evidence_size_bytes
       or v_receipt.detected_mime_type <> v_candidate.evidence_mime_type
       or v_receipt.content_sha256 <> v_candidate.evidence_sha256 then
      raise exception 'Acceptance evidence receipt is invalid or expired.';
    end if;
    update iads_private.evidence_receipts set state = 'consumed', consumed_at = clock_timestamp()
     where id = p_accept_receipt_id and state = 'pending';
    if not found then raise exception 'Acceptance receipt was already consumed.'; end if;
  elsif p_accept_receipt_id is not null then
    raise exception 'External URL candidates do not accept Storage receipts.';
  end if;
  v_achievement := jsonb_build_object(
    'id', v_candidate.id::text, 'title', v_candidate.title,
    'category', v_candidate.category, 'date', v_candidate.date,
    'issuer', v_candidate.issuer, 'description', v_candidate.description
  );
  if v_candidate.canonical_storage_ref is not null then
    v_achievement := v_achievement || jsonb_build_object('file', v_candidate.canonical_storage_ref);
  end if;
  v_result := public.au_commit_achievement(
    auth.uid(), 'iads', v_candidate.id, v_achievement, v_candidate.canonical_storage_ref
  );
  v_outcome := v_result ->> 'outcome';
  if v_outcome = 'duplicate' then
    update public.iads_candidates set status = 'duplicate', decided_at = clock_timestamp(),
      updated_at = clock_timestamp() where id = p_candidate_id;
    return jsonb_build_object('outcome','duplicate','verification_id',v_result -> 'verification_id');
  end if;
  v_verification_id := (v_result ->> 'verification_id')::uuid;
  v_profile_updated_at := (v_result ->> 'updated_at')::timestamptz;
  insert into public.iads_achievement_provenance (
    candidate_id, student_id, verification_id, item_id, source_kind, source_url,
    source_storage_ref, canonical_storage_ref, evidence_size_bytes,
    evidence_mime_type, evidence_sha256
  ) values (
    v_candidate.id, auth.uid(), v_verification_id, v_candidate.id::text,
    v_candidate.source_kind, v_candidate.source_url, v_candidate.source_storage_ref,
    v_candidate.canonical_storage_ref, v_candidate.evidence_size_bytes,
    v_candidate.evidence_mime_type, v_candidate.evidence_sha256
  );
  update public.iads_candidates set status = 'accepted', verification_id = v_verification_id,
    decided_at = clock_timestamp(), updated_at = clock_timestamp()
   where id = p_candidate_id;
  return jsonb_build_object(
    'outcome','accepted','verification_id',v_verification_id,
    'achievement',v_achievement,'updated_at',v_profile_updated_at);
end
$function$;

create or replace function public.iads_decline_candidate(p_candidate_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog
as $function$
declare
  v_candidate public.iads_candidates%rowtype;
begin
  if auth.uid() is null then raise exception 'Sign in is required.'; end if;
  perform pg_advisory_xact_lock(hashtextextended(auth.uid()::text, 0));
  select * into v_candidate from public.iads_candidates
   where id = p_candidate_id and student_id = auth.uid() for update;
  if not found then raise exception 'Candidate not found.'; end if;
  if v_candidate.status = 'declined' then return jsonb_build_object('outcome','declined'); end if;
  if v_candidate.status not in ('awaiting_review','awaiting_evidence') then
    raise exception 'This candidate can no longer be declined.';
  end if;
  update public.iads_candidates set status = 'declined',
    decided_at = clock_timestamp(), updated_at = clock_timestamp()
   where id = p_candidate_id;
  return jsonb_build_object('outcome','declined');
end
$function$;

do $grants$
declare
  v_function record;
begin
  for v_function in
    select p.oid::regprocedure as signature
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public' and p.proname like 'iads\_%' escape '\'
  loop
    execute format('revoke all on function %s from public, anon, authenticated, service_role', v_function.signature);
  end loop;
end
$grants$;
grant execute on function public.iads_create_candidate(uuid,text,text,text,text,text,text,text,text) to authenticated;
grant execute on function public.iads_attach_source(uuid,text) to authenticated;
grant execute on function public.iads_update_candidate(uuid,timestamptz,text,text,text,text,text) to authenticated;
grant execute on function public.iads_begin_evidence_operation(uuid,text) to authenticated;
grant execute on function public.iads_finalize_evidence(uuid,uuid) to authenticated;
grant execute on function public.iads_accept_candidate(uuid,uuid,timestamptz) to authenticated;
grant execute on function public.iads_decline_candidate(uuid) to authenticated;
grant execute on function public.iads_record_evidence_receipt(uuid,uuid,uuid,uuid,text,text,text,text,text,text,bigint,text,text,bigint,bytea)
  to service_role;

do $receipt_acl_check$
declare
  v_signature regprocedure := to_regprocedure(
    'public.iads_record_evidence_receipt(uuid,uuid,uuid,uuid,text,text,text,text,text,text,bigint,text,text,bigint,bytea)'
  );
begin
  if has_schema_privilege('service_role','iads_private','USAGE')
     or has_table_privilege('service_role','iads_private.hmac_keys','SELECT')
     or has_table_privilege('service_role','iads_private.hmac_keys','INSERT')
     or has_table_privilege('service_role','iads_private.hmac_keys','UPDATE')
     or has_table_privilege('service_role','iads_private.hmac_keys','DELETE')
     or has_table_privilege('service_role','iads_private.evidence_receipts','SELECT')
     or has_table_privilege('service_role','iads_private.evidence_receipts','INSERT')
     or has_table_privilege('service_role','iads_private.evidence_receipts','UPDATE')
     or has_table_privilege('service_role','iads_private.evidence_receipts','DELETE')
     or has_function_privilege('service_role',
       'iads_private.receipt_payload(text,uuid,uuid,uuid,text,uuid,text,text,text,text,bigint,text,text,bigint)',
       'EXECUTE')
     or has_function_privilege('service_role','iads_private.constant_time_equal(bytea,bytea)','EXECUTE')
     or has_function_privilege('anon',v_signature,'EXECUTE')
     or has_function_privilege('authenticated',v_signature,'EXECUTE')
     or not has_function_privilege('service_role',v_signature,'EXECUTE')
     or not has_table_privilege('iads_receipt_owner','iads_private.hmac_keys','SELECT')
     or not has_table_privilege('iads_receipt_owner','iads_private.evidence_receipts','INSERT') then
    raise exception 'IADS permission check failed: receipt owner or service-role ACLs are unsafe.';
  end if;
end
$receipt_acl_check$;

revoke all on table public.iads_candidates, public.iads_achievement_provenance
  from public, anon, service_role;
revoke insert, update, delete, truncate on table public.iads_candidates,
  public.iads_achievement_provenance from authenticated;
grant select on table public.iads_candidates, public.iads_achievement_provenance to authenticated;
grant select on table public.iads_candidates to iads_receipt_owner;

grant execute on function iads_private.receipt_payload(text,uuid,uuid,uuid,text,uuid,text,text,text,text,bigint,text,text,bigint)
  to iads_receipt_owner;
grant execute on function iads_private.constant_time_equal(bytea,bytea) to iads_receipt_owner;

insert into storage.buckets(id, name, public, file_size_limit, allowed_mime_types)
values ('iads-evidence', 'iads-evidence', false, 5242880,
  array['application/pdf','image/jpeg','image/png','image/webp']::text[])
on conflict (id) do nothing;

create policy iads_evidence_student_select on storage.objects
  for select to authenticated
  using (bucket_id = 'iads-evidence' and (storage.foldername(name))[1] = auth.uid()::text);
create policy iads_evidence_student_insert on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'iads-evidence'
    and (storage.foldername(name))[1] = auth.uid()::text
    and (storage.foldername(name))[2] = 'iads-evidence'
  );
create policy iads_evidence_staff_select on storage.objects
  for select to authenticated
  using (
    bucket_id = 'iads-evidence'
    and case
      when (storage.foldername(name))[1] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      then public.au_can_verify(((storage.foldername(name))[1])::uuid, 'achievement')
      else false
    end
  );
create policy iads_evidence_mfa_fence on storage.objects
  as restrictive for all to authenticated
  using (bucket_id <> 'iads-evidence' or public.au_mfa_verified())
  with check (bucket_id <> 'iads-evidence' or public.au_mfa_verified());
create policy iads_evidence_select_fence on storage.objects
  as restrictive for select to authenticated
  using (
    bucket_id <> 'iads-evidence'
    or (storage.foldername(name))[1] = auth.uid()::text
    or case
      when (storage.foldername(name))[1] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      then public.au_can_verify(((storage.foldername(name))[1])::uuid, 'achievement')
      else false
    end
  );
create policy iads_evidence_insert_fence on storage.objects
  as restrictive for insert to authenticated
  with check (
    bucket_id <> 'iads-evidence'
    or ((storage.foldername(name))[1] = auth.uid()::text
        and (storage.foldername(name))[2] = 'iads-evidence')
  );
create policy iads_evidence_update_fence on storage.objects
  as restrictive for update to authenticated
  using (bucket_id <> 'iads-evidence')
  with check (bucket_id <> 'iads-evidence');
create policy iads_evidence_delete_fence on storage.objects
  as restrictive for delete to authenticated
  using (bucket_id <> 'iads-evidence');

-- Expired receipt rows may be removed by a privileged maintenance process.
-- Evidence objects are deliberately not auto-deleted.
