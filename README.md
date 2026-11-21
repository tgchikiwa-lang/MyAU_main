# MyAU – Africa University portal setup

1. In Supabase SQL Editor, run `backend/migrations/0008_records_verification_finance.sql`,
   `backend/migrations/0009_result_verification.sql`, `backend/migrations/0010_recommendation_letters.sql`,
   `backend/migrations/0011_lecturer_sharing_and_achievement_history.sql`,
   `backend/migrations/0012_official_results_scoped_verifiers_alumni.sql`,
   `backend/migrations/0013_queue_unmatched_alumni_requests.sql`, and
   `backend/migrations/0014_disambiguate_alumni_email.sql`, in that order. Migration 0008
   assumes migration 0007 and existing owner-scoped `profiles` policies are installed.
2. The supplied images `assets/images/au_1.jpg` and `assets/images/au_3.jpg` are used for login backgrounds
   and the homepage hero, respectively.
3. Create Records/Admin roles in Supabase SQL Editor only; never expose a service-role key in browser code:
   ```sql
   update auth.users
      set raw_app_meta_data = coalesce(raw_app_meta_data,'{}'::jsonb) || '{"role":"records"}'
    where email = 'records.officer@example.com';   -- use "admin" for administrators
   ```
   The person signs out and in again afterwards.
4. Deploy `js/app.js`, `js/staff.js`, `js/lecturer.js`, `js/alumni.js`, the pages, Edge Function, and migrations.
   `js/config.js` is unchanged. Optional: add `currency: "USD"` to `config.js`.
5. Storage: club pictures, ID photos and certificates use the existing private `student-content` bucket and
   the same `<user id>/…` folder rule used by CV uploads. Migration 0010 adds recommendation-letter policies.

Students can select verified projects, achievements, and clubs when requesting a recommendation. Only those
selected snapshots are shared with the exact referee email after email-link sign-in; access expires within 90
days and students can revoke it. From a saved request, students can send a Supabase secure sign-in link directly
to the referee. After one click, the link signs the lecturer in and opens the lecturer workspace. Add the deployed
`pages/lecturer.html` URL to Supabase Authentication's allowed redirect URLs and enable email-link sign-in. If
lecturers do not already have Auth accounts, allow email sign-up; otherwise pre-create their Auth accounts.
Lecturers can edit a summary based on the selected items and track their own status. Lecturer access is logged,
and overdue requests are flagged in the lecturer workspace. Scheduled email reminders require a separately
deployed, secured email/Edge Function; the static site does not send them.

Official course results are stored separately from student profiles. Students can only view results tied to
their own authenticated account. Before results or verifier access are assigned, Records must link each official
student number to an Auth user UUID in the protected student registry after checking university records and
recording the source checked; editable profile numbers are not trusted for these mappings. Get the Auth UUID
from the Supabase Auth users list. Records can add results manually or import a CSV with the
exact required headers `student_id,course_code,course,grade,semester`. Here `student_id` is the official number
in the verified registry. Imports accept up to 1,000 rows. Re-importing the same student, course code, and semester
updates the result and records the prior values in history. Existing student-entered grades are not copied into
the official table.

Administrators can assign verifier access from the Admin console. An assignment is bound to the verifier's
Supabase Auth user UUID and an explicit list of student numbers and item categories (projects, achievements,
clubs/activities). Database RLS enforces those limits even for direct API access. Remove the assignment to
revoke it. Verifiers use the Staff sign-in page but do not receive Records/Admin permissions.

Alumni can request an account email change from the sign-in page using their student number, current university
email, and personal email. The request does not reveal whether the account exists and does not grant access.
Records must check the university records and enter an identity-check note before approving; MyAU does not
collect identity documents. Approval requests an Auth email change and sends a confirmation message to the
personal address; the university email remains the login until that confirmation succeeds. Enable Supabase
email confirmations and configure the deployed site as its Auth Site URL so Supabase sends a verification link
to the new address. The student profile email is refreshed from the confirmed Auth email on their next sign-in.
Deploy the server function with the Supabase CLI:

```powershell
supabase functions deploy alumni-access --project-ref mrkgziygjbknujsesvta
```

The function uses server-side Supabase environment secrets. Never copy a service-role key into browser code or
the static site. Alumni requests appear in the Staff console's Alumni access tab; the current workflow does not
send email alerts to Records. Migration 0013 ensures requests still reach the Records queue when the student
number and university email have not yet been linked to an Auth account. Before approval, Records must add
that verified student-number link with the exact university email from the request.

Student achievements include the university-approved category (Academic, Leadership, Research, Community
Service, Sports, Arts & Culture, Other), date, issuer, and description. Existing achievements remain visible;
their old verification remains recognized until a Records-reviewed change or a new verification request.

## Local review and IADS preview

This repository is a static site; it has no `package.json` build or local backend. From the repository root,
serve it with Python:

```powershell
python -m http.server 8000 --bind 127.0.0.1
```

Open `http://127.0.0.1:8000/` for the landing page. The signed-in IADS page is
`http://127.0.0.1:8000/pages/iads.html`; it requires a valid Supabase session and the IADS backend described
below. The signed-in portal navigation includes IADS.

For an offline group walkthrough, open
`http://127.0.0.1:8000/pages/iads-preview.html`. This opt-in, read-only page uses fictional sample content,
has inert controls, and loads no application or Supabase JavaScript. It cannot create or submit records. It
demonstrates the IADS layout only, not the live workflow.

The browser configuration is already present in `js/config.js`; no `.env` file or build step is used by the
static preview. The actual workflow connects to the configured Supabase project. Do not open its signed-in
route for an offline-only demonstration. For interactive local testing, use a team staging project; never
point the student UI at production.

## IADS MVP

IADS is available from the signed-in student navigation. Certificate uploads use the existing private
`student-content` bucket as the student-owned source and a separate private `iads-evidence` bucket for the
canonical copy. External HTTPS URLs are stored only as provenance; verification evidence contains only
private `storage://` references. Accepted achievements use the existing pending `verifications` workflow.
Staff review remains in the existing Records queue; authorized reviewers see an external source link from
the protected provenance record or a short-lived signed URL for canonical evidence.

Before applying the additive IADS migrations, reconcile the live Supabase migration ledger with the live
catalog; the local migration filenames do not prove which migrations are deployed. Apply
`backend/migrations/0016_achievement_mutation_boundary.sql` and then
`backend/migrations/0017_iads_mvp.sql` only after their preflight blocks pass. Do not edit or rerun earlier
MyAU migrations to make the IADS migration pass. The migrations abort on incompatible profiles,
verification objects, triggers, authorization helpers, Storage setup, cryptographic extension, or role
attributes.

The database migration creates an empty private HMAC key table and the non-login `iads_receipt_owner` role.
Before deploying `supabase/functions/iads-evidence`, provision one random 32-byte HMAC key through an
approved protected operations channel: store it in `iads_private.hmac_keys` as the matching key ID and
provide the same key ID and base64-encoded key to the Edge Function as
`IADS_HMAC_KEY_ID` and `IADS_HMAC_KEY_B64`. Also configure the function's normal Supabase URL, anon key,
and server-side service-role key. Never put key material in this repository, a migration, browser config,
or a browser request; never use the service-role client for Storage. The function validates Storage bytes
through the student's JWT and uses its service-role client only for the signed receipt RPC.

Deploy the Edge Function only after applying both migrations and provisioning the same key on each side.
Until that configuration exists, evidence validation fails closed. Keep canonical evidence and abandoned
candidate copies until an institutional retention period is approved; do not enable automatic object cleanup.
The profile mutation RPCs serialize achievement writes and reject stale full-profile saves so IADS acceptance
cannot silently overwrite a concurrent MyAU save.

Do not apply these migrations to production before the staging migrations, receipt/Storage authorization,
concurrency, and workflow tests have passed. A local static preview does not validate any backend behavior.

Validate the hash implementation in an isolated staging database with
`node tests/iads-hash-vectors.mjs` after applying migration 0016 there. Before production, also test concurrent
manual/IADS submissions for one student, idempotency-key reuse with identical and changed inputs, receipt
expiry/replay, service-role denial of private key/table access, student Storage ownership and immutability,
staff MFA/scoped evidence access, and that recommendation eligibility remains limited to verified items.

The Records console includes a queue for verified-achievement correction/deletion requests. Direct edits and
removals of unchanged verified projects, achievements, and clubs are blocked. Approved changes supersede the
old verification and are recorded in the student's history.

Projects are sent to the Records verification queue when saved. The Results page only displays official data
supplied by Records; it does not issue an official transcript. The digital student ID QR code is generated in the browser and contains
only the student ID. Records can add an assessment and upload the referee's signed recommendation letter as a
PDF; only the request's student and Records staff can access that private letter.
