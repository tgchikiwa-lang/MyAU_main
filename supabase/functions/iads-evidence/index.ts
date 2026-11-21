import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const MAX_BYTES = 5 * 1024 * 1024;
const MIME_EXTENSION: Record<string, string> = {
  "application/pdf": "pdf",
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/webp": "webp",
};

function respond(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function uuid(value: unknown): value is string {
  return typeof value === "string"
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function bytesMatch(data: Uint8Array, mime: string) {
  if (mime === "application/pdf") return new TextDecoder().decode(data.subarray(0, 5)) === "%PDF-";
  if (mime === "image/jpeg") return data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff;
  if (mime === "image/png") return [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a].every((b, i) => data[i] === b);
  if (mime === "image/webp") {
    return new TextDecoder().decode(data.subarray(0, 4)) === "RIFF"
      && new TextDecoder().decode(data.subarray(8, 12)) === "WEBP";
  }
  return false;
}

function detectMime(data: Uint8Array) {
  for (const mime of Object.keys(MIME_EXTENSION)) if (bytesMatch(data, mime)) return mime;
  throw new Error("The uploaded bytes are not a supported PDF, JPEG, PNG, or WebP certificate.");
}

async function sha256(data: Uint8Array) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  return [...digest].map(value => value.toString(16).padStart(2, "0")).join("");
}

function uuidBytes(uuidValue: string) {
  return uuidValue.toLowerCase();
}

function canonicalReceipt(
  keyId: string,
  receiptId: string,
  studentId: string,
  candidateId: string,
  purpose: string,
  operationId: string,
  sourceBucket: string,
  sourcePath: string,
  canonicalBucket: string,
  canonicalPath: string,
  size: number,
  mime: string,
  hash: string,
  expiresMs: number,
) {
  const fields = [
    keyId, uuidBytes(receiptId), uuidBytes(studentId), uuidBytes(candidateId),
    purpose, uuidBytes(operationId), sourceBucket, sourcePath, canonicalBucket,
    canonicalPath, String(size), mime.toLowerCase(), hash.toLowerCase(), String(expiresMs),
  ];
  const encoder = new TextEncoder();
  const chunks = [
    encoder.encode("IADS-RECEIPT"),
    new Uint8Array([0, 1]),
  ];
  for (const field of fields) {
    const bytes = encoder.encode(field);
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, bytes.byteLength, false);
    chunks.push(length, bytes);
  }
  const total = chunks.reduce((n, item) => n + item.byteLength, 0);
  const payload = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    payload.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return payload;
}

async function signReceipt(payload: Uint8Array) {
  const encoded = Deno.env.get("IADS_HMAC_KEY_B64");
  if (!encoded) throw new Error("IADS evidence validation is not configured on the server.");
  let raw: Uint8Array;
  try {
    raw = Uint8Array.from(atob(encoded), character => character.charCodeAt(0));
  } catch {
    throw new Error("IADS evidence validation key configuration is invalid.");
  }
  if (raw.byteLength !== 32) throw new Error("IADS evidence validation key configuration is invalid.");
  const key = await crypto.subtle.importKey(
    "raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, payload));
  raw.fill(0);
  return signed;
}

function fromStorageRef(ref: unknown, userId: string) {
  if (typeof ref !== "string" || !ref.startsWith(`storage://${userId}/`)) {
    throw new Error("The candidate evidence reference is invalid.");
  }
  return ref.slice("storage://".length);
}

function sameBytes(left: Uint8Array, right: Uint8Array) {
  if (left.byteLength !== right.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < left.byteLength; i++) diff |= left[i] ^ right[i];
  return diff === 0;
}

async function downloadObject(userClient: ReturnType<typeof createClient>, bucket: string, path: string) {
  const { data, error } = await userClient.storage.from(bucket).download(path);
  if (error) {
    if (/object not found/i.test(error.message)) return null;
    throw new Error(`Evidence could not be read through the signed-in student's Storage access: ${error.message}`);
  }
  if (!data) throw new Error("Storage returned no evidence bytes.");
  const bytes = new Uint8Array(await data.arrayBuffer());
  if (!bytes.byteLength || bytes.byteLength > MAX_BYTES) {
    throw new Error("Evidence must be between 1 byte and 5 MB.");
  }
  const mime = detectMime(bytes);
  return { bytes, mime, hash: await sha256(bytes) };
}

async function recordReceipt(
  serviceClient: ReturnType<typeof createClient>,
  candidate: Record<string, unknown>,
  studentId: string,
  purpose: "submit" | "accept",
  operationId: string,
  expiresMs: number,
  sourcePath: string,
  canonicalPath: string,
  size: number,
  mime: string,
  hash: string,
) {
  const keyId = Deno.env.get("IADS_HMAC_KEY_ID");
  if (!keyId || !uuid(candidate.id)) throw new Error("IADS evidence validation is not configured on the server.");
  const signature = await signReceipt(canonicalReceipt(
    keyId, operationId, studentId, candidate.id, purpose, operationId,
    "student-content", sourcePath, "iads-evidence", canonicalPath,
    size, mime, hash, expiresMs,
  ));
  const { data, error } = await serviceClient.rpc("iads_record_evidence_receipt", {
    p_receipt_id: operationId,
    p_operation_id: operationId,
    p_student_id: studentId,
    p_candidate_id: candidate.id,
    p_purpose: purpose,
    p_key_id: keyId,
    p_source_bucket: "student-content",
    p_source_path: sourcePath,
    p_canonical_bucket: "iads-evidence",
    p_canonical_path: canonicalPath,
    p_file_size_bytes: size,
    p_detected_mime_type: mime,
    p_content_sha256: hash,
    p_expires_ms: expiresMs,
    p_signature: `\\x${[...signature].map(b => b.toString(16).padStart(2, "0")).join("")}`,
  });
  if (error) throw new Error(`Evidence receipt could not be recorded: ${error.message}`);
  return String(data);
}

Deno.serve(async request => {
  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (request.method !== "POST") return respond(405, { error: "POST is required." });
  try {
    const url = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const authorization = request.headers.get("Authorization");
    if (!url || !anonKey || !serviceKey) {
      return respond(500, { error: "IADS evidence validation is not configured on the server." });
    }
    if (!authorization?.startsWith("Bearer ")) return respond(401, { error: "Sign in is required." });

    let payload: Record<string, unknown>;
    try {
      payload = await request.json();
    } catch {
      return respond(400, { error: "A valid JSON request is required." });
    }
    if (!uuid(payload.candidate_id) || !["validate", "accept"].includes(String(payload.action))) {
      return respond(400, { error: "A valid candidate and action are required." });
    }

    const userClient = createClient(url, anonKey, {
      auth: { persistSession: false },
      global: { headers: { Authorization: authorization } },
    });
    const { data: authData, error: authError } = await userClient.auth.getUser();
    if (authError || !authData.user) return respond(401, { error: "The student session is invalid or expired." });
    const studentId = authData.user.id;

    const { data: candidateRow, error: candidateError } = await userClient
      .from("iads_candidates").select("*").eq("id", payload.candidate_id).maybeSingle();
    if (candidateError) throw new Error(`Candidate could not be loaded: ${candidateError.message}`);
    if (!candidateRow || candidateRow.student_id !== studentId) {
      return respond(404, { error: "Candidate not found." });
    }
    const candidate = candidateRow as Record<string, unknown>;
    if (payload.action === "accept" && candidate.status === "accepted") {
      return respond(200, { outcome: "accepted", verification_id: candidate.verification_id });
    }
    if (candidate.source_kind !== "upload") {
      return respond(400, { error: "This candidate does not require file validation." });
    }

    const sourcePath = fromStorageRef(candidate.source_storage_ref, studentId);
    if (sourcePath !== `${studentId}/iads-source/${candidate.id}`) {
      return respond(409, { error: "The source evidence path does not match this candidate." });
    }
    const serviceClient = createClient(url, serviceKey, { auth: { persistSession: false } });

    if (payload.action === "validate") {
      if (candidate.status === "awaiting_review") {
        return respond(200, { outcome: "validated", candidate_id: candidate.id });
      }
      if (candidate.status !== "awaiting_evidence") {
        return respond(409, { error: "This candidate is not awaiting evidence." });
      }
      const source = await downloadObject(userClient, "student-content", sourcePath);
      if (!source) return respond(409, { error: "Upload the certificate before validating this candidate." });
      if (candidate.requested_evidence_sha256 !== source.hash) {
        return respond(409, { error: "The uploaded certificate differs from the file used to create this request." });
      }
      const canonicalPath = `${studentId}/iads-evidence/${candidate.id}.${MIME_EXTENSION[source.mime]}`;
      const currentCanonical = await downloadObject(userClient, "iads-evidence", canonicalPath);
      if (currentCanonical) {
        if (currentCanonical.mime !== source.mime || currentCanonical.hash !== source.hash
            || !sameBytes(currentCanonical.bytes, source.bytes)) {
          return respond(409, { error: "The existing canonical evidence differs; it was not overwritten." });
        }
      } else {
        const { error: uploadError } = await userClient.storage.from("iads-evidence").upload(
          canonicalPath, new Blob([source.bytes], { type: source.mime }),
          { contentType: source.mime, upsert: false },
        );
        if (uploadError) {
          const retriedCanonical = await downloadObject(userClient, "iads-evidence", canonicalPath);
          if (!retriedCanonical || retriedCanonical.mime !== source.mime
              || retriedCanonical.hash !== source.hash
              || !sameBytes(retriedCanonical.bytes, source.bytes)) {
            throw new Error(`Canonical evidence upload failed: ${uploadError.message}`);
          }
        }
      }
      const { data: operationData, error: operationError } = await userClient.rpc(
        "iads_begin_evidence_operation",
        { p_candidate_id: candidate.id, p_purpose: "submit" },
      );
      if (operationError) throw new Error(`Evidence operation could not start: ${operationError.message}`);
      const operation = Array.isArray(operationData) ? operationData[0] : operationData;
      if (!operation || !uuid(operation.operation_id)) throw new Error("Evidence operation returned an invalid receipt context.");
      const receiptId = await recordReceipt(
        serviceClient, candidate, studentId, "submit", operation.operation_id,
        Number(operation.expires_ms), sourcePath, canonicalPath,
        source.bytes.byteLength, source.mime, source.hash,
      );
      const { error: finalizeError } = await userClient.rpc("iads_finalize_evidence", {
        p_candidate_id: candidate.id, p_receipt_id: receiptId,
      });
      if (finalizeError) throw new Error(`Evidence was validated but could not be attached: ${finalizeError.message}`);
      return respond(200, { outcome: "validated", candidate_id: candidate.id });
    }

    if (candidate.status !== "awaiting_review" || typeof candidate.canonical_storage_ref !== "string") {
      return respond(409, { error: "This candidate is not ready for acceptance." });
    }
    const canonicalPath = fromStorageRef(candidate.canonical_storage_ref, studentId);
    const canonical = await downloadObject(userClient, "iads-evidence", canonicalPath);
    if (!canonical || canonical.bytes.byteLength !== candidate.evidence_size_bytes
        || canonical.mime !== candidate.evidence_mime_type
        || canonical.hash !== candidate.evidence_sha256) {
      return respond(409, { error: "Canonical evidence no longer matches the validated receipt." });
    }
    const { data: operationData, error: operationError } = await userClient.rpc(
      "iads_begin_evidence_operation",
      { p_candidate_id: candidate.id, p_purpose: "accept" },
    );
    if (operationError) throw new Error(`Acceptance evidence operation could not start: ${operationError.message}`);
    const operation = Array.isArray(operationData) ? operationData[0] : operationData;
    if (!operation || !uuid(operation.operation_id)) throw new Error("Acceptance operation returned an invalid receipt context.");
    const receiptId = await recordReceipt(
      serviceClient, candidate, studentId, "accept", operation.operation_id,
      Number(operation.expires_ms), sourcePath, canonicalPath,
      canonical.bytes.byteLength, canonical.mime, canonical.hash,
    );
    return respond(200, { outcome: "validated", receipt_id: receiptId });
  } catch (error) {
    return respond(400, { error: error instanceof Error ? error.message : "Evidence validation failed." });
  }
});
