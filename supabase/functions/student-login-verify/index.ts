
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function respond(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

async function hashCode(code: string) {
  const bytes = new TextEncoder().encode(code);
  const hash = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function getSessionIdFromToken(token: string): string | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;

    const base64 = payload
      .replace(/-/g, "+")
      .replace(/_/g, "/");

    const padded = base64.padEnd(
      Math.ceil(base64.length / 4) * 4,
      "="
    );

    const claims = JSON.parse(atob(padded));
    const id = claims.session_id;

    if (
      typeof id === "string" &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)
    ) {
      return id;
    }

    return null;
  } catch {
    return null;
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return respond(405, { error: "Method not allowed." });
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const resendKey = Deno.env.get("RESEND_API_KEY");

    if (!resendKey) {
      return respond(500, {
        error: "Email service is not configured.",
      });
    }

    const authHeader = req.headers.get("Authorization");

    if (!authHeader?.startsWith("Bearer ")) {
      return respond(401, { error: "Please sign in first." });
    }

    const token = authHeader.replace("Bearer ", "");

    const authClient = createClient(supabaseUrl, anonKey, {
      auth: { persistSession: false },
    });

    const { data: authData, error: authError } =
      await authClient.auth.getUser(token);

    if (authError || !authData.user) {
      return respond(401, {
        error: "Your login session is invalid.",
      });
    }

    const user = authData.user;

    const sessionId = getSessionIdFromToken(token);

    if (!sessionId) {
      return respond(401, {
        error: "Could not identify your login session. Please sign in again.",
      });
    }

    const admin = createClient(supabaseUrl, serviceKey, {
      auth: { persistSession: false },
    });

    const body = await req.json();
    const action = body.action;

    // SEND VERIFICATION CODE
    if (action === "send") {
      if (!user.email) {
        return respond(400, {
          error: "Your account has no email address.",
        });
      }

      const { data: previous, error: previousError } = await admin
        .from("student_login_codes")
        .select("created_at")
        .eq("user_id", user.id)
        .eq("session_id", sessionId)
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (previousError) {
        return respond(500, {
          error: "Could not check your previous verification request.",
        });
      }

      if (
        previous &&
        Date.now() - new Date(previous.created_at).getTime() < 60_000
      ) {
        return respond(429, {
          error: "Please wait one minute before requesting another code.",
        });
      }

      const random = new Uint32Array(1);
      crypto.getRandomValues(random);

      const code = String(random[0] % 1_000_000).padStart(6, "0");

      const codeHash = await hashCode(code);
      const expiresAt = new Date(
        Date.now() + 10 * 60_000
      ).toISOString();

      const { error: deleteError } = await admin
        .from("student_login_codes")
        .delete()
        .eq("user_id", user.id)
        .eq("session_id", sessionId);

      if (deleteError) {
        return respond(500, {
          error: "Could not prepare your verification request.",
        });
      }

      const { error: insertError } = await admin
        .from("student_login_codes")
        .insert({
          user_id: user.id,
          session_id: sessionId,
          code_hash: codeHash,
          expires_at: expiresAt,
        });

      if (insertError) {
        return respond(500, {
          error: "Could not create your verification code.",
        });
      }

      const emailResponse = await fetch(
        "https://api.resend.com/emails",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${resendKey}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            from: "MyAU Verification <onboarding@resend.dev>",
            to: [user.email],
            subject: "Your MyAU verification code",
            html: `<p>Your MyAU verification code is:</p>
                   <h2>${code}</h2>
                   <p>This code expires in 10 minutes. Do not share it with anyone.</p>`,
          }),
        }
      );

      if (!emailResponse.ok) {
        await admin
          .from("student_login_codes")
          .delete()
          .eq("user_id", user.id)
          .eq("session_id", sessionId);

        return respond(502, {
          error: "The email could not be sent. Check your Resend account and recipient address.",
        });
      }

      return respond(200, {
        message: "Verification code sent.",
      });
    }

    // VERIFY SUBMITTED CODE
    if (action === "verify") {
      const submittedCode = String(body.code ?? "").trim();

      if (!/^\d{6}$/.test(submittedCode)) {
        return respond(400, {
          error: "Enter a valid six-digit code.",
        });
      }

      const { data: challenge, error: challengeError } = await admin
        .from("student_login_codes")
        .select("*")
        .eq("user_id", user.id)
        .eq("session_id", sessionId)
        .is("verified_at", null)
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (challengeError || !challenge) {
        return respond(400, {
          error: "No active verification code. Request a new one.",
        });
      }

      if (new Date(challenge.expires_at).getTime() < Date.now()) {
        await admin
          .from("student_login_codes")
          .delete()
          .eq("id", challenge.id);

        return respond(400, {
          error: "Your code has expired. Request a new one.",
        });
      }

      if (challenge.attempts >= 5) {
        await admin
          .from("student_login_codes")
          .delete()
          .eq("id", challenge.id);

        return respond(429, {
          error: "Too many attempts. Request a new code.",
        });
      }

      const submittedHash = await hashCode(submittedCode);

      if (submittedHash !== challenge.code_hash) {
        await admin
          .from("student_login_codes")
          .update({ attempts: challenge.attempts + 1 })
          .eq("id", challenge.id);

        return respond(400, {
          error: "Incorrect verification code.",
        });
      }

      const { error: updateError } = await admin
        .from("student_login_codes")
        .update({ verified_at: new Date().toISOString() })
        .eq("id", challenge.id);

      if (updateError) {
        return respond(500, {
          error: "Could not complete verification.",
        });
      }

      return respond(200, {
        message: "Email verification successful.",
      });
    }

    return respond(400, { error: "Unknown action." });

  } catch (error) {
    console.error("Student login verification error:", error);

    return respond(500, {
      error: "An unexpected error occurred.",
    });
  }
});

