// Supabase Edge Function "pocketbook-login": log in with a username + PIN.
// It finds the email for that username on the server, so the app never sees anyone else's email.
// Deploy: Supabase → Edge Functions → Deploy a new function → Via Editor → name it  pocketbook-login
// then turn OFF "Verify JWT" (Enforce JWT verification) in the function's settings.
import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "https://mypocketbook.github.io",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method" }, 405);
  try {
    const { login, pin } = await req.json();
    const username = String(login || "").trim().toLowerCase();
    if (!/^[a-z0-9_.]{3,20}$/.test(username) || !pin) return json({ error: "wrong" }, 401);

    const url = Deno.env.get("SUPABASE_URL")!;
    const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });
    const publicKey = Deno.env.get("SUPABASE_ANON_KEY") || "sb_publishable_FDBCMDIQlD2ALD1e892beQ_LHtSdBcL";
    const anon = createClient(url, publicKey, { auth: { persistSession: false } });

    const { data: row } = await admin.from("pocketbook_usernames").select("user_id").eq("username", username).maybeSingle();
    if (!row) return json({ error: "wrong" }, 401);
    const { data: u } = await admin.auth.admin.getUserById(row.user_id);
    const email = u?.user?.email;
    if (!email) return json({ error: "wrong" }, 401);

    const { data, error } = await anon.auth.signInWithPassword({ email, password: String(pin) });
    if (error || !data.session) return json({ error: "wrong" }, 401);   // same answer for any mistake
    return json({ access_token: data.session.access_token, refresh_token: data.session.refresh_token });
  } catch (_e) {
    return json({ error: "bad request" }, 400);
  }
});
