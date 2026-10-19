// موقع دفع مع تسجيل دخول ديسكورد ولوحة تحكم - Cloudflare Worker (ملف واحد)
//
// من لوحة Cloudflare (Settings ثم Variables and Secrets) بتحط بس هدول الأربعة:
//   DISCORD_CLIENT_ID      رقم التطبيق من Discord Developer Portal
//   DISCORD_CLIENT_SECRET  السر (Secret) من نفس الصفحة
//   ADMIN_ID               الـ Discord User ID تبعك (إنت المالك)
//   SESSION_SECRET         أي نص عشوائي طويل (30 حرف أو أكثر)
// والربط (Binding) من نوع KV باسم: STORE
// أي شي ثاني (طرق الدفع، بايبال، PayTabs، المسؤولين، إشعار ديسكورد) بتحطه من لوحة التحكم /admin

const enc = new TextEncoder();
const dec = new TextDecoder();
const MASK = "••••••";
const DEFAULT_PAYTABS_BASE = "https://secure-jordan.paytabs.com";

const DEFAULT_CONFIG = {
  storeName: "اسم متجرك",
  currency: "دينار",
  afterNote: "رح نتأكد من الدفع ونتواصل معك على ديسكورد.",
  discordWebhook: "",
  admins: [],
  methods: [
    { id: "m1", type: "manual", name: "كليك CliQ", hint: "تحويل فوري", note: "حوّل من تطبيق البنك على الاسم المستعار.",
      fields: [{ k: "الاسم المستعار", v: "YOURNAME" }, { k: "اسم المستلم", v: "اسمك الكامل" }],
      rate: 1, gwCurrency: "USD", gw: {} }
  ]
};

// ---------- أدوات ----------
function toB64u(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64u(str) {
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
async function sign(secret, data) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toB64u(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(data))));
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function getCookie(request, name) {
  const c = request.headers.get("Cookie") || "";
  for (const part of c.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}
function cookie(name, value, maxAge) {
  return name + "=" + value + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" + maxAge;
}
const SEC = { "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "frame-ancestors 'none'", "Referrer-Policy": "same-origin" };
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...SEC } });
}
function page(body) {
  return new Response(body, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...SEC } });
}
function redirect(to, cookies = [], status = 302) {
  const h = new Headers({ Location: to, ...SEC });
  for (const c of cookies) h.append("Set-Cookie", c);
  return new Response(null, { status, headers: h });
}
function clip(v, n) {
  return String(v == null ? "" : v).slice(0, n);
}
function newId() {
  return toB64u(crypto.getRandomValues(new Uint8Array(6)));
}

async function makeSession(env, user) {
  const payload = toB64u(enc.encode(JSON.stringify({ id: user.id, name: user.name, exp: Date.now() + 7 * 864e5 })));
  return payload + "." + (await sign(env.SESSION_SECRET, payload));
}
async function getSession(request, env) {
  const raw = getCookie(request, "s");
  if (!raw) return null;
  const [payload, sig] = raw.split(".");
  if (!payload || !sig) return null;
  if (!safeEqual(sig, await sign(env.SESSION_SECRET, payload))) return null;
  try {
    const s = JSON.parse(dec.decode(fromB64u(payload)));
    return s.exp > Date.now() ? s : null;
  } catch (e) {
    return null;
  }
}
async function loadConfig(env) {
  const c = await env.STORE.get("config", "json");
  return c ? { ...DEFAULT_CONFIG, ...c, admins: c.admins || [], methods: c.methods || [] } : DEFAULT_CONFIG;
}
function isOwnerId(env, id) {
  return id === String(env.ADMIN_ID).trim();
}
function isAdminId(env, cfg, id) {
  return isOwnerId(env, id) || cfg.admins.some((a) => a.id === id);
}
function publicConfig(cfg) {
  return {
    storeName: cfg.storeName,
    currency: cfg.currency,
    afterNote: cfg.afterNote,
    methods: cfg.methods.map((m) => ({
      id: m.id, type: m.type, name: m.name, hint: m.hint, note: m.note,
      fields: m.type === "manual" ? m.fields : [], rate: m.rate, gwCurrency: m.gwCurrency
    }))
  };
}
function maskedConfig(cfg) {
  const c = JSON.parse(JSON.stringify(cfg));
  if (c.discordWebhook) c.discordWebhook = MASK;
  for (const m of c.methods) {
    if (m.gw && m.gw.secret) m.gw.secret = MASK;
    if (m.gw && m.gw.serverKey) m.gw.serverKey = MASK;
  }
  return c;
}
function cleanConfig(b, old, owner) {
  const keep = (v, o) => (v === MASK ? o || "" : clip(v, 300).trim());
  const methods = (Array.isArray(b.methods) ? b.methods : []).slice(0, 12).map((m) => {
    const type = ["manual", "paypal", "paytabs"].includes(m.type) ? m.type : "manual";
    const id = /^[\w-]{1,20}$/.test(String(m.id || "")) ? String(m.id) : newId();
    const o = (old.methods || []).find((x) => x.id === id) || { gw: {} };
    const g = m.gw || {};
    const og = o.gw || {};
    const gw = {};
    if (type === "paypal") {
      gw.clientId = clip(g.clientId, 200).trim();
      gw.secret = keep(g.secret, og.secret);
      gw.mode = g.mode === "live" ? "live" : "sandbox";
    }
    if (type === "paytabs") {
      gw.profileId = clip(g.profileId, 20).trim();
      gw.serverKey = keep(g.serverKey, og.serverKey);
      const base = clip(g.baseUrl, 100).trim().replace(/\/+$/, "");
      gw.baseUrl = /^https:\/\/[a-z0-9.-]+\.paytabs\.(com|sa)$/.test(base) ? base : DEFAULT_PAYTABS_BASE;
    }
    const rate = Number(m.rate);
    return {
      id, type,
      name: clip(m.name, 40).trim(),
      hint: clip(m.hint, 40).trim(),
      note: clip(m.note, 200).trim(),
      fields: type === "manual" ? (Array.isArray(m.fields) ? m.fields : []).slice(0, 8).map((f) => ({ k: clip(f.k, 40), v: clip(f.v, 120) })).filter((f) => f.k || f.v) : [],
      rate: rate > 0 && rate < 1e6 ? rate : 1,
      gwCurrency: (clip(m.gwCurrency, 3).toUpperCase().match(/^[A-Z]{3}$/) || ["USD"])[0],
      gw
    };
  }).filter((m) => m.name);
  let admins = old.admins || [];
  if (owner) {
    admins = (Array.isArray(b.admins) ? b.admins : []).slice(0, 20)
      .map((a) => ({ id: clip(a.id, 25).trim(), name: clip(a.name, 40).trim() }))
      .filter((a) => /^\d{5,25}$/.test(a.id));
  }
  const hook = keep(b.discordWebhook, old.discordWebhook);
  return {
    storeName: clip(b.storeName, 60).trim() || "متجري",
    currency: clip(b.currency, 20).trim() || "دينار",
    afterNote: clip(b.afterNote, 200).trim(),
    discordWebhook: /^https:\/\/(discord|discordapp)\.com\/api\/webhooks\//.test(hook) ? hook : "",
    admins,
    methods
  };
}

function notify(env, ctx, cfg, text) {
  if (!cfg.discordWebhook) return;
  const users = [String(env.ADMIN_ID).trim()].concat(cfg.admins.map((a) => a.id));
  ctx.waitUntil(fetch(cfg.discordWebhook, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content: "<@" + String(env.ADMIN_ID).trim() + "> " + text, allowed_mentions: { users } })
  }).catch(() => {}));
}
function orderText(title, o) {
  return title + "\nالمشتري: " + o.buyerName + " (<@" + o.buyerId + ">)\nالمنتج: " + o.item +
    "\nالمبلغ: " + o.amount + "\nالطريقة: " + o.method +
    (o.payAmount && o.methodType !== "manual" ? "\nالمدفوع: " + o.payAmount + " " + o.payCurrency : "") +
    (o.ref ? "\nرقم العملية: " + o.ref : "");
}

// ---------- تسجيل الدخول ----------
function login(url, env) {
  const state = toB64u(crypto.getRandomValues(new Uint8Array(18)));
  const q = new URLSearchParams({
    client_id: env.DISCORD_CLIENT_ID,
    response_type: "code",
    redirect_uri: url.origin + "/callback",
    scope: "identify",
    state,
    prompt: "none"
  });
  return redirect("https://discord.com/oauth2/authorize?" + q, [cookie("st", state, 600)]);
}
async function callback(request, url, env) {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state || state !== getCookie(request, "st")) {
    return page("<p dir='rtl'>فشل تسجيل الدخول. <a href='/login'>جرّب مرة ثانية</a></p>");
  }
  const tok = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "DiscordBot (payment-site, 1.0)" },
    body: new URLSearchParams({
      grant_type: "authorization_code", code, redirect_uri: url.origin + "/callback",
      client_id: env.DISCORD_CLIENT_ID, client_secret: env.DISCORD_CLIENT_SECRET
    })
  });
  if (!tok.ok) return page("<p dir='rtl'>ديسكورد رفض الطلب. تأكد من الـ Client Secret ومن رابط الـ Redirect. <a href='/login'>جرّب مرة ثانية</a></p>");
  const { access_token } = await tok.json();
  const me = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: "Bearer " + access_token, "User-Agent": "DiscordBot (payment-site, 1.0)" }
  });
  if (!me.ok) return page("<p dir='rtl'>ما قدرت أجيب بيانات حسابك من ديسكورد.</p>");
  const u = await me.json();
  const s = await makeSession(env, { id: u.id, name: clip(u.global_name || u.username, 60) });
  return redirect("/", [cookie("s", s, 604800), cookie("st", "", 0)]);
}

// ---------- بوابات الدفع ----------
function ppBase(g) {
  return g.mode === "live" ? "https://api-m.paypal.com" : "https://api-m.sandbox.paypal.com";
}
async function ppToken(g) {
  const r = await fetch(ppBase(g) + "/v1/oauth2/token", {
    method: "POST",
    headers: { Authorization: "Basic " + btoa(g.clientId + ":" + g.secret), "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials"
  });
  if (!r.ok) throw new Error("paypal auth");
  return (await r.json()).access_token;
}
async function startPaypal(m, order, origin, storeName) {
  const g = m.gw;
  const t = await ppToken(g);
  const r = await fetch(ppBase(g) + "/v2/checkout/orders", {
    method: "POST",
    headers: { Authorization: "Bearer " + t, "Content-Type": "application/json" },
    body: JSON.stringify({
      intent: "CAPTURE",
      purchase_units: [{ reference_id: order.id, description: order.item.slice(0, 120), amount: { currency_code: order.payCurrency, value: order.payAmount.toFixed(2) } }],
      application_context: {
        brand_name: storeName.slice(0, 60), user_action: "PAY_NOW", shipping_preference: "NO_SHIPPING",
        return_url: origin + "/paid/paypal?oid=" + order.id, cancel_url: origin + "/?canceled=1"
      }
    })
  });
  if (!r.ok) throw new Error("paypal order");
  const d = await r.json();
  const link = (d.links || []).find((l) => l.rel === "approve" || l.rel === "payer-action");
  if (!link) throw new Error("paypal link");
  return { url: link.href, ref: d.id };
}
async function capturePaypal(m, order, token) {
  if (!token || token !== order.gwRef) return false;
  const g = m.gw;
  const t = await ppToken(g);
  const r = await fetch(ppBase(g) + "/v2/checkout/orders/" + encodeURIComponent(token) + "/capture", {
    method: "POST", headers: { Authorization: "Bearer " + t, "Content-Type": "application/json" }, body: "{}"
  });
  let d = await r.json().catch(() => ({}));
  if (!r.ok) {
    const g2 = await fetch(ppBase(g) + "/v2/checkout/orders/" + encodeURIComponent(token), { headers: { Authorization: "Bearer " + t } });
    d = await g2.json().catch(() => ({}));
  }
  return d.status === "COMPLETED";
}
async function startPaytabs(m, order, origin) {
  const g = m.gw;
  const back = origin + "/paid/paytabs?oid=" + order.id;
  const r = await fetch(g.baseUrl + "/payment/request", {
    method: "POST",
    headers: { authorization: g.serverKey, "content-type": "application/json" },
    body: JSON.stringify({
      profile_id: Number(g.profileId), tran_type: "sale", tran_class: "ecom",
      cart_id: order.id, cart_currency: order.payCurrency, cart_amount: order.payAmount,
      cart_description: order.item.slice(0, 120), return: back, callback: back
    })
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || !d.redirect_url) throw new Error("paytabs request");
  return { url: d.redirect_url, ref: d.tran_ref };
}
async function verifyPaytabs(m, order) {
  const g = m.gw;
  if (!order.gwRef) return false;
  const r = await fetch(g.baseUrl + "/payment/query", {
    method: "POST",
    headers: { authorization: g.serverKey, "content-type": "application/json" },
    body: JSON.stringify({ profile_id: Number(g.profileId), tran_ref: order.gwRef })
  });
  const d = await r.json().catch(() => ({}));
  const st = d.payment_result && d.payment_result.response_status;
  return st === "A" && (!d.cart_id || d.cart_id === order.id);
}

async function paidReturn(request, env, ctx, url, kind) {
  const oid = url.searchParams.get("oid") || "";
  if (!/^[\w-]+$/.test(oid)) return redirect("/");
  let order = await env.STORE.get("order:" + oid, "json");
  if (!order) return redirect("/?canceled=1", [], 303);
  const cfg = await loadConfig(env);
  const m = cfg.methods.find((x) => x.id === order.methodId);
  let ok = order.status === "paid";
  if (!ok && m && order.status === "pending" && order.methodType === kind) {
    try {
      ok = kind === "paypal" ? await capturePaypal(m, order, url.searchParams.get("token")) : await verifyPaytabs(m, order);
    } catch (e) {
      ok = false;
    }
    if (ok) {
      const fresh = await env.STORE.get("order:" + oid, "json");
      if (fresh && fresh.status !== "paid") {
        order = { ...fresh, status: "paid", paidAt: Date.now() };
        await env.STORE.put("order:" + oid, JSON.stringify(order));
        notify(env, ctx, cfg, orderText("تم الدفع بنجاح", order));
      }
    }
  }
  if (request.method === "POST" && (request.headers.get("content-type") || "").includes("json")) return json({ ok });
  return redirect(ok ? "/?paid=1" : "/?canceled=1", [], 303);
}

// ---------- الـ API ----------
function readOrderInput(b) {
  const amount = Number(b.amount);
  const item = clip(b.item, 120).trim();
  if (!item || !(amount > 0) || amount > 1e7) return null;
  return { item, amount };
}

async function api(request, env, ctx, url) {
  const p = url.pathname;
  const s = await getSession(request, env);
  const cfg = await loadConfig(env);
  const admin = !!s && isAdminId(env, cfg, s.id);
  const owner = !!s && isOwnerId(env, s.id);

  if (request.method === "POST") {
    const o = request.headers.get("Origin");
    if (o && o !== url.origin) return json({ error: "طلب غير مسموح" }, 403);
  }

  if (p === "/api/me") return json({ loggedIn: !!s, name: s ? s.name : null, isAdmin: admin, isOwner: owner, storeName: cfg.storeName });
  if (!s) return json({ error: "سجّل دخولك أول" }, 401);

  if (p === "/api/config" && request.method === "GET") return json(publicConfig(cfg));

  if ((p === "/api/orders" || p === "/api/pay") && request.method === "POST") {
    const b = await request.json().catch(() => ({}));
    const inp = readOrderInput(b);
    if (!inp) return json({ error: "اكتب المنتج والمبلغ بشكل صحيح" }, 400);
    const m = cfg.methods.find((x) => x.id === b.methodId);
    if (!m) return json({ error: "اختار طريقة دفع" }, 400);
    const base = {
      id: Date.now() + "-" + newId(), at: Date.now(), buyerId: s.id, buyerName: s.name,
      item: inp.item, amount: inp.amount, method: m.name, methodId: m.id, methodType: m.type,
      ref: clip(b.ref, 120)
    };

    if (p === "/api/orders") {
      if (m.type !== "manual") return json({ error: "هاي الطريقة بتدفع أونلاين" }, 400);
      if (await env.STORE.get("rl:" + s.id)) return json({ error: "استنى دقيقة قبل ما تبعت طلب ثاني" }, 429);
      await env.STORE.put("rl:" + s.id, "1", { expirationTtl: 60 });
      const order = { ...base, status: "manual" };
      await env.STORE.put("order:" + order.id, JSON.stringify(order));
      notify(env, ctx, cfg, orderText("طلب جديد (تحويل يدوي، تأكد من المبلغ)", order));
      return json({ ok: true });
    }

    if (m.type === "manual") return json({ error: "هاي الطريقة تحويل يدوي" }, 400);
    const order = { ...base, status: "pending", payCurrency: m.gwCurrency, payAmount: Math.round(inp.amount * m.rate * 100) / 100 };
    if (!(order.payAmount > 0)) return json({ error: "المبلغ صغير كثير" }, 400);
    try {
      const r = m.type === "paypal" ? await startPaypal(m, order, url.origin, cfg.storeName) : await startPaytabs(m, order, url.origin);
      order.gwRef = r.ref;
      await env.STORE.put("order:" + order.id, JSON.stringify(order), { expirationTtl: 604800 });
      return json({ url: r.url });
    } catch (e) {
      return json({ error: "ما قدرت أتصل ببوابة الدفع. صاحب المتجر لازم يراجع الإعدادات." }, 502);
    }
  }

  if (!admin) return json({ error: "للمسؤول فقط" }, 403);

  if (p === "/api/admin/config" && request.method === "GET") return json({ config: maskedConfig(cfg), isOwner: owner });
  if (p === "/api/admin/config" && request.method === "POST") {
    const b = await request.json().catch(() => ({}));
    const next = cleanConfig(b, cfg, owner);
    await env.STORE.put("config", JSON.stringify(next));
    return json({ ok: true, config: maskedConfig(next) });
  }
  if (p === "/api/orders" && request.method === "GET") {
    const list = await env.STORE.list({ prefix: "order:" });
    const names = list.keys.map((k) => k.name).sort().reverse().slice(0, 200);
    const orders = (await Promise.all(names.map((n) => env.STORE.get(n, "json")))).filter((o) => o && o.status !== "pending");
    return json(orders);
  }
  if (p === "/api/orders/done" && request.method === "POST") {
    const b = await request.json().catch(() => ({}));
    const id = String(b.id || "");
    if (!/^[\w-]+$/.test(id)) return json({ error: "رقم غير صالح" }, 400);
    await env.STORE.delete("order:" + id);
    return json({ ok: true });
  }
  return json({ error: "غير موجود" }, 404);
}

// ---------- الصفحات ----------
const HEAD = String.raw`<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;500;600&family=Reem+Kufi:wght@600&display=swap">
<style>
:root{--bg:#eef6fb;--surface:#fff;--fg:#0f2433;--muted:#53697a;--line:#d3e3ef;--accent:#0369a1;--accent-fg:#fff;--accent-soft:#e0f2fe;--bad:#b42318;--good:#067647}
@media (prefers-color-scheme:dark){:root{--bg:#0a1822;--surface:#11222e;--fg:#e6f0f7;--muted:#93abc0;--line:#25425a;--accent:#38bdf8;--accent-fg:#04202e;--accent-soft:#0c3047;--bad:#f97066;--good:#47cd89;color-scheme:dark}}
*{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.7 "IBM Plex Sans Arabic","Segoe UI",Tahoma,sans-serif;padding:28px max(16px,env(safe-area-inset-right)) 48px max(16px,env(safe-area-inset-left))}
.wrap{max-width:560px;margin:0 auto;display:flex;flex-direction:column;gap:16px}
.col{display:flex;flex-direction:column;gap:8px}
h1{font-family:"Reem Kufi","Segoe UI",Tahoma,sans-serif;font-size:30px;line-height:1.3;margin:0}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;color:var(--muted);font-size:14px}
.top a{color:var(--accent)}
.step{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:18px;display:flex;flex-direction:column;gap:12px;min-width:0}
.step h2{font-size:17px;font-weight:600;margin:0}
.row{display:grid;grid-template-columns:1fr 130px;gap:10px}
@media(max-width:440px){.row{grid-template-columns:1fr}}
label{display:flex;flex-direction:column;gap:4px;font-size:14px;color:var(--muted);min-width:0}
input,textarea,select{font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px 12px;width:100%;min-width:0}
textarea{min-height:84px;resize:vertical}
input:focus-visible,textarea:focus-visible,select:focus-visible,button:focus-visible,a:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.methods{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.method{font:inherit;text-align:right;color:var(--fg);background:var(--bg);border:1.5px solid var(--line);border-radius:10px;padding:12px 14px;cursor:pointer;display:flex;flex-direction:column;min-width:0}
.method span{font-size:13px;color:var(--muted)}
.method[aria-pressed="true"]{border-color:var(--accent);background:var(--accent-soft)}
.field{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 12px;background:var(--bg);border:1px solid var(--line);border-radius:8px;min-width:0}
.field .k{font-size:13px;color:var(--muted);display:block}
.field .v{font-weight:600;direction:ltr;unicode-bidi:plaintext;overflow-wrap:anywhere;user-select:all}
.txt{min-width:0}
.btn{font:inherit;font-weight:600;border:0;border-radius:10px;padding:13px 16px;background:var(--accent);color:var(--accent-fg);cursor:pointer;text-align:center;text-decoration:none;display:block;width:100%}
.btn:disabled{opacity:.6;cursor:default}
.btn.ghost{background:transparent;color:var(--accent);border:1px solid var(--accent);font-weight:500;padding:4px 12px;width:auto;display:inline-block;flex:none}
.note,.hint{color:var(--muted);font-size:14px;margin:0}
.err{color:var(--bad);font-size:14px;margin:0;min-height:1em}
.ok{color:var(--good)}
.banner{border-radius:10px;padding:12px 14px;background:var(--accent-soft);border:1px solid var(--accent)}
.total{display:flex;justify-content:space-between;align-items:baseline;border-top:1px dashed var(--line);padding-top:12px}
.total strong{font-size:22px}
.order{border:1px solid var(--line);border-radius:10px;padding:12px;display:flex;flex-direction:column;gap:4px;background:var(--bg)}
.order small{color:var(--muted)}
.tag{display:inline-block;font-size:12px;border:1px solid var(--line);border-radius:999px;padding:0 10px;color:var(--muted);align-self:flex-start}
.tag.paid{color:var(--good);border-color:var(--good)}
.fieldset{border:1px solid var(--line);border-radius:10px;padding:12px;display:flex;flex-direction:column;gap:10px}
</style>`;

const SHOP_HTML = String.raw`<!doctype html><html lang="ar" dir="rtl"><head><title>الدفع</title>${HEAD}</head><body>
<main class="wrap">
  <header><h1 id="storeName"></h1></header>
  <div class="top" id="who" hidden><span>مسجّل دخول: <b id="whoName"></b></span><span><a id="adminLink" href="/admin" hidden>لوحة التحكم</a> <a href="/logout">تسجيل خروج</a></span></div>
  <div class="banner" id="paidBanner" hidden>تم الدفع بنجاح. شكرا لك، رح نتواصل معك على ديسكورد.</div>
  <div class="banner" id="cancelBanner" hidden>الدفع ما اكتمل. إذا خصم منك مبلغ، تواصل معنا على ديسكورد.</div>

  <section class="step" id="login" hidden>
    <h2>سجّل دخولك أول</h2>
    <p class="note">بتسجّل بحسابك على ديسكورد عشان نعرف مين صاحب الطلب. ما بنشوف كلمة السر ولا رسائلك.</p>
    <a class="btn" href="/login">سجّل دخول بديسكورد</a>
  </section>

  <div id="shop" hidden class="wrap" style="max-width:none">
    <section class="step">
      <h2>1. شو بدك تشتري؟</h2>
      <div class="row">
        <label for="item">المنتج أو الخدمة<input id="item" maxlength="120" placeholder="مثال: اشتراك شهري" autocomplete="off"></label>
        <label for="amount">المبلغ (<span id="cur1"></span>)<input id="amount" type="number" inputmode="decimal" min="0" step="0.01" placeholder="0.00"></label>
      </div>
    </section>
    <section class="step">
      <h2>2. كيف بدك تدفع؟</h2>
      <div class="methods" id="methods"></div>
    </section>
    <section class="step">
      <h2 id="step3"></h2>
      <div id="fields" class="col"></div>
      <p class="note" id="note"></p>
      <div class="total"><span>المبلغ المطلوب</span><strong id="total">—</strong></div>
      <p class="note" id="conv" hidden></p>
      <label for="ref" id="refBox">رقم العملية أو اسم المرسل (اختياري)<input id="ref" maxlength="120" autocomplete="off"></label>
      <p class="err" id="err"></p>
      <button class="btn" id="send" type="button"></button>
    </section>
  </div>

  <section class="step" id="done" hidden>
    <h2>وصل طلبك</h2>
    <p class="note" id="afterNote"></p>
  </section>
</main>
<script>
const $ = (id) => document.getElementById(id);
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
async function j(url, opt) {
  const r = await fetch(url, opt);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || "صار خطأ");
  return d;
}
let cfg, cur = 0;
const isGw = (m) => m.type === "paypal" || m.type === "paytabs";
function copyText(text, btn) {
  const ok = () => { btn.textContent = "تم النسخ"; setTimeout(() => { btn.textContent = "نسخ"; }, 1500); };
  const fb = () => { const t = document.createElement("textarea"); t.value = text; document.body.appendChild(t); t.select(); try { document.execCommand("copy"); ok(); } catch (e) {} t.remove(); };
  try { navigator.clipboard.writeText(text).then(ok, fb); } catch (e) { fb(); }
}
function renderMethods() {
  const box = $("methods"); box.innerHTML = "";
  cfg.methods.forEach((m, i) => {
    const b = el("button", "method"); b.type = "button";
    b.setAttribute("aria-pressed", String(i === cur));
    b.appendChild(el("b", null, m.name)); b.appendChild(el("span", null, m.hint));
    b.onclick = () => { cur = i; renderMethods(); renderDetails(); };
    box.appendChild(b);
  });
}
function renderDetails() {
  const m = cfg.methods[cur]; const box = $("fields"); box.innerHTML = "";
  if (!m) return;
  const gw = isGw(m);
  $("step3").textContent = gw ? "3. ادفع أونلاين" : "3. حوّل وبعدين أكّد";
  $("send").textContent = gw ? "ادفع الآن" : "دفعت، أكّد طلبي";
  $("refBox").hidden = gw;
  m.fields.forEach((f) => {
    const row = el("div", "field"); const t = el("div", "txt");
    t.appendChild(el("span", "k", f.k)); t.appendChild(el("span", "v", f.v));
    const c = el("button", "btn ghost", "نسخ"); c.type = "button"; c.onclick = () => copyText(f.v, c);
    row.appendChild(t); row.appendChild(c); box.appendChild(row);
  });
  $("note").textContent = m.note || (gw ? "رح يفتحلك صفحة دفع آمنة، وبترجع للموقع بعد ما تخلص." : "");
  updateTotal();
}
function updateTotal() {
  const a = parseFloat($("amount").value); const m = cfg.methods[cur];
  $("total").textContent = a > 0 ? a.toLocaleString("en-US", { maximumFractionDigits: 2 }) + " " + cfg.currency : "—";
  const show = m && isGw(m) && a > 0;
  $("conv").hidden = !show;
  if (show) $("conv").textContent = "رح تدفع: " + (Math.round(a * m.rate * 100) / 100).toLocaleString("en-US", { minimumFractionDigits: 2 }) + " " + m.gwCurrency;
}
async function init() {
  const q = new URLSearchParams(location.search);
  if (q.get("paid")) $("paidBanner").hidden = false;
  if (q.get("canceled")) $("cancelBanner").hidden = false;
  const me = await j("/api/me");
  $("storeName").textContent = me.storeName; document.title = me.storeName;
  if (!me.loggedIn) { $("login").hidden = false; return; }
  $("who").hidden = false; $("whoName").textContent = me.name; $("adminLink").hidden = !me.isAdmin;
  cfg = await j("/api/config");
  $("cur1").textContent = cfg.currency;
  if (!cfg.methods.length) { $("err").textContent = "ما في طرق دفع مفعّلة حاليا."; }
  $("shop").hidden = false;
  renderMethods(); renderDetails();
  $("amount").addEventListener("input", updateTotal);
  $("send").onclick = async () => {
    $("err").textContent = "";
    const m = cfg.methods[cur]; if (!m) return;
    const amount = parseFloat($("amount").value); const item = $("item").value.trim();
    if (!item || !(amount > 0)) { $("err").textContent = "اكتب المنتج والمبلغ أول."; return; }
    $("send").disabled = true;
    const body = JSON.stringify({ item, amount, methodId: m.id, ref: $("ref").value.trim() });
    const opt = { method: "POST", headers: { "Content-Type": "application/json" }, body };
    try {
      if (isGw(m)) { const r = await j("/api/pay", opt); location.href = r.url; return; }
      await j("/api/orders", opt);
      $("shop").hidden = true; $("done").hidden = false; $("afterNote").textContent = cfg.afterNote || "";
    } catch (e) { $("err").textContent = e.message; $("send").disabled = false; }
  };
}
init().catch((e) => { document.body.appendChild(el("p", "err", "صار خطأ: " + e.message)); });
</script></body></html>`;

const ADMIN_HTML = String.raw`<!doctype html><html lang="ar" dir="rtl"><head><title>لوحة التحكم</title>${HEAD}</head><body>
<main class="wrap">
  <header><h1>لوحة التحكم</h1></header>
  <div class="top"><span id="msg"></span><span><a href="/">رجوع للمتجر</a></span></div>

  <section class="step" id="deny" hidden><p class="note">هاي الصفحة للمسؤولين فقط. <a href="/login">سجّل دخول</a></p></section>

  <div id="panel" hidden class="wrap" style="max-width:none">
    <section class="step">
      <h2>الطلبات</h2>
      <div id="orders" class="col" style="gap:10px"></div>
    </section>

    <section class="step">
      <h2>إعدادات المتجر</h2>
      <div class="row">
        <label for="storeName">اسم المتجر<input id="storeName" maxlength="60"></label>
        <label for="currency">العملة<input id="currency" maxlength="20"></label>
      </div>
      <label for="afterNote">رسالة بتظهر للزبون بعد الطلب<input id="afterNote" maxlength="200"></label>
      <label for="hook">رابط Webhook لقناة ديسكورد (اختياري، عشان يجيك إشعار مع كل طلب)<input id="hook" type="password" autocomplete="off" placeholder="https://discord.com/api/webhooks/..."></label>
    </section>

    <section class="step">
      <h2>طرق الدفع</h2>
      <div id="methods" class="col" style="gap:12px"></div>
      <button class="btn ghost" id="add" type="button">إضافة طريقة دفع</button>
    </section>

    <section class="step" id="adminsBox" hidden>
      <h2>المسؤولين معك</h2>
      <p class="note">كل سطر بهالشكل: رقم الديسكورد: الاسم. المسؤول بيقدر يدخل لوحة التحكم ويعدّل ويشوف الطلبات، بس إنت بس بتقدر تضيف أو تشيل مسؤولين.</p>
      <textarea id="admins" aria-label="المسؤولين"></textarea>
    </section>

    <p class="err" id="err"></p>
    <button class="btn" id="save" type="button">حفظ كل التغييرات</button>
  </div>
</main>
<script>
const $ = (id) => document.getElementById(id);
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
async function j(url, opt) {
  const r = await fetch(url, opt);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || "صار خطأ");
  return d;
}
const TYPES = [["manual", "تحويل يدوي (كليك، بنك، محفظة...)"], ["paypal", "PayPal"], ["paytabs", "فيزا وماستركارد وأبل باي (PayTabs)"]];
let methods = [], isOwner = false;

function field(parent, cls, label, val, type) {
  const l = el("label", null, label); const i = el("input"); i.className = cls; i.value = val || ""; if (type) i.type = type; if (type === "password") i.autocomplete = "off";
  l.appendChild(i); parent.appendChild(l); return i;
}
function readMethods() {
  return Array.from(document.querySelectorAll(".fieldset")).map((fs) => {
    const v = (c) => fs.querySelector("." + c).value.trim();
    return {
      id: fs.dataset.id || "", type: v("mtype"), name: v("mn"), hint: v("mh"), note: v("mt"),
      fields: fs.querySelector(".mf").value.split("\n").map((l) => {
        const i = l.indexOf(":");
        return i < 0 ? { k: "", v: l.trim() } : { k: l.slice(0, i).trim(), v: l.slice(i + 1).trim() };
      }).filter((f) => f.k || f.v),
      rate: parseFloat(v("mrate")) || 1, gwCurrency: v("mcur") || "USD",
      gw: { clientId: v("ppid"), secret: fs.querySelector(".ppsecret").value, mode: v("ppmode"),
            profileId: v("ptid"), serverKey: fs.querySelector(".ptkey").value, baseUrl: v("ptbase") }
    };
  });
}
function renderMethods() {
  const box = $("methods"); box.innerHTML = "";
  methods.forEach((m, i) => {
    const g = m.gw || {};
    const fs = el("div", "fieldset"); fs.dataset.id = m.id || "";
    const tl = el("label", null, "نوع الطريقة"); const sel = el("select"); sel.className = "mtype";
    TYPES.forEach((t) => { const o = el("option", null, t[1]); o.value = t[0]; if (t[0] === m.type) o.selected = true; sel.appendChild(o); });
    tl.appendChild(sel); fs.appendChild(tl);
    field(fs, "mn", "الاسم اللي بيظهر للزبون (مثال: كليك، PayPal، بطاقة)", m.name);
    field(fs, "mh", "وصف قصير", m.hint);
    field(fs, "mt", "ملاحظة للزبون (اختياري)", m.note);

    const man = el("div", "col");
    const l = el("label", null, "البيانات اللي بتظهر للزبون، كل سطر بهالشكل: الاسم: القيمة");
    const ta = el("textarea"); ta.className = "mf"; ta.value = (m.fields || []).map((f) => f.k + ": " + f.v).join("\n");
    l.appendChild(ta); man.appendChild(l); fs.appendChild(man);

    const gwb = el("div", "col");
    gwb.appendChild(el("p", "note", "الزبون بيدفع بعملة البوابة. اكتب سعر التحويل من عملة المتجر (مثال: دينار لدولار = 1.41)."));
    field(gwb, "mcur", "عملة البوابة (3 أحرف، مثال USD)", m.gwCurrency || "USD");
    field(gwb, "mrate", "سعر التحويل من عملة المتجر لعملة البوابة", m.rate || 1, "number");
    fs.appendChild(gwb);

    const pp = el("div", "col");
    pp.appendChild(el("p", "note", "من developer.paypal.com بقسم Apps and Credentials، بتجيب Client ID و Secret. جرّب أول بوضع التجربة (Sandbox) وبعدين غيّره للحقيقي (Live)."));
    field(pp, "ppid", "PayPal Client ID", g.clientId);
    field(pp, "ppsecret", "PayPal Secret", g.secret, "password");
    const ml = el("label", null, "الوضع"); const ms = el("select"); ms.className = "ppmode";
    [["sandbox", "تجربة (Sandbox)"], ["live", "حقيقي (Live)"]].forEach((t) => { const o = el("option", null, t[1]); o.value = t[0]; if (t[0] === (g.mode || "sandbox")) o.selected = true; ms.appendChild(o); });
    ml.appendChild(ms); pp.appendChild(ml); fs.appendChild(pp);

    const pt = el("div", "col");
    pt.appendChild(el("p", "note", "من لوحة PayTabs بقسم Developers ثم Key management بتجيب Profile ID و Server Key. أبل باي بيظهر لزبائنك بس إذا كان مفعّل بحساب PayTabs تبعك."));
    field(pt, "ptid", "PayTabs Profile ID", g.profileId);
    field(pt, "ptkey", "PayTabs Server Key", g.serverKey, "password");
    field(pt, "ptbase", "رابط PayTabs (للأردن بيكون جاهز)", g.baseUrl || "https://secure-jordan.paytabs.com");
    fs.appendChild(pt);

    const toggle = () => { const t = sel.value; man.hidden = t !== "manual"; gwb.hidden = t === "manual"; pp.hidden = t !== "paypal"; pt.hidden = t !== "paytabs"; };
    sel.onchange = toggle; toggle();
    const rm = el("button", "btn ghost", "حذف هاي الطريقة"); rm.type = "button";
    rm.onclick = () => { methods = readMethods(); methods.splice(i, 1); renderMethods(); };
    fs.appendChild(rm); box.appendChild(fs);
  });
}
async function loadOrders() {
  const list = await j("/api/orders"); const box = $("orders"); box.innerHTML = "";
  if (!list.length) { box.appendChild(el("p", "note", "ما في طلبات.")); return; }
  list.forEach((o) => {
    const c = el("div", "order");
    const paid = o.status === "paid";
    c.appendChild(el("span", "tag" + (paid ? " paid" : ""), paid ? "مدفوع أونلاين" : "تحويل يدوي، تأكد من حسابك"));
    c.appendChild(el("b", null, o.item + " - " + o.amount));
    const extra = o.payAmount && o.methodType !== "manual" ? " | المدفوع: " + o.payAmount + " " + o.payCurrency : "";
    c.appendChild(el("span", null, "الطريقة: " + o.method + extra + (o.ref ? " | رقم العملية: " + o.ref : "")));
    c.appendChild(el("small", null, o.buyerName + " (ID: " + o.buyerId + ") - " + new Date(o.at).toLocaleString("ar")));
    const b = el("button", "btn ghost", "تم، شيله من القائمة"); b.type = "button";
    b.onclick = async () => { await j("/api/orders/done", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: o.id }) }); loadOrders(); };
    c.appendChild(b); box.appendChild(c);
  });
}
function fill(cfg) {
  $("storeName").value = cfg.storeName; $("currency").value = cfg.currency; $("afterNote").value = cfg.afterNote || "";
  $("hook").value = cfg.discordWebhook || "";
  methods = cfg.methods; renderMethods();
  $("admins").value = (cfg.admins || []).map((a) => a.id + ": " + a.name).join("\n");
}
async function init() {
  const me = await j("/api/me");
  if (!me.isAdmin) { $("deny").hidden = false; return; }
  isOwner = me.isOwner;
  $("panel").hidden = false; $("msg").textContent = "أهلا " + me.name + (isOwner ? " (المالك)" : " (مسؤول)");
  $("adminsBox").hidden = !isOwner;
  const r = await j("/api/admin/config"); fill(r.config); loadOrders();
  $("add").onclick = () => { methods = readMethods(); methods.push({ id: "", type: "manual", name: "", hint: "", note: "", fields: [], rate: 1, gwCurrency: "USD", gw: {} }); renderMethods(); };
  $("save").onclick = async () => {
    const e = $("err"); e.className = "err"; e.textContent = "";
    const admins = $("admins").value.split("\n").map((l) => { const i = l.indexOf(":"); return i < 0 ? { id: l.trim(), name: "" } : { id: l.slice(0, i).trim(), name: l.slice(i + 1).trim() }; }).filter((a) => a.id);
    try {
      const res = await j("/api/admin/config", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ storeName: $("storeName").value, currency: $("currency").value, afterNote: $("afterNote").value, discordWebhook: $("hook").value, methods: readMethods(), admins }) });
      fill(res.config); e.className = "err ok"; e.textContent = "تم الحفظ";
    } catch (x) { e.textContent = x.message; }
  };
}
init().catch((e) => { document.body.appendChild(el("p", "err", "صار خطأ: " + e.message)); });
</script></body></html>`;

// ---------- نقطة الدخول ----------
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const missing = ["DISCORD_CLIENT_ID", "DISCORD_CLIENT_SECRET", "ADMIN_ID", "SESSION_SECRET"].filter((k) => !env[k]);
    if (missing.length || !env.STORE) {
      return new Response("ناقص إعدادات: " + missing.concat(env.STORE ? [] : ["STORE (KV)"]).join(", "), { status: 500, headers: { "content-type": "text/plain; charset=utf-8" } });
    }
    try {
      switch (url.pathname) {
        case "/login": return login(url, env);
        case "/callback": return await callback(request, url, env);
        case "/logout": return redirect("/", [cookie("s", "", 0)]);
        case "/admin": return page(ADMIN_HTML);
        case "/": return page(SHOP_HTML);
        case "/paid/paypal": return await paidReturn(request, env, ctx, url, "paypal");
        case "/paid/paytabs": return await paidReturn(request, env, ctx, url, "paytabs");
      }
      if (url.pathname.startsWith("/api/")) return await api(request, env, ctx, url);
      return new Response("غير موجود", { status: 404 });
    } catch (e) {
      return json({ error: "خطأ في السيرفر" }, 500);
    }
  }
};
