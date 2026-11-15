// Fungsi server Netlify: simpan & ambil data aplikasi di Netlify Blobs.
// Alamat: /api/state
//   GET  /api/state          -> ambil data tersimpan
//   GET  /api/state?meta=1   -> cek koneksi + versi saja
//   PUT  /api/state          -> simpan (body JSON: { data, baseVersion, force })
// Semua permintaan wajib header  x-sync-pin  yang sama dengan variabel SYNC_PIN.
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api/state" };

const MAX_BYTES = 4000000;
const MAX_FAILS = 10;
const FAIL_WINDOW_MS = 10 * 60 * 1000;

const json = (code, obj) =>
  new Response(JSON.stringify(obj), {
    status: code,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });

function pinOk(given) {
  const real = Netlify.env.get("SYNC_PIN") || "";
  if (!real || typeof given !== "string") return false;
  const a = crypto.createHash("sha256").update(given).digest();
  const b = crypto.createHash("sha256").update(real).digest();
  return crypto.timingSafeEqual(a, b);
}

export default async (req, context) => {
  try {
    if (!Netlify.env.get("SYNC_PIN")) return json(500, { ok: false, error: "SYNC_PIN belum diisi di Environment variables Netlify (lalu deploy ulang)" });

    const data = getStore({ name: "nestvault", consistency: "strong" });
    const guard = getStore({ name: "nestvault-guard", consistency: "strong" });

    // batasi tebakan PIN per alamat IP
    const ip = String(context.ip || req.headers.get("x-nf-client-connection-ip") || "unknown").replace(/[^0-9a-zA-Z.:]/g, "_");
    const now = Date.now();
    let g = (await guard.get(ip, { type: "json" })) || { n: 0, t: now };
    if (now - g.t > FAIL_WINDOW_MS) g = { n: 0, t: now };
    if (g.n >= MAX_FAILS) return json(429, { ok: false, error: "Terlalu banyak salah PIN, coba lagi nanti" });
    if (!pinOk(req.headers.get("x-sync-pin"))) {
      await guard.setJSON(ip, { n: g.n + 1, t: g.t });
      return json(401, { ok: false, error: "PIN salah" });
    }

    const cur = await data.get("state", { type: "json" }); // { version, updatedAt, data } atau null
    const url = new URL(req.url);

    if (req.method === "GET") {
      if (url.searchParams.get("meta")) return json(200, { ok: true, exists: !!cur, version: cur ? cur.version : 0, updatedAt: cur ? cur.updatedAt : null });
      if (!cur) return json(200, { ok: true, exists: false, version: 0, data: null });
      return json(200, { ok: true, exists: true, version: cur.version, updatedAt: cur.updatedAt, data: cur.data });
    }

    if (req.method === "PUT" || req.method === "POST") {
      const raw = await req.text();
      if (raw.length > MAX_BYTES) return json(413, { ok: false, error: "Data terlalu besar" });
      let body = null;
      try { body = JSON.parse(raw); } catch (e) {}
      if (!body || typeof body.data !== "object" || body.data === null) return json(400, { ok: false, error: "Body harus berisi { data: {...} }" });

      const curVersion = cur ? cur.version : 0;
      if (!body.force && typeof body.baseVersion === "number" && body.baseVersion !== curVersion) {
        return json(409, { ok: false, conflict: true, version: curVersion, updatedAt: cur ? cur.updatedAt : null, error: "Data di database lebih baru dari yang kamu pegang" });
      }
      const next = { version: curVersion + 1, updatedAt: new Date().toISOString(), data: body.data };
      await data.setJSON("state", next);
      return json(200, { ok: true, version: next.version, updatedAt: next.updatedAt });
    }

    return json(405, { ok: false, error: "Metode tidak didukung" });
  } catch (err) {
    return json(500, { ok: false, error: "Kesalahan server: " + (err && err.message ? err.message : "tidak diketahui") });
  }
};
