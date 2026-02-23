const express = require("express");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json({ limit: "1mb" }));

app.use((req, res, next) => {
  console.log(`[REQ] ${req.method} ${req.url}`);
  next();
});

const NAVER_CLIENT_ID = process.env.NAVER_CLIENT_ID;
const NAVER_CLIENT_SECRET = process.env.NAVER_CLIENT_SECRET;
const NAVER_SELLER_ACCOUNT_ID = process.env.NAVER_SELLER_ACCOUNT_ID; // SELLER용

app.get("/", (req, res) => res.status(200).send("naver-sign-server-ok"));
app.get("/health", (req, res) =>
  res.status(200).json({
    ok: true,
    node: process.version,
    hasClientId: !!NAVER_CLIENT_ID,
    hasClientSecret: !!NAVER_CLIENT_SECRET,
    hasSellerAccountId: !!NAVER_SELLER_ACCOUNT_ID,
  })
);

app.get("/myip", async (req, res) => {
  try {
    const r = await fetch("https://api.ipify.org?format=json");
    const data = await r.json();
    return res.json({ ip: data.ip });
  } catch (e) {
    return res.status(500).json({ error: "ip_check_failed", message: e?.message || String(e) });
  }
});

/**
 * /token?type=SELF  (기본)
 * /token?type=SELLER (SELLER 토큰)
 */
app.post("/token", async (req, res) => {
  try {
    if (!NAVER_CLIENT_ID || !NAVER_CLIENT_SECRET) {
      return res.status(500).json({
        error: "missing_env",
        message: "Set NAVER_CLIENT_ID and NAVER_CLIENT_SECRET on Railway Variables (naver-sign-server).",
      });
    }

    const type = (req.query.type || "SELF").toString().toUpperCase();

    if (type === "SELLER" && !NAVER_SELLER_ACCOUNT_ID) {
      return res.status(500).json({
        error: "missing_env",
        message:
          "type=SELLER requires NAVER_SELLER_ACCOUNT_ID on Railway Variables (naver-sign-server).",
      });
    }

    const timestamp = Date.now().toString();
    const password = `${NAVER_CLIENT_ID}_${timestamp}`;

    const hashed = await bcrypt.hash(password, NAVER_CLIENT_SECRET);
    const client_secret_sign = Buffer.from(hashed).toString("base64");

    const tokenUrl = "https://api.commerce.naver.com/external/v1/oauth2/token";

    const form = new URLSearchParams();
    form.append("client_id", NAVER_CLIENT_ID);
    form.append("timestamp", timestamp);
    form.append("client_secret_sign", client_secret_sign);
    form.append("grant_type", "client_credentials");
    form.append("type", type);

    if (type === "SELLER") {
      form.append("account_id", NAVER_SELLER_ACCOUNT_ID);
    }

    const r = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });

    const raw = await r.text();
    console.log(`[TOKEN] status=${r.status} body=${raw.slice(0, 500)}`);

    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      data = { raw };
    }

    if (!r.ok) {
      return res.status(r.status).json({
        error: "token_failed",
        status: r.status,
        response: data,
        debug: { type, hasAccountId: !!NAVER_SELLER_ACCOUNT_ID },
      });
    }

    return res.json(data);
  } catch (e) {
    console.error("[TOKEN_ERR]", e);
    return res.status(500).json({ error: "token_server_error", message: e?.message || String(e) });
  }
});

process.on("uncaughtException", (err) => console.error("[UNCAUGHT_EXCEPTION]", err));
process.on("unhandledRejection", (err) => console.error("[UNHANDLED_REJECTION]", err));

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, "0.0.0.0", () => console.log(`listening on ${PORT}`));
