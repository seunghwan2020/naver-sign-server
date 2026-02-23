const express = require("express");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json({ limit: "1mb" }));

// 요청 로그
app.use((req, res, next) => {
  console.log(`[REQ] ${req.method} ${req.url}`);
  next();
});

const NAVER_CLIENT_ID = process.env.NAVER_CLIENT_ID;
const NAVER_CLIENT_SECRET = process.env.NAVER_CLIENT_SECRET;

app.get("/", (req, res) => res.status(200).send("ok-root"));
app.get("/health", (req, res) => res.status(200).send("ok-health"));

app.post("/token", async (req, res) => {
  try {
    if (!NAVER_CLIENT_ID || !NAVER_CLIENT_SECRET) {
      return res.status(500).json({
        error: "missing_env",
        message: "Set NAVER_CLIENT_ID and NAVER_CLIENT_SECRET on Railway Variables (naver-sign-server service).",
      });
    }

    const timestamp = Date.now().toString();
    const password = `${NAVER_CLIENT_ID}_${timestamp}`;

    // 네이버 방식: client_secret을 bcrypt salt로 사용
    const hashed = await bcrypt.hash(password, NAVER_CLIENT_SECRET);
    const client_secret_sign = Buffer.from(hashed).toString("base64");

    const tokenUrl = "https://api.commerce.naver.com/external/v1/oauth2/token";

    const form = new URLSearchParams();
    form.append("client_id", NAVER_CLIENT_ID);
    form.append("timestamp", timestamp);
    form.append("client_secret_sign", client_secret_sign);
    form.append("grant_type", "client_credentials");
    form.append("type", "SELF");

    const r = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });

    const raw = await r.text();
    let data;
    try { data = JSON.parse(raw); } catch { data = { raw }; }

    if (!r.ok) {
      console.log("[TOKEN_FAIL]", r.status, raw.slice(0, 300));
      return res.status(r.status).json({
        error: "token_failed",
        status: r.status,
        response: data,
      });
    }

    return res.json(data);
  } catch (e) {
    console.error("[TOKEN_ERR]", e);
    return res.status(500).json({
      error: "token_server_error",
      message: e?.message || String(e),
    });
  }
});

process.on("uncaughtException", (err) => console.error("[UNCAUGHT_EXCEPTION]", err));
process.on("unhandledRejection", (err) => console.error("[UNHANDLED_REJECTION]", err));

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, "0.0.0.0", () => console.log(`listening on ${PORT}`));
