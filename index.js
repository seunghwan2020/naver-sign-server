const express = require("express");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json({ limit: "1mb" }));

// 요청 로그 (무조건 남기기)
app.use((req, res, next) => {
  console.log(`[REQ] ${req.method} ${req.url}`);
  next();
});

const NAVER_CLIENT_ID = process.env.NAVER_CLIENT_ID;
const NAVER_CLIENT_SECRET = process.env.NAVER_CLIENT_SECRET;

app.get("/health", (req, res) => {
  return res.status(200).json({
    ok: true,
    hasClientId: !!NAVER_CLIENT_ID,
    hasClientSecret: !!NAVER_CLIENT_SECRET,
    node: process.version,
  });
});

// 전역 에러 핸들러용 유틸
function safeJson(res, status, obj) {
  try {
    return res.status(status).json(obj);
  } catch (e) {
    // 최후의 수단
    res.status(status).send(JSON.stringify(obj));
  }
}

app.post("/token", async (req, res) => {
  try {
    if (!NAVER_CLIENT_ID || !NAVER_CLIENT_SECRET) {
      return safeJson(res, 500, {
        error: "missing_env",
        message:
          "Set NAVER_CLIENT_ID and NAVER_CLIENT_SECRET on the auth server (Railway Variables).",
      });
    }

    const timestamp = Date.now().toString();
    const password = `${NAVER_CLIENT_ID}_${timestamp}`;

    // ✅ 여기서 Invalid salt면 바로 JSON으로 떨어지게
    const hashed = await bcrypt.hash(password, NAVER_CLIENT_SECRET);
    const client_secret_sign = Buffer.from(hashed).toString("base64");

    const tokenUrl = "https://api.commerce.naver.com/external/v1/oauth2/token";

    const form = new URLSearchParams();
    form.append("client_id", NAVER_CLIENT_ID);
    form.append("timestamp", timestamp);
    form.append("client_secret_sign", client_secret_sign);
    form.append("grant_type", "client_credentials");
    form.append("type", "SELF");

    console.log("[TOKEN] calling naver token endpoint...");

    const r = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });

    const raw = await r.text();
    console.log(`[TOKEN] status=${r.status} body=${raw.slice(0, 300)}`);

    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      data = { raw };
    }

    if (!r.ok) {
      return safeJson(res, r.status, {
        error: "token_failed",
        status: r.status,
        response: data,
      });
    }

    return safeJson(res, 200, data);
  } catch (e) {
    console.error("[ERR] /token", e);
    return safeJson(res, 500, {
      error: "token_server_error",
      message: e?.message || String(e),
      stack: e?.stack,
    });
  }
});

// 전역 에러 핸들러(Express)
app.use((err, req, res, next) => {
  console.error("[EXPRESS_ERR]", err);
  return safeJson(res, 500, {
    error: "express_error",
    message: err?.message || String(err),
  });
});

// 프로세스 레벨 에러도 잡기
process.on("uncaughtException", (err) => {
  console.error("[UNCAUGHT_EXCEPTION]", err);
});
process.on("unhandledRejection", (err) => {
  console.error("[UNHANDLED_REJECTION]", err);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Auth server running on ${PORT}`));
