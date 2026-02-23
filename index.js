const express = require("express");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());

// ✅ 이 서버(Railway)에만 저장할 환경변수
// NAVER_CLIENT_ID
// NAVER_CLIENT_SECRET
const NAVER_CLIENT_ID = process.env.NAVER_CLIENT_ID;
const NAVER_CLIENT_SECRET = process.env.NAVER_CLIENT_SECRET;

app.get("/health", (req, res) => res.status(200).send("ok"));

/**
 * 1) 서명 생성만 필요하면 /sign
 * 2) n8n에서 제일 편하게 쓰려면 /token (서명+토큰발급까지 한 번에)
 */
app.post("/sign", async (req, res) => {
  try {
    if (!NAVER_CLIENT_ID || !NAVER_CLIENT_SECRET) {
      return res.status(500).json({
        error: "missing_env",
        message: "NAVER_CLIENT_ID or NAVER_CLIENT_SECRET is not set on auth server",
      });
    }

    const timestamp = Date.now().toString();
    const password = `${NAVER_CLIENT_ID}_${timestamp}`;

    // 네이버 문서 방식: client_secret을 bcrypt salt로 사용
    const hashed = await bcrypt.hash(password, NAVER_CLIENT_SECRET);
    const client_secret_sign = Buffer.from(hashed).toString("base64");

    return res.json({
      client_id: NAVER_CLIENT_ID,
      timestamp,
      client_secret_sign,
    });
  } catch (e) {
    return res.status(500).json({
      error: "sign_failed",
      message: e?.message || String(e),
    });
  }
});

app.post("/token", async (req, res) => {
  try {
    if (!NAVER_CLIENT_ID || !NAVER_CLIENT_SECRET) {
      return res.status(500).json({
        error: "missing_env",
        message: "NAVER_CLIENT_ID or NAVER_CLIENT_SECRET is not set on auth server",
      });
    }

    const timestamp = Date.now().toString();
    const password = `${NAVER_CLIENT_ID}_${timestamp}`;
    const hashed = await bcrypt.hash(password, NAVER_CLIENT_SECRET);
    const client_secret_sign = Buffer.from(hashed).toString("base64");

    // 네이버 토큰 endpoint
    const tokenUrl = "https://api.commerce.naver.com/external/v1/oauth2/token";

    // Node 18+ 에서는 fetch 내장. (Railway Node 22 OK)
    const form = new URLSearchParams();
    form.append("client_id", NAVER_CLIENT_ID);
    form.append("timestamp", timestamp);
    form.append("client_secret_sign", client_secret_sign);
    form.append("grant_type", "client_credentials");
    form.append("type", "SELF"); // 대부분 SELF로 시작 권장

    const r = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });

    const text = await r.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { raw: text }; }

    if (!r.ok) {
      return res.status(r.status).json({
        error: "token_failed",
        status: r.status,
        response: data,
      });
    }

    // data: { access_token, token_type, expires_in, ... } 형태
    return res.json(data);
  } catch (e) {
    return res.status(500).json({
      error: "token_server_error",
      message: e?.message || String(e),
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Auth server running on ${PORT}`));
