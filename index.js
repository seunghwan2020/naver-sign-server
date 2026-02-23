/**
 * naver-sign-server / auth server
 * - 목적:
 *   1) /health 로 살아있는지 확인
 *   2) /myip 로 "현재 이 서버가 외부로 나갈 때 쓰는 공인 IP" 확인
 *   3) /token 로 네이버 커머스 OAuth2 토큰 발급 (client_secret_sign 생성 포함)
 *
 * Railway 권장 환경변수 (naver-sign-server 서비스에만 설정):
 * - NAVER_CLIENT_ID
 * - NAVER_CLIENT_SECRET   (bcrypt salt 형태여야 함: 보통 $2a$10$... 또는 $2b$10$...)
 * Railway는 PORT를 자동 주입하므로 PORT를 따로 고정하지 않는 것을 권장
 */

const express = require("express");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json({ limit: "1mb" }));

// ===== 요청 로깅 =====
app.use((req, res, next) => {
  console.log(`[REQ] ${req.method} ${req.url}`);
  next();
});

// ===== 환경변수 =====
const NAVER_CLIENT_ID = process.env.NAVER_CLIENT_ID;
const NAVER_CLIENT_SECRET = process.env.NAVER_CLIENT_SECRET;

// ===== 기본 라우트 =====
app.get("/", (req, res) => res.status(200).send("naver-sign-server-ok"));

app.get("/health", (req, res) => {
  return res.status(200).json({
    ok: true,
    service: "naver-sign-server",
    node: process.version,
    hasClientId: !!NAVER_CLIENT_ID,
    hasClientSecret: !!NAVER_CLIENT_SECRET,
  });
});

/**
 * /myip
 * - 이 서버(Railway)가 외부로 나갈 때 사용하는 공인 IP 확인
 * - 이 IP를 네이버 커머스 API센터의 "허용 IP"에 등록해야 403(IP_NOT_ALLOWED)이 사라짐
 */
app.get("/myip", async (req, res) => {
  try {
    // ipify: 간단하고 안정적인 공인 IP 확인 서비스
    const r = await fetch("https://api.ipify.org?format=json", { method: "GET" });
    const data = await r.json();
    return res.json({ ip: data.ip });
  } catch (e) {
    return res.status(500).json({
      error: "ip_check_failed",
      message: e?.message || String(e),
    });
  }
});

/**
 * /token
 * - 네이버 커머스 OAuth2 토큰 발급 (client_secret_sign 생성 포함)
 * - n8n에서는 이 endpoint만 POST로 호출하면 access_token을 받게 구성
 */
app.post("/token", async (req, res) => {
  try {
    if (!NAVER_CLIENT_ID || !NAVER_CLIENT_SECRET) {
      return res.status(500).json({
        error: "missing_env",
        message:
          "NAVER_CLIENT_ID or NAVER_CLIENT_SECRET is not set. Set them in Railway Variables for this service.",
      });
    }

    const timestamp = Date.now().toString();
    const password = `${NAVER_CLIENT_ID}_${timestamp}`;

    // 네이버 문서 방식: client_secret을 bcrypt salt로 사용
    // - client_secret이 salt 형태가 아니면 Invalid salt version 에러 발생
    const hashed = await bcrypt.hash(password, NAVER_CLIENT_SECRET);
    const client_secret_sign = Buffer.from(hashed).toString("base64");

    const tokenUrl = "https://api.commerce.naver.com/external/v1/oauth2/token";

    const form = new URLSearchParams();
    form.append("client_id", NAVER_CLIENT_ID);
    form.append("timestamp", timestamp);
    form.append("client_secret_sign", client_secret_sign);
    form.append("grant_type", "client_credentials");
    // 기존
    // form.append("type", "SELF");
    
    // 변경
    form.append("type", "SELLER");
    form.append("account_id", process.env.NAVER_SELLER_ACCOUNT_ID);

    const r = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });

    const raw = await r.text();

    // 로그는 너무 길어지지 않게 앞부분만
    console.log(`[TOKEN] status=${r.status} body=${raw.slice(0, 400)}`);

    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      data = { raw };
    }

    if (!r.ok) {
      // 네이버에서 내려준 에러를 그대로 반환해 디버깅하기 쉽게
      return res.status(r.status).json({
        error: "token_failed",
        status: r.status,
        response: data,
      });
    }

    // 성공: { access_token, token_type, expires_in, ... }
    return res.status(200).json(data);
  } catch (e) {
    console.error("[TOKEN_ERR]", e);
    return res.status(500).json({
      error: "token_server_error",
      message: e?.message || String(e),
      // 운영 안정화 후에는 stack은 빼도 됨
      stack: e?.stack,
    });
  }
});

// ===== 프로세스 레벨 에러 로깅(크래시 원인 찾기 용) =====
process.on("uncaughtException", (err) => console.error("[UNCAUGHT_EXCEPTION]", err));
process.on("unhandledRejection", (err) => console.error("[UNHANDLED_REJECTION]", err));

// ===== listen (Railway는 PORT를 주입) =====
const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, "0.0.0.0", () => console.log(`listening on ${PORT}`));
