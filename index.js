/**
 * naver-sign-server (Railway)
 * 목적:
 *  - /health : 서버 상태 + env 세팅 여부 확인
 *  - /myip   : 현재 Railway egress 공인 IP 확인 (네이버 허용 IP 등록용)
 *  - /token  : 네이버 커머스 OAuth2 토큰 발급 (SELF/SELLER 선택 가능)
 *
 * ✅ Railway(이 서비스) Variables에 넣을 것
 *  - NAVER_CLIENT_ID
 *  - NAVER_CLIENT_SECRET   (bcrypt salt 형태: 보통 $2a$10$... 또는 $2b$10$...)
 *  - NAVER_SELLER_ACCOUNT_ID   (SELLER 토큰 필요 시)
 *
 * ✅ 사용법
 *  - SELF 토큰:   POST /token
 *  - SELLER 토큰: POST /token?type=SELLER
 *
 * ✅ n8n에서 호출 예
 *  - https://<domain>/token
 *  - https://<domain>/token?type=SELLER
 */

const express = require("express");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json({ limit: "1mb" }));

// ---------- 공통 로깅 ----------
app.use((req, res, next) => {
  console.log(`[REQ] ${req.method} ${req.url}`);
  next();
});

// ---------- 환경변수 ----------
const NAVER_CLIENT_ID = process.env.NAVER_CLIENT_ID;
const NAVER_CLIENT_SECRET = process.env.NAVER_CLIENT_SECRET;
const NAVER_SELLER_ACCOUNT_ID = process.env.NAVER_SELLER_ACCOUNT_ID;

// ---------- 기본 라우트 ----------
app.get("/", (req, res) => res.status(200).send("naver-sign-server-ok"));

app.get("/health", (req, res) => {
  res.status(200).json({
    ok: true,
    service: "naver-sign-server",
    node: process.version,
    env: {
      hasClientId: !!NAVER_CLIENT_ID,
      hasClientSecret: !!NAVER_CLIENT_SECRET,
      hasSellerAccountId: !!NAVER_SELLER_ACCOUNT_ID,
    },
  });
});

// ---------- 공인 IP 확인 ----------
app.get("/myip", async (req, res) => {
  try {
    const r = await fetch("https://api.ipify.org?format=json");
    const data = await r.json();
    return res.status(200).json({ ip: data.ip });
  } catch (e) {
    return res.status(500).json({
      error: "ip_check_failed",
      message: e?.message || String(e),
    });
  }
});

// ---------- 유틸: 네이버 토큰 요청 ----------
async function requestNaverToken({ type }) {
  const timestamp = Date.now().toString();
  const password = `${NAVER_CLIENT_ID}_${timestamp}`;

  // 네이버 방식: client_secret을 bcrypt salt로 사용
  // client_secret이 salt 형태가 아니면 "Invalid salt version" 에러 발생
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
  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    data = { raw };
  }

  return {
    ok: r.ok,
    status: r.status,
    data,
    debug: {
      type,
      timestamp,
      hasClientSecretSign: !!client_secret_sign,
      accountIdSent: type === "SELLER" ? (NAVER_SELLER_ACCOUNT_ID || "MISSING") : "N/A",
    },
    rawPreview: raw.slice(0, 500),
  };
}

// ---------- 토큰 발급 ----------
app.post("/token", async (req, res) => {
  try {
    // 1) env 체크
    if (!NAVER_CLIENT_ID || !NAVER_CLIENT_SECRET) {
      return res.status(500).json({
        error: "missing_env",
        message:
          "NAVER_CLIENT_ID or NAVER_CLIENT_SECRET is not set. Set them in Railway Variables for naver-sign-server.",
      });
    }

    // 2) type 파라미터 (기본 SELF)
    const type = (req.query.type || "SELF").toString().toUpperCase();
    if (!["SELF", "SELLER"].includes(type)) {
      return res.status(400).json({
        error: "bad_request",
        message: "type must be SELF or SELLER",
        received: type,
      });
    }

    // 3) SELLER일 경우 account_id 필수
    if (type === "SELLER" && !NAVER_SELLER_ACCOUNT_ID) {
      return res.status(500).json({
        error: "missing_env",
        message:
          "type=SELLER requires NAVER_SELLER_ACCOUNT_ID in Railway Variables for naver-sign-server.",
      });
    }

    // 4) 네이버 토큰 요청
    const result = await requestNaverToken({ type });

    console.log(`[TOKEN] status=${result.status} body=${result.rawPreview}`);

    // 5) 실패면 네이버 응답을 그대로 전달 + 디버그 포함
    if (!result.ok) {
      return res.status(result.status).json({
        error: "token_failed",
        status: result.status,
        response: result.data, // 네이버가 준 code/message/traceId 가 여기 들어옴
        debug: result.debug,
      });
    }

    // 6) 성공이면 그대로 반환 (access_token, token_type, expires_in 등)
    return res.status(200).json(result.data);
  } catch (e) {
    console.error("[TOKEN_ERR]", e);
    return res.status(500).json({
      error: "token_server_error",
      message: e?.message || String(e),
      stack: e?.stack,
    });
  }
});

// ---------- 프로세스 레벨 에러 로그 ----------
process.on("uncaughtException", (err) => console.error("[UNCAUGHT_EXCEPTION]", err));
process.on("unhandledRejection", (err) => console.error("[UNHANDLED_REJECTION]", err));

// ---------- listen (Railway PORT 사용) ----------
const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, "0.0.0.0", () => console.log(`listening on ${PORT}`));
