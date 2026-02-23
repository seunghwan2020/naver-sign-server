/**
 * naver-sign-server (Railway) - v1.2 최종 완전판
 * ✅ 포함 기능: /token(토큰발급), /myip(IP확인), /health(상태체크)
 */

const express = require("express");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json({ limit: "1mb" }));

// ---------- 환경변수 체크 ----------
const { NAVER_CLIENT_ID, NAVER_CLIENT_SECRET, NAVER_SELLER_ACCOUNT_ID } = process.env;

// ---------- [미들웨어] 모든 요청 로그 출력 ----------
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ---------- 1. 기본 경로 ----------
app.get("/", (req, res) => res.status(200).send("Naver Sign Server is Running! v1.2"));

// ---------- 2. 공인 IP 확인 (/myip) ----------
// 네이버 커머스 센터에 등록할 IP를 확인하는 용도입니다.
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

// ---------- 3. 서버 상태 확인 (/health) ----------
app.get("/health", (req, res) => {
  res.status(200).json({
    ok: true,
    env: {
      hasClientId: !!NAVER_CLIENT_ID,
      hasClientSecret: !!NAVER_CLIENT_SECRET,
      hasSellerAccountId: !!NAVER_SELLER_ACCOUNT_ID,
    },
  });
});

// ---------- [유틸] 네이버 토큰 요청 함수 ----------
async function requestNaverToken(type) {
  const timestamp = Date.now().toString();
  const password = `${NAVER_CLIENT_ID}_${timestamp}`;

  const hashed = await bcrypt.hash(password, NAVER_CLIENT_SECRET);
  const client_secret_sign = Buffer.from(hashed).toString("base64");

  const tokenUrl = "https://api.commerce.naver.com/external/v1/oauth2/token";
  const params = new URLSearchParams();
  params.append("client_id", NAVER_CLIENT_ID);
  params.append("timestamp", timestamp);
  params.append("client_secret_sign", client_secret_sign);
  params.append("grant_type", "client_credentials");
  params.append("type", type);

  if (type === "SELLER") {
    params.append("account_id", NAVER_SELLER_ACCOUNT_ID);
  }

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });

  const text = await response.text();
  let data;
  try { data = JSON.parse(text); } catch (e) { data = { raw: text }; }

  return { ok: response.ok, status: response.status, data };
}

// ---------- 4. 토큰 발급 API (/token) ----------
app.post("/token", async (req, res) => {
  try {
    if (!NAVER_CLIENT_ID || !NAVER_CLIENT_SECRET) {
      throw new Error("Railway 환경변수가 설정되지 않았습니다.");
    }

    const type = (req.query.type || "SELF").toUpperCase();

    if (type === "SELLER" && !NAVER_SELLER_ACCOUNT_ID) {
      return res.status(400).json({ error: "missing_account_id" });
    }

    const result = await requestNaverToken(type);

    if (!result.ok) {
      return res.status(result.status).json({
        ok: false,
        error: "token_failed",
        response: result.data // 여기에 "호출이 허용되지 않은 IP" 메시지가 담겨서 나옵니다.
      });
    }

    return res.status(200).json(result.data);
  } catch (err) {
    return res.status(500).json({ error: "server_error", message: err.message });
  }
});

// ---------- 서버 시작 ----------
const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server v1.2 listening on port ${PORT}`);
});
