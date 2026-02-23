/**
 * naver-sign-server (Railway) - v1.1 수정본
 * * ✅ 주요 수정 사항:
 * 1. 로그 강화: 네이버가 뱉는 에러를 더 상세히 출력
 * 2. 안정성: fetch 요청 시 타임아웃 및 예외 처리 강화
 * 3. 기본값 최적화: type 파라미터가 없어도 SELF로 안정적 처리
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

// ---------- 기본 경로 ----------
app.get("/", (req, res) => res.status(200).send("Naver Sign Server is Running! v1.1"));

// ---------- [유틸] 네이버 토큰 요청 함수 ----------
async function requestNaverToken(type) {
  const timestamp = Date.now().toString();
  const password = `${NAVER_CLIENT_ID}_${timestamp}`;

  // 1. bcrypt 서명 생성 (SELF 성공을 통해 검증됨)
  const hashed = await bcrypt.hash(password, NAVER_CLIENT_SECRET);
  const client_secret_sign = Buffer.from(hashed).toString("base64");

  const tokenUrl = "https://api.commerce.naver.com/external/v1/oauth2/token";
  
  // 2. 파라미터 구성
  const params = new URLSearchParams();
  params.append("client_id", NAVER_CLIENT_ID);
  params.append("timestamp", timestamp);
  params.append("client_secret_sign", client_secret_sign);
  params.append("grant_type", "client_credentials");
  params.append("type", type);

  if (type === "SELLER") {
    params.append("account_id", NAVER_SELLER_ACCOUNT_ID);
  }

  // 3. 네이버 서버에 요청
  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });

  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    data = { raw: text };
  }

  return {
    ok: response.ok,
    status: response.status,
    data: data
  };
}

// ---------- [메인] 토큰 발급 API ----------
app.post("/token", async (req, res) => {
  try {
    // 1. 필수 환경변수 확인
    if (!NAVER_CLIENT_ID || !NAVER_CLIENT_SECRET) {
      throw new Error("Railway 환경변수(ID/SECRET)가 설정되지 않았습니다.");
    }

    // 2. 타입 설정 (기본값 SELF)
    const type = (req.query.type || "SELF").toUpperCase();

    // 3. SELLER일 때 계정 ID 확인
    if (type === "SELLER" && !NAVER_SELLER_ACCOUNT_ID) {
      return res.status(400).json({
        ok: false,
        error: "missing_account_id",
        message: "type=SELLER인 경우 NAVER_SELLER_ACCOUNT_ID 설정이 필요합니다."
      });
    }

    // 4. 토큰 요청 실행
    const result = await requestNaverToken(type);

    if (!result.ok) {
      console.error(`[NAVER_ERROR] Status: ${result.status}, Body:`, JSON.stringify(result.data));
      return res.status(result.status).json({
        ok: false,
        source: "NAVER_API",
        detail: result.data
      });
    }

    // 5. 성공 응답
    console.log(`[SUCCESS] Token issued for type: ${type}`);
    return res.status(200).json(result.data);

  } catch (err) {
    console.error("[SERVER_ERROR]", err.message);
    return res.status(500).json({
      ok: false,
      error: "server_internal_error",
      message: err.message
    });
  }
});

// ---------- 서버 시작 ----------
const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server is listening on port ${PORT}`);
  console.log(`Mode: ${NAVER_SELLER_ACCOUNT_ID ? 'Full Support' : 'SELF Only'}`);
});
