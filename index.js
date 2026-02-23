const express = require("express");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());

app.get("/health", (req, res) => res.status(200).send("ok"));

app.post("/sign", async (req, res) => {
  try {
    const { clientId, clientSecret } = req.body || {};

    if (!clientId || !clientSecret) {
      return res.status(400).json({ error: "Missing clientId or clientSecret" });
    }

    const timestamp = Date.now().toString();
    const password = `${clientId}_${timestamp}`;

    const hashed = await bcrypt.hash(password, clientSecret); // 기존 방식 유지
    const client_secret_sign = Buffer.from(hashed).toString("base64");

    return res.json({ timestamp, client_secret_sign });
  } catch (e) {
    // ✅ 서버 크래시 방지
    return res.status(500).json({
      error: "sign_failed",
      message: e?.message || String(e),
      hint:
        "clientSecret이 bcrypt salt 형식($2a$10$...)이 아니거나 n8n expression이 그대로 전달된 경우입니다.",
      receivedClientSecretPrefix:
        typeof req?.body?.clientSecret === "string"
          ? req.body.clientSecret.slice(0, 10)
          : null,
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sign server running on port ${PORT}`));
