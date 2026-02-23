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

    // ⚠️ clientSecret이 bcrypt salt 형식이 아니면 여기서 에러 남
    const hashed = await bcrypt.hash(password, clientSecret);

    const client_secret_sign = Buffer.from(hashed).toString("base64");

    return res.json({ timestamp, client_secret_sign });
  } catch (e) {
    // 서버가 죽지 않게 에러를 JSON으로 반환
    return res.status(500).json({
      error: "sign_failed",
      message: e?.message || String(e),
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sign server running on ${PORT}`));
