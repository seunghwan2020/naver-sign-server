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

    // ✅ 핵심 변경:
    // 1) clientSecret을 salt로 쓰지 않는다 (Invalid salt version 방지)
    // 2) 대신 password에 clientSecret을 섞어서 해시한다
    const mixed = `${password}_${clientSecret}`;

    // rounds(10) 방식은 항상 안전
    const hashed = await bcrypt.hash(mixed, 10);
    const client_secret_sign = Buffer.from(hashed).toString("base64");

    return res.json({ timestamp, client_secret_sign });
  } catch (e) {
    return res.status(500).json({
      error: "sign_failed",
      message: e?.message || String(e),
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Sign server running on port ${PORT}`));
