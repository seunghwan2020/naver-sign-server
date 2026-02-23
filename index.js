const express = require("express");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());

app.post("/sign", async (req, res) => {
  const { clientId, clientSecret } = req.body;

  if (!clientId || !clientSecret) {
    return res.status(400).json({ error: "Missing clientId or clientSecret" });
  }

  const timestamp = Date.now().toString();
  const password = clientId + "_" + timestamp;

  const hashed = await bcrypt.hash(password, clientSecret);
  const client_secret_sign = Buffer.from(hashed).toString("base64");

  res.json({
    timestamp,
    client_secret_sign
  });
});

app.listen(3000, () => {
  console.log("Sign server running on port 3000");
});
