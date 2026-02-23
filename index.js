const express = require("express");
const app = express();

app.get("/", (req, res) => res.status(200).send("ok-root"));
app.get("/health", (req, res) => res.status(200).send("ok-health"));

const PORT = Number(process.env.PORT || 3000);

// ✅ 핵심: 외부에서 접근 가능하도록 0.0.0.0 바인딩
app.listen(PORT, "0.0.0.0", () => {
  console.log(`listening on ${PORT}`);
});
