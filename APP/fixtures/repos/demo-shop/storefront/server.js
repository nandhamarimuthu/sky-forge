const express = require("express");
const axios = require("axios");
const _ = require("lodash");

const app = express();
app.use(express.json());

const API = process.env.SHOP_API || "http://localhost:5000";

app.get("/health", (req, res) => res.json({ status: "ok" }));

app.get("/catalogue", async (req, res) => {
  const { data } = await axios.get(`${API}/products`);
  res.json(_.sortBy(data, "price"));
});

app.post("/basket", (req, res) => {
  const basket = _.merge({}, req.body);
  res.json({ items: basket.items || [], count: (basket.items || []).length });
});

app.get("/admin/report", (req, res) => {
  res.json({ generated: new Date().toISOString() });
});

if (require.main === module) {
  app.listen(process.env.PORT || 3000);
}

module.exports = app;
