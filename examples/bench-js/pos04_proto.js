// 正例：应命中 JS-CWE-1321 原型链污染 / JS-SEC-006 SQL / 开放重定向
function mergeConfig(target, userInput) {
  for (const key in userInput) {
    target[key] = userInput[key];        // 未过滤 __proto__，原型链污染
  }
  return target;
}
const express = require("express");
const app = express();
app.get("/go", (req, res) => {
  res.redirect(req.query.url);           // 开放重定向：外部 URL 直达 redirect
});
app.get("/user", (req, res) => {
  db.query(`SELECT * FROM u WHERE name = '${req.query.name}'`);  // SQL 拼接
});
