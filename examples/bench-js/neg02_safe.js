// 反例：安全写法，应零命中
function safeMerge(target, userInput) {
  for (const key of Object.keys(userInput)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
    target[key] = userInput[key];        // 危险键已过滤
  }
  return target;
}
const ALLOW = new Set(["/home", "/about"]);
app.get("/go", (req, res) => {
  const url = ALLOW.has(req.query.url) ? req.query.url : "/home";  // 白名单
  res.redirect(url);
});
db.query("SELECT * FROM u WHERE name = ?", [req.query.name]);      // 参数化
const obj = yaml.load(raw, { schema: yaml.SAFE_SCHEMA });          // 安全 schema
const secret = process.env.SECRET;                                 // 环境变量
