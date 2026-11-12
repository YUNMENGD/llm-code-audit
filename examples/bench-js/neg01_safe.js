// 反例：全部安全写法，应零命中
const data = JSON.parse(raw);                    // 不是 eval
el.textContent = comment;                        // 不是 innerHTML
el.innerHTML = "";                               // 清空豁免
db.query("SELECT * FROM users WHERE id = ?", [id]);  // 参数化
const { execFile } = require("child_process");
execFile("convert", [file, "out.png"]);          // 参数数组不经 shell
const token = crypto.randomBytes(16).toString("hex");
const agent = new https.Agent({ rejectUnauthorized: true });
const apiKey = process.env.API_KEY;              // 环境变量豁免
try { risky(); } catch (e) { console.error(e); } // 有处理
// eval( 这行是注释，不应命中
/* document.write("块注释里的也不应命中") */
if (a === b) { doThing(); }                      // 严格相等
// eslint-disable-next-line no-eval
eval(trustedConstant);                           // 显式抑制标记
