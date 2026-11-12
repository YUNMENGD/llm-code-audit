// 正例：应命中 JS-SEC-003 / JS-SEC-004 / JS-SEC-005
function renderComment(comment) {
  document.getElementById("out").innerHTML = comment;   // JS-SEC-003
  document.write("<p>" + comment + "</p>");             // JS-SEC-004
}
const cp = require("child_process");
cp.exec(`convert ${req.query.file} out.png`);           // JS-SEC-005
