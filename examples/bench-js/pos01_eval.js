// 正例：应命中 JS-SEC-001 / JS-SEC-002 / JS-SEC-006
const userInput = location.hash.slice(1);
const result = eval(userInput);            // JS-SEC-001
const fn = new Function("x", userInput);   // JS-SEC-002
db.query(`SELECT * FROM users WHERE id = ${userInput}`);  // JS-SEC-006
console.log(result, fn);
