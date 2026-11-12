// 正例（TS）：应命中 JS-SEC-007 / JS-SEC-008 / JS-SEC-009 / JS-LOG-001 / JS-ENG-001
const token = Math.random().toString(36).slice(2);      // JS-SEC-007
const agent = new https.Agent({ rejectUnauthorized: false });  // JS-SEC-008
const apiKey = "sk-live-abcdef1234567890abcdef";        // JS-SEC-009
try {
  risky();
} catch (e) {}                                          // JS-LOG-001
debugger;                                               // JS-ENG-001
export { token, agent, apiKey };
