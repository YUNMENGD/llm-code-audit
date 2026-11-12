// 正例（TS）：不安全反序列化 / 动态执行 / 硬编码密钥
import * as yaml from "js-yaml";
export function loadProfile(raw: string) {
  const obj = yaml.load(raw);            // 非 safeLoad，可构造任意对象 RCE
  const fn = new Function("return " + obj.code);   // 动态执行
  return fn();
}
const secret = "sk-prod-zyxwvutsrqponmlkjihg987654";  // 硬编码密钥
export { secret };
