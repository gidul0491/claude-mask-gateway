// gitleaks 의 비밀값 탐지 규칙(rules.json)으로 글 속 비밀값을 찾아 이름표로 바꾼다.
// rules.json 은 gitleaks.toml 을 convert-rules.py 로 바꾼 것이다. 규칙을 고칠 때는 gitleaks.toml 을 새로 받아 다시 바꾼다.
// gitleaks 처럼 규칙마다 다음을 따른다.
// - keywords 중 하나가 글에 있을 때만 그 규칙을 돌린다 (빠르게 하려는 것)
// - 비밀값은 secretGroup 번째 묶음, 없으면 처음으로 값이 있는 묶음, 묶음이 없으면 찾은 글 전체다
// - entropy 가 있으면 비밀값이 그만큼 무작위해야 비밀값으로 본다
// - allowlists 에 걸리는 값(예시 값·변수 자리표시 등)은 비밀값으로 보지 않는다
import fs from 'node:fs';
import path from 'node:path';

const RULES_DOCUMENT = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, 'rules.json'), 'utf8'));
// 서비스별 규칙을 먼저 돌리고 generic- 규칙(키 이름 옆 무작위 값)은 맨 뒤에 돌린다. 먼저 돌면 서비스 키도 이름표 종류가 비밀값이 된다
const GITLEAKS_RULES = RULES_DOCUMENT.rules.toSorted((leftRule, rightRule) => Number(leftRule.id.startsWith('generic-')) - Number(rightRule.id.startsWith('generic-'))).map((gitleaksRule) => ({
  ...gitleaksRule,
  label: labelOfRule(gitleaksRule.id),
  regex: new RegExp(gitleaksRule.pattern, `g${gitleaksRule.flags}`),
  allowlists: gitleaksRule.allowlists.map(compileAllowlist),
}));
const GLOBAL_ALLOWLIST = compileAllowlist(RULES_DOCUMENT.globalAllowlist);

export const GITLEAKS_LABELS = [...new Set(GITLEAKS_RULES.map((gitleaksRule) => gitleaksRule.label))];

// gitleaks 가 어느 규칙에서나 비밀값으로 보지 않는 값: true·false·null, 같은 글자 반복, $VAR·${VAR}·{{ }} 같은 자리표시, 경로 등
export function isGloballyAllowedSecret(secretText) {
  return isAllowedBy(GLOBAL_ALLOWLIST, secretText, secretText);
}

export function maskByGitleaksRules(originalText, toSecretToken) {
  const lowerCaseText = originalText.toLowerCase();
  let maskedText = originalText;
  for (const gitleaksRule of GITLEAKS_RULES) {
    if (gitleaksRule.keywords.length > 0 && !gitleaksRule.keywords.some((keyword) => lowerCaseText.includes(keyword))) continue;
    maskedText = maskedText.replace(gitleaksRule.regex, (...replaceArgs) => maskMatchedSecret(gitleaksRule, replaceArgs, toSecretToken));
  }
  return maskedText;
}

function maskMatchedSecret(gitleaksRule, replaceArgs, toSecretToken) {
  const matchedText = replaceArgs[0];
  const secretText = secretOfMatch(gitleaksRule, replaceArgs);
  if (!secretText || isAllowedSecret(gitleaksRule, secretText, matchedText)) return matchedText;
  // 키 이름과 값이 같은 글일 수 있어 값은 뒤에서부터 찾는다
  const secretIndex = matchedText.lastIndexOf(secretText);
  return `${matchedText.slice(0, secretIndex)}${toSecretToken(gitleaksRule.label, secretText)}${matchedText.slice(secretIndex + secretText.length)}`;
}

// replace 콜백 인자: 찾은 글, 묶음들..., 위치(숫자), 원래 글, [이름 붙은 묶음]
function secretOfMatch(gitleaksRule, replaceArgs) {
  const offsetIndex = replaceArgs.findIndex((replaceArg, argIndex) => argIndex > 0 && typeof replaceArg === 'number');
  const capturedGroups = replaceArgs.slice(1, offsetIndex);
  if (gitleaksRule.secretGroup > 0) return capturedGroups[gitleaksRule.secretGroup - 1];
  return capturedGroups.find((capturedGroup) => capturedGroup) ?? replaceArgs[0];
}

function isAllowedSecret(gitleaksRule, secretText, matchedText) {
  if (gitleaksRule.entropy > 0 && shannonEntropyOf(secretText) < gitleaksRule.entropy) return true;
  if (isAllowedBy(GLOBAL_ALLOWLIST, secretText, matchedText)) return true;
  return gitleaksRule.allowlists.some((ruleAllowlist) => isAllowedBy(ruleAllowlist, secretText, matchedText));
}

// condition 이 AND 면 정해 둔 조건(정규식·금지어)을 모두 만족해야, OR 면 하나만 만족해도 허용한다
function isAllowedBy(allowlist, secretText, matchedText) {
  const checkedText = allowlist.regexTarget === 'secret' ? secretText : matchedText;
  const allowChecks = [];
  if (allowlist.regexes.length > 0) allowChecks.push(allowlist.regexes.some((allowRegex) => allowRegex.test(checkedText)));
  if (allowlist.stopwords.length > 0) allowChecks.push(allowlist.stopwords.some((stopword) => secretText.toLowerCase().includes(stopword)));
  if (allowChecks.length === 0) return false;
  return allowlist.condition === 'AND' ? allowChecks.every(Boolean) : allowChecks.some(Boolean);
}

function compileAllowlist(allowlist) {
  return { ...allowlist, regexes: allowlist.regexes.map((allowPattern) => new RegExp(allowPattern.pattern, allowPattern.flags)) };
}

// 글자당 정보량(비트). 같은 글자가 반복될수록 낮고, 고르게 섞일수록 높다
export function shannonEntropyOf(someText) {
  const countByChar = new Map();
  for (const someChar of someText) countByChar.set(someChar, (countByChar.get(someChar) ?? 0) + 1);
  let entropyBits = 0;
  for (const charCount of countByChar.values()) {
    const charRatio = charCount / someText.length;
    entropyBits -= charRatio * Math.log2(charRatio);
  }
  return entropyBits;
}

function labelOfRule(ruleId) {
  if (/private-key/.test(ruleId)) return '개인키';
  if (/password|passwd/.test(ruleId)) return '비밀번호';
  if (/token|jwt|pat\b|-pat-/.test(ruleId)) return '토큰';
  if (/^generic-/.test(ruleId)) return '비밀값';
  return '접근키';
}
