// 글 속 비밀값(비밀번호·키·토큰)을 찾아 toSecretToken 으로 받은 이름표로 바꾼다.
// 앞의 규칙부터 차례로 찾는다. 이미 이름표가 된 값은 toSecretToken 이 그대로 돌려준다.
// 1. 자리 규칙: 접속 주소·SQL·암호화 함수에서 비밀값이 오는 자리
// 2. gitleaks 규칙: 서비스별 키·토큰 모양과, 키 이름 옆의 무작위 값
// 3. 이름 규칙: password·secret·key 같은 이름에 붙은 값
// 4. 무작위 문자열 규칙: 이름이 없어도 따옴표 안에서 키처럼 무작위로 보이는 긴 값
import { GITLEAKS_LABELS, isGloballyAllowedSecret, maskByGitleaksRules, shannonEntropyOf } from './gitleaks/gitleaks-rules.js';

// SQL 문자열: N'…' 도 받고, 값 안의 '' 는 따옴표 한 글자다
const sqlTextOf = (groupName) => `N?'(?<${groupName}>(?:[^'\\n]|''){4,})'`;
// 이 낱말이 든 이름의 값은 비밀값으로 본다
const STRONG_SECRET_WORDS = 'pass|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|auth[_-]?key|credential';
// 이 낱말로 끝나는 이름은 값이 키처럼 생겼을 때만 비밀값으로 본다 (cacheKey: 'user_list' 같은 것은 두려고)
const KEY_WORDS = 'key|salt|iv|cipher';
// 이름의 첫 글자에서만 찾기 시작해야 긴 줄에서 글자마다 다시 훑지 않는다
const SECRET_NAME = `(?<![A-Za-z0-9_.-])(?<secretName>[A-Za-z0-9_.-]*?(?:${STRONG_SECRET_WORDS}|${KEY_WORDS})[A-Za-z0-9_.-]*)`;
// 키 낱말로 끝나도 비밀값이 아닌 이름의 앞부분: primaryKey, cache_key, publicKey 등
const NOT_SECRET_KEY_NAME_HEAD = /(?:primary|foreign|unique|sort|partition|cache|redis|row|map|index|lookup|storage|translation|i18n|route|query|object|dict|composite|surrogate|public|group|cluster|hot|short|shortcut|press|event|react|list|item|column|table|field|id)[_.-]?$/i;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// 파일이 바뀌지 않았는지 보는 공개 해시(package-lock 의 integrity 등). 비밀값이 아니다
const FILE_CHECKSUM_PATTERN = /^sha(?:1|256|384|512)-/;
// 예시 주소·설명에 쓰는 자리표시 값: driver://username:password@, password: 'changeme', '<비밀번호>'
const PLACEHOLDER_SECRET_PATTERN = /^(?:password|passwd|pass|pwd|secret|username|user|changeme|example|sample|test|dummy|x{3,}|\*{3,}|your[_-]?[a-z_-]*|<[^>]*>)$/i;
const RANDOM_STRING_MIN_ENTROPY = 4;
// 이 이름표의 값은 모양이 분명한 자리에서 찾은 것이라, 다른 글에 그대로 나와도 다시 가린다 (명령 결과에 찍힌 키 등).
// 이름·무작위 문자열로 짐작한 비밀값(비밀값)은 잘못 짐작했을 때 같은 글자가 들어간 곳마다 가려지므로 넣지 않는다
export const EVERYWHERE_MASKED_SECRET_LABELS = ['암호화키', '비밀번호', '개인키', '접근키', '토큰'];

const POSITION_RULES = [
  // 접속 주소 안의 비밀번호: mysql://아이디:비밀번호@호스트
  { label: '비밀번호', pattern: /(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*:\/\/[^\s:/@"'`]+:(?<secret1>[^\s@/"'`]+)@/gi },
  // MySQL: AES_ENCRYPT(값, '키'), CREATE USER … IDENTIFIED BY '비밀번호'
  { label: '암호화키', pattern: new RegExp(`AES_(?:EN|DE)CRYPT\\s*\\([^,]*,\\s*(?:${sqlTextOf('secret1')}|"(?<secret2>[^"\\n]{4,})")`, 'gi') },
  { label: '비밀번호', pattern: new RegExp(`IDENTIFIED\\s+(?:WITH\\s+\\w+\\s+)?BY\\s+${sqlTextOf('secret1')}`, 'gi') },
  // MSSQL: ENCRYPTBYPASSPHRASE('키', 값). OPEN SYMMETRIC KEY … WITH PASSWORD = '…' 는 이름 규칙이 찾는다
  { label: '암호화키', pattern: new RegExp(`(?:EN|DE)CRYPTBYPASSPHRASE\\s*\\(\\s*${sqlTextOf('secret1')}`, 'gi') },
  // Node: crypto.createCipheriv('aes-128-ecb', '키', …), crypto.createHmac('sha256', '키')
  { label: '암호화키', pattern: /\bcreate(?:Cipheriv|Decipheriv|Hmac)\(\s*(['"`])[^'"`\n]*\1\s*,\s*(['"`])(?<secret1>[^'"`\n]{4,})\2/g },
  // PHP: openssl_encrypt($값, 'AES-128-ECB', '키'), hash_hmac('sha256', $값, '키')
  { label: '암호화키', pattern: /\b(?:openssl_(?:en|de)crypt|hash_hmac)\(\s*[^,\n]+,\s*[^,\n]+,\s*(['"])(?<secret1>[^'"\n]{4,})\1/g },
  // Java: new SecretKeySpec("키".getBytes(), "AES"), new IvParameterSpec("값".getBytes())
  { label: '암호화키', pattern: /\bnew\s+(?:SecretKeySpec|IvParameterSpec)\(\s*"(?<secret1>[^"\n]{4,})"/g },
];

const NAME_RULES = [
  // 이름에 붙은 따옴표 값: password: "값", DB_PASS = '값', "apiKey": "값", WITH PASSWORD = N'값'
  { label: '비밀값', pattern: new RegExp(`["']?${SECRET_NAME}["']?\\s*[:=]\\s*(?:${sqlTextOf('secret1')}|"(?<secret2>[^"\\n]{4,})"|\`(?<secret3>[^\`\\n]{4,})\`)`, 'gi'), isSecret: isNamedSecret },
  // 설정 파일 한 줄의 따옴표 없는 값: DB_PASSWORD=값, password: 값
  { label: '비밀값', pattern: new RegExp(`^\\s*${SECRET_NAME}\\s*[:=]\\s*(?<secret1>[^\\s"'\`#;,]{4,}),?\\s*$`, 'gim'), isSecret: isNamedSecret },
];

const RANDOM_STRING_RULES = [
  { label: '비밀값', pattern: /(['"`])(?<secret1>[A-Za-z0-9+/=_\-.~!@#$%^&*]{20,200})\1/g, isSecret: isRandomLookingSecret },
];

export const SECRET_LABELS = [...new Set([...POSITION_RULES, ...NAME_RULES, ...RANDOM_STRING_RULES].map((secretRule) => secretRule.label).concat(GITLEAKS_LABELS))];

export function maskSecretValues(originalText, toSecretToken) {
  let maskedText = maskBySecretRules(originalText, POSITION_RULES, toSecretToken);
  maskedText = maskByGitleaksRules(maskedText, toSecretToken);
  maskedText = maskBySecretRules(maskedText, NAME_RULES, toSecretToken);
  return maskBySecretRules(maskedText, RANDOM_STRING_RULES, toSecretToken);
}

// 규칙의 secret 으로 시작하는 이름 묶음 중 값이 있는 것이 비밀값이다. 찾은 글에서 그 값만 이름표로 바꾼다.
// 이름과 값이 같은 글일 수 있어(password: 'password') 값은 뒤에서부터 찾는다
function maskBySecretRules(originalText, secretRules, toSecretToken) {
  let maskedText = originalText;
  for (const secretRule of secretRules) {
    maskedText = maskedText.replace(secretRule.pattern, (...replaceArgs) => {
      const matchedText = replaceArgs[0];
      const namedGroups = replaceArgs.at(-1);
      const secretText = Object.entries(namedGroups).find(([groupName, groupValue]) => groupName.startsWith('secret') && groupName !== 'secretName' && groupValue)?.[1];
      if (!secretText || isPlaceholderSecret(secretText) || (secretRule.isSecret && !secretRule.isSecret(secretText, namedGroups))) return matchedText;
      const secretIndex = matchedText.lastIndexOf(secretText);
      return `${matchedText.slice(0, secretIndex)}${toSecretToken(secretRule.label, secretText)}${matchedText.slice(secretIndex + secretText.length)}`;
    });
  }
  return maskedText;
}

// 키 이름의 값은 숫자만 있어도 IV 같은 비밀값일 수 있어, 숫자·참과 거짓 예외는 password·token 같은 이름에만 둔다
function isNamedSecret(secretText, { secretName }) {
  if (isCodeReference(secretText) || isIdentifierLike(secretText)) return false;
  if (hasWordInName(secretName, STRONG_SECRET_WORDS)) return !isPlainSetting(secretText);
  return isKeyName(secretName) && looksLikeKeyValue(secretText);
}

// 낱말이 이름 안의 한 낱말일 때만: db_pass, PASSWORD, loginPassword 는 되고 minipass, bypass, compass 는 안 된다
function hasWordInName(secretName, nameWords) {
  for (const wordMatch of secretName.matchAll(new RegExp(nameWords, 'gi'))) {
    const nameHead = secretName.slice(0, wordMatch.index);
    if (nameHead === '' || /[^A-Za-z]$/.test(nameHead) || /[A-Z]/.test(wordMatch[0][0])) return true;
  }
  return false;
}

// 키 낱말이 이름 끝의 낱말일 때만: aesKey, AES_KEY, enc-iv 는 되고 monkey, div 는 안 된다
function isKeyName(secretName) {
  const keyWord = secretName.match(new RegExp(`(?:${KEY_WORDS})$`, 'i'))?.[0];
  if (!keyWord) return false;
  const nameHead = secretName.slice(0, -keyWord.length);
  const isWordStart = nameHead === '' || /[^A-Za-z]$/.test(nameHead) || /[A-Z]/.test(keyWord[0]);
  return isWordStart && !NOT_SECRET_KEY_NAME_HEAD.test(nameHead);
}

// 키 값처럼 생긴 값: 8자 이상이고 글자 종류가 섞였거나 16자 이상. user_list 처럼 낱말을 이은 값은 아니다
function looksLikeKeyValue(secretText) {
  if (secretText.length < 8 || /^[A-Za-z]+(?:[_.:-][A-Za-z]+)*$/.test(secretText)) return false;
  return charKindCountOf(secretText) >= 2 || secretText.length >= 16;
}

// 이름 없이 따옴표 안에 있는 값은 대소문자·숫자가 모두 있고 충분히 무작위해야 비밀값으로 본다. UUID 는 뺀다
function isRandomLookingSecret(secretText) {
  if (UUID_PATTERN.test(secretText) || FILE_CHECKSUM_PATTERN.test(secretText) || isPathOrAddress(secretText)) return false;
  const hasEveryLetterKind = /[a-z]/.test(secretText) && /[A-Z]/.test(secretText) && /[0-9]/.test(secretText);
  return hasEveryLetterKind && shannonEntropyOf(secretText) >= RANDOM_STRING_MIN_ENTROPY;
}

function isPlaceholderSecret(secretText) {
  return PLACEHOLDER_SECRET_PATTERN.test(secretText) || isGloballyAllowedSecret(secretText);
}

function charKindCountOf(someText) {
  return [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((charKindPattern) => charKindPattern.test(someText)).length;
}

// 비밀값이 아닌 설정: 다른 곳을 가리키는 코드, 숫자(tokenExpireSeconds: 3600), true·false·null
function isPlainSetting(configValue) {
  return isCodeReference(configValue) || /^\d+$/.test(configValue) || /^(true|false|null)$/i.test(configValue);
}

// 값 대신 다른 곳을 가리키는 코드: req.body.password, process.env.DB_PASS, $loginPassword, ${DB_PASS}, 패키지 판 ^3.1.6
function isCodeReference(configValue) {
  return /^[A-Za-z_$][\w$]*(\.[\w$]+)+$/.test(configValue)
    || /^\$[A-Za-z_]\w*$/.test(configValue)
    || /^\$\{[^}]+\}$/.test(configValue)
    || /^[~^<>=]*\d+(?:\.[\dx*]+)+(?:-[\w.]+)?$/.test(configValue);
}

// 낱말을 _·- 로 이은 이름 같은 값: authentication_string, passport-local. 비밀번호로 쓰는 일이 거의 없다
function isIdentifierLike(secretText) {
  return /^[a-z]+(?:[_-][a-z]+)+$/.test(secretText);
}

// 주소·경로·선택자: /api/v1/list, ./img/a.png, #cfg_Servers. + 나 = 가 없는 / 는 키보다 경로에 가깝다
function isPathOrAddress(secretText) {
  return /^[#./]/.test(secretText) || (secretText.includes('/') && !/[+=]/.test(secretText));
}
