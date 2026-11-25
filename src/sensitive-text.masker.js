// 글 속 비밀값(비밀번호·키·토큰)과 개인정보를 가린다.
// 마스킹 통로와 훅이 이 파일의 export 함수만 쓰므로, 다른 마스킹 방식으로 바꿀 때는 이 파일만 바꾼다.
//
// 가린 값에는 이름표를 붙인다: [휴대폰-3fa9c1 ###-####-####], [암호화키-4be1a0].
// 앞부분(라벨-해시)은 값마다 정해진다. 마스킹 키(MASKING_KEY_FILE)로 만든 해시라서 다시 켜도 같고, 키 없이는 원래 값을 알아낼 수 없다.
// Claude 는 원래 값을 모른 채 이름표를 명령에 쓰고, 실행 직전에 원래 값으로 되돌린다.
// 되돌리기 표는 이 프로그램 메모리에만 있다. 대화를 이어 쓸 때마다 앞 내용이 다시 가려지면서 표가 다시 채워진다.
//
// 비밀값은 secret-value.rules.js 의 규칙(자리·gitleaks·이름·무작위 문자열)으로 찾는다.
// 비밀값은 명령을 실행할 때만 되돌리고, 사람에게 보내는 답에서는 이름표로 둔다.
// 한 번 본 비밀값은 어떤 글에 나와도 다시 가린다. 명령 결과에 비밀값이 그대로 찍혀 나가는 것을 막는다.
//
// 개인정보 이름표의 앞부분은 구분 글자(-·.·띄어쓰기)를 뺀 본 글자로 만든다. 그래서 010-1234-5678 과 01012345678 은 앞부분이 같다.
// 뒷부분은 원래 쓰인 모양이다. # 하나가 본 글자 하나다. Claude 가 모양을 바꿔 쓰면(###########) 그 모양으로 되돌린다.
// DB 마다 저장 모양이 달라도 Claude 가 원래 값을 모른 채 맞는 모양으로 조회할 수 있게 하려는 것이다.
// 이름·주소처럼 모양이 정해지지 않은 개인정보는 찾지 못한다.
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EVERYWHERE_MASKED_SECRET_LABELS, SECRET_LABELS, maskSecretValues } from './secret-value.rules.js';

// 처음 쓸 때 만들어 본인만 읽을 수 있게 둔다. 컴퓨터끼리 같은 키를 두면 같은 값은 같은 이름표로 가려진다
const MASKING_KEY_FILE = path.join(os.homedir(), '.config', 'claude-mask-gateway', 'masking-key');
// 한 번 본 비밀값을 다른 글에서 다시 가릴 때의 최소 길이. 짧은 값은 경로·단어와 겹쳐 엉뚱한 곳까지 가린다
const KNOWN_SECRET_MIN_LENGTH = 6;
// 번호판 가운데 글자. "12월 2026" 같은 글이 차량번호로 잡히지 않게 이 글자만 본다
const VEHICLE_PLATE_LETTERS = '가나다라마거너더러머버서어저고노도로모보소오조구누두루무부수우주아바사자배하허호';
// 지역 이륜차 번호판은 자동차에 없는 글자도 쓴다
const REGIONAL_BIKE_PLATE_LETTERS = `${VEHICLE_PLATE_LETTERS}파차카타커처터`;
const PLATE_SIDO_NAMES = '서울|부산|대구|인천|광주|대전|울산|경기|강원|충북|충남|전북|전남|경북|경남|제주';
// 차량번호 모양
//   자동차:           12가3456, 123가4567
//   이륜차 전국번호판: 1가12345 (2026-03-20부터)
//   이륜차 지역번호판: 서울강남가1234, 서울 강남 가 1234, 세종가1234 (시도 + 시군구 + 글자 + 숫자 4자리, 세종은 시군구가 없다)
// 시도 없이 시군구만 적은 것(강남가1234)은 "번호가 1234" 같은 문장과 구별되지 않아 찾지 않는다
const VEHICLE_NUMBER_PATTERN = new RegExp([
  `(?<![가-힣])(?:(?:${PLATE_SIDO_NAMES}) ?[가-힣]{1,4}|세종) ?[${REGIONAL_BIKE_PLATE_LETTERS}] ?\\d{4}(?!\\d)`,
  `(?<![\\d.])\\d[${VEHICLE_PLATE_LETTERS}] ?\\d{5}(?!\\d)`,
  `(?<!\\d)\\d{2,3}[${VEHICLE_PLATE_LETTERS}] ?\\d{4}(?!\\d)`,
].join('|'), 'g');

// 앞의 규칙이 먼저 바뀐다. 주민번호(13자리)를 전화번호보다 먼저 찾는다.
// 주민번호는 사람이 쓰는 대로 앞뒤 사이에 - 나 띄어쓰기가 있어도 찾는다 (971205-1234567, 971205 - 1234567, 971205 1234567).
// separatorChars: 모양으로 남기는 구분 글자. null 이면 모양을 붙이지 않는다 (이메일은 모양이 글자 수만 드러낸다)
const PERSONAL_VALUE_RULES = [
  { label: '주민번호', pattern: /(?<!\d)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]) *-? *[1-8]\d{6}(?!\d)/g, separatorChars: '- ' },
  { label: '카드', pattern: /(?<!\d)\d{4}-\d{4}-\d{4}-\d{4}(?!\d)/g, separatorChars: '-' },
  { label: '면허', pattern: /(?<!\d)\d{2}-\d{2}-\d{6}-\d{2}(?!\d)/g, separatorChars: '-' },
  { label: '휴대폰', pattern: /(?<!\d)01[016789][-. ]?\d{3,4}[-. ]?\d{4}(?!\d)/g, separatorChars: '-. ' },
  { label: '전화', pattern: /(?<!\d)0(?:2|[3-6][1-5]|70)[-. ]?\d{3,4}[-. ]?\d{4}(?!\d)/g, separatorChars: '-. ' },
  { label: '이메일', pattern: /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, separatorChars: null },
  { label: '차량', pattern: VEHICLE_NUMBER_PATTERN, separatorChars: ' ' },
];
const SHAPE_CORE_CHAR = '#';
const MASKED_VALUE_LABELS = [...new Set([...SECRET_LABELS, ...PERSONAL_VALUE_RULES.map((valueRule) => valueRule.label)])];
// 대화를 이어 쓸 때마다 앞 내용 전체가 다시 실려 오므로, 한 번 가린 글은 결과를 기억해 다시 훑지 않는다
const MASKED_TEXT_CACHE_CHAR_LIMIT = 50_000_000;
// [라벨-해시] 또는 [라벨-해시 모양]. 모양은 # 로 시작하고 # 와 구분 글자로만 이루어진다
const MASKED_VALUE_SOURCE = `\\[(${MASKED_VALUE_LABELS.join('|')})-([0-9a-f]{6})(?: (#[#. -]*))?\\]`;
const MASKED_VALUE_PATTERN = new RegExp(MASKED_VALUE_SOURCE, 'g');
const WHOLE_MASKED_VALUE_PATTERN = new RegExp(`^${MASKED_VALUE_SOURCE}$`);

// 라벨-해시 → 원래 비밀값
const secretValueByMaskCode = new Map();
// 라벨-해시 → { coreText: 구분 글자를 뺀 본 글자, originalShape: 처음 본 모양 }
const personalValueByMaskCode = new Map();
// 원래 글 → 가린 글. 넣은 순서대로 남아 있어 오래된 것부터 지운다
const maskedTextByOriginalText = new Map();
let cachedTextCharCount = 0;
let knownSecretPattern = null;
let maskingKey = null;

export function maskSensitiveText(originalText) {
  const cachedMaskedText = maskedTextByOriginalText.get(originalText);
  if (cachedMaskedText !== undefined) return cachedMaskedText;
  const maskedText = maskPersonalValues(maskSecretValues(maskKnownSecretValues(originalText), toSecretToken));
  rememberMaskedText(originalText, maskedText);
  return maskedText;
}

// includeSecrets: 비밀값도 되돌린다. 명령을 실행할 때만 켠다. 사람에게 보내는 답에서는 비밀값을 이름표로 둔다.
// 표에 없거나 모양의 # 개수가 본 글자 수와 다르면 그대로 둔다
export function unmaskSensitiveText(maskedText, { includeSecrets = false } = {}) {
  return maskedText.replace(MASKED_VALUE_PATTERN, (maskedValue, valueLabel, valueHash, wantedShape) => {
    const maskCode = `${valueLabel}-${valueHash}`;
    if (secretValueByMaskCode.has(maskCode)) return includeSecrets && !wantedShape ? secretValueByMaskCode.get(maskCode) : maskedValue;
    const personalValue = personalValueByMaskCode.get(maskCode);
    if (!personalValue) return maskedValue;
    return fillShape(wantedShape ?? personalValue.originalShape, personalValue.coreText) ?? maskedValue;
  });
}

// 글에 가릴 값(비밀값·개인정보)이 있는지. 마스킹 통로가 가리는 규칙 그대로 보고, 이미 가린 값(이름표)이 남아 있어도 있다고 본다
export function containsSensitiveValues(someText) {
  return maskSensitiveText(someText) !== someText || findMaskedValues(someText).length > 0;
}

// 글에 든 이름표 목록 (같은 값은 한 번만)
export function findMaskedValues(someText) {
  return [...new Set(someText.match(MASKED_VALUE_PATTERN) ?? [])];
}

// 이 프로그램이 가린 적 있는 이름표인지. 사람이 직접 적었거나 통로를 다시 켜기 전에 가린 이름표는 되돌릴 원래 값이 없다
export function isKnownMaskedValue(maskedValue) {
  const [, valueLabel, valueHash] = maskedValue.match(WHOLE_MASKED_VALUE_PATTERN) ?? [];
  const maskCode = `${valueLabel}-${valueHash}`;
  return secretValueByMaskCode.has(maskCode) || personalValueByMaskCode.has(maskCode);
}

// 가린 적 없는 이름표 모양 글을 이름표가 아닌 글로 바꾼다. Claude 가 가린 값으로 알고 명령에 써서 되돌리기를 되풀이하지 않게 한다
export function markNeverMaskedValues(someText) {
  return someText.replace(MASKED_VALUE_PATTERN, (maskedValue) => (isKnownMaskedValue(maskedValue) ? maskedValue : `(가린 값 아님: ${maskedValue.slice(1, -1)})`));
}

export function isSecretMaskedValue(maskedValue) {
  const maskedLabel = maskedValue.match(WHOLE_MASKED_VALUE_PATTERN)?.[1];
  return SECRET_LABELS.includes(maskedLabel);
}

// 앞에서 본 비밀값이 모양 규칙에 걸리지 않는 곳(명령 결과의 한 줄 등)에 나와도 가린다
function maskKnownSecretValues(originalText) {
  const secretPattern = buildKnownSecretPattern();
  if (!secretPattern) return originalText;
  const maskCodeBySecretValue = new Map([...secretValueByMaskCode].map(([maskCode, secretValue]) => [secretValue, maskCode]));
  return originalText.replace(secretPattern, (secretValue) => `[${maskCodeBySecretValue.get(secretValue)}]`);
}

function maskPersonalValues(originalText) {
  let maskedText = originalText;
  for (const valueRule of PERSONAL_VALUE_RULES) {
    maskedText = maskedText.replace(valueRule.pattern, (personalValue) => toPersonalToken(valueRule, personalValue));
  }
  return maskedText;
}

// 이미 이름표인 값(앞에서 가린 글을 다시 가릴 때)은 그대로 둔다
function toSecretToken(secretLabel, secretValue) {
  if (WHOLE_MASKED_VALUE_PATTERN.test(secretValue)) return secretValue;
  const maskCode = `${secretLabel}-${hashOf(`${secretLabel}:${secretValue}`)}`;
  if (!secretValueByMaskCode.has(maskCode)) {
    secretValueByMaskCode.set(maskCode, secretValue);
    forgetKnownSecretPattern();
  }
  return `[${maskCode}]`;
}

function toPersonalToken({ label: valueLabel, separatorChars }, personalValue) {
  const valueChars = Array.from(personalValue);
  const coreText = separatorChars === null ? personalValue : valueChars.filter((valueChar) => !separatorChars.includes(valueChar)).join('');
  const valueShape = separatorChars === null ? null : valueChars.map((valueChar) => (separatorChars.includes(valueChar) ? valueChar : SHAPE_CORE_CHAR)).join('');
  const maskCode = `${valueLabel}-${hashOf(`${valueLabel}:${coreText}`)}`;
  if (!personalValueByMaskCode.has(maskCode)) personalValueByMaskCode.set(maskCode, { coreText, originalShape: valueShape });
  return valueShape === null ? `[${maskCode}]` : `[${maskCode} ${valueShape}]`;
}

// 긴 값부터 찾아야 한 값이 다른 값의 일부일 때 긴 값이 통째로 가려진다. 값 앞뒤에 글자가 붙어 있으면 다른 낱말이라 보고 두지 않는다
function buildKnownSecretPattern() {
  if (knownSecretPattern) return knownSecretPattern;
  const knownSecretValues = [...secretValueByMaskCode]
    .filter(([maskCode, secretValue]) => EVERYWHERE_MASKED_SECRET_LABELS.includes(maskCode.split('-')[0]) && isDistinctiveSecret(secretValue))
    .map(([, secretValue]) => secretValue);
  if (knownSecretValues.length === 0) return null;
  const escapedSecretValues = knownSecretValues.sort((left, right) => right.length - left.length).map((secretValue) => secretValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  knownSecretPattern = new RegExp(`(?<![A-Za-z0-9_])(?:${escapedSecretValues.join('|')})(?![A-Za-z0-9_])`, 'g');
  return knownSecretPattern;
}

// 모양의 # 자리에 본 글자를 차례로 넣는다. 모양이 없으면 본 글자 그대로, # 개수가 다르면 null
function fillShape(valueShape, coreText) {
  if (valueShape === null) return coreText;
  const coreChars = Array.from(coreText);
  const shapeChars = Array.from(valueShape);
  if (shapeChars.filter((shapeChar) => shapeChar === SHAPE_CORE_CHAR).length !== coreChars.length) return null;
  let coreCharIndex = 0;
  return shapeChars.map((shapeChar) => (shapeChar === SHAPE_CORE_CHAR ? coreChars[coreCharIndex++] : shapeChar)).join('');
}

// 다른 글에서 다시 가려도 엉뚱한 낱말과 겹치지 않을 값: 충분히 길고, 영문 낱말만으로 된 짧은 값(admin1 이 아닌 admin 등)은 아니다
function isDistinctiveSecret(secretValue) {
  if (secretValue.length < KNOWN_SECRET_MIN_LENGTH) return false;
  return /[^A-Za-z]/.test(secretValue) || secretValue.length >= 12;
}

// 새 비밀값을 알게 되면 기억해 둔 가린 글도 버린다. 그 값이 든 글을 다시 가려야 하기 때문이다
function forgetKnownSecretPattern() {
  knownSecretPattern = null;
  maskedTextByOriginalText.clear();
  cachedTextCharCount = 0;
}

function rememberMaskedText(originalText, maskedText) {
  maskedTextByOriginalText.set(originalText, maskedText);
  cachedTextCharCount += originalText.length + maskedText.length;
  for (const [oldestOriginalText, oldestMaskedText] of maskedTextByOriginalText) {
    if (cachedTextCharCount <= MASKED_TEXT_CACHE_CHAR_LIMIT) break;
    maskedTextByOriginalText.delete(oldestOriginalText);
    cachedTextCharCount -= oldestOriginalText.length + oldestMaskedText.length;
  }
}

function hashOf(hashInput) {
  return crypto.createHmac('sha256', getMaskingKey()).update(hashInput).digest('hex').slice(0, 6);
}

function getMaskingKey() {
  maskingKey ??= readOrCreateMaskingKey();
  return maskingKey;
}

function readOrCreateMaskingKey() {
  if (!fs.existsSync(MASKING_KEY_FILE)) {
    fs.mkdirSync(path.dirname(MASKING_KEY_FILE), { recursive: true, mode: 0o700 });
    if (process.platform === 'win32') grantOwnerOnlyOnWindows(path.dirname(MASKING_KEY_FILE));
    fs.writeFileSync(MASKING_KEY_FILE, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  }
  return fs.readFileSync(MASKING_KEY_FILE, 'utf8').trim();
}

// 윈도우는 mode 가 듣지 않는다. 상속 권한을 끊고 본인에게만 주며, (OI)(CI) 로 안에 만드는 키 파일까지 물려준다
function grantOwnerOnlyOnWindows(keyFolder) {
  const windowsUser = process.env.USERDOMAIN ? `${process.env.USERDOMAIN}\\${process.env.USERNAME}` : process.env.USERNAME;
  const icaclsRun = spawnSync('icacls', [keyFolder, '/inheritance:r', '/grant:r', `${windowsUser}:(OI)(CI)F`], { encoding: 'utf8' });
  if (icaclsRun.status !== 0) {
    throw new Error(`${keyFolder} 를 본인만 읽게 하지 못했습니다: ${(icaclsRun.stderr || icaclsRun.stdout || '').trim()}`);
  }
}
