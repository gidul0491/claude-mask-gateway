// 도구 실행 직전 훅(PreToolUse). Claude 는 가린 값(예: [휴대폰-3fa9c1 ###-####-####], [암호화키-4be1a0])만 알아서 명령·검색어·파일 내용에 가린 값을 쓴다.
// 실행 직전에 원래 값으로 되돌려 도구가 실제 값으로 돌게 한다. 되돌리기 표는 마스킹 통로 안에만 있어 통로에 묻는다.
// 비밀값은 명령 실행(Bash)에만 되돌린다. 파일 쓰기에 되돌리면 비밀값이 파일에 그대로 남으므로 그때는 가린 값 그대로 쓴다.
// 되돌려야 하는데 되돌리지 못한 가린 값이 남으면 실행하지 않고, 그 이유를 Claude 에게 돌려줘 고쳐 쓰게 한다.
import { findMaskedValues, isSecretMaskedValue } from './sensitive-text.masker.js';
import { UNMASK_PATH, UNMASK_WITH_SECRETS_PATH } from './masking.gateway.js';

const SECRET_UNMASK_TOOLS = new Set(['Bash']);

// 마스킹 통로(이 컴퓨터 안 127.0.0.1)를 지나지 않는 대화는 가린 값을 받은 적이 없어 되돌릴 것도 없다
if (!isThroughMaskingGateway(process.env.ANTHROPIC_BASE_URL)) process.exit(0);

const hookInput = JSON.parse(await readStandardInput());
const maskedToolInput = JSON.stringify(hookInput.tool_input);
if (findMaskedValues(maskedToolInput).length === 0) process.exit(0);

const isSecretUnmasked = SECRET_UNMASK_TOOLS.has(hookInput.tool_name);
const { unmaskedToolInput, neverMaskedValues } = await requestUnmask(maskedToolInput, isSecretUnmasked ? UNMASK_WITH_SECRETS_PATH : UNMASK_PATH);
if (neverMaskedValues.length > 0) {
  blockToolRun(`${neverMaskedValues.join(', ')} 은(는) 이 대화에서 가린 적 없는 값이라 원래 값이 없어 실행하지 않았습니다. 다시 시도하지 말고, 원래 값을 알려 달라고 답하세요.`);
}
const unknownMaskedValues = findMaskedValues(unmaskedToolInput).filter((maskedValue) => isSecretUnmasked || !isSecretMaskedValue(maskedValue));
if (unknownMaskedValues.length > 0) {
  blockToolRun(`가린 값 ${unknownMaskedValues.join(', ')} 을(를) 원래 값으로 되돌리지 못해 실행하지 않았습니다. 앞부분([휴대폰-3fa9c1 처럼 라벨-해시)은 질문이나 앞 결과에 나온 그대로 쓰고, 뒤의 모양은 # 개수를 원래 모양과 같게 쓰세요. 비밀값 이름표에는 모양을 붙이지 않습니다.`);
}
console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', updatedInput: JSON.parse(unmaskedToolInput) } }));

async function requestUnmask(toolInputText, unmaskPath) {
  try {
    const unmaskResponse = await fetch(`${process.env.ANTHROPIC_BASE_URL}${unmaskPath}`, { method: 'POST', body: toolInputText });
    if (!unmaskResponse.ok) throw new Error(`응답 ${unmaskResponse.status}`);
    return await unmaskResponse.json();
  } catch (unmaskError) {
    blockToolRun(`가린 값을 원래 값으로 되돌리지 못해 실행하지 않았습니다: ${unmaskError.message}`);
  }
}

function isThroughMaskingGateway(anthropicBaseUrl) {
  return /^http:\/\/127\.0\.0\.1:\d+/.test(anthropicBaseUrl ?? '');
}

// 종료 코드 2 로 끝내면 도구가 실행되지 않고, 표준 오류의 글이 Claude 에게 전달된다
function blockToolRun(blockReason) {
  console.error(blockReason);
  process.exit(2);
}

async function readStandardInput() {
  const inputChunks = [];
  for await (const inputChunk of process.stdin) inputChunks.push(inputChunk);
  return Buffer.concat(inputChunks).toString('utf8');
}
