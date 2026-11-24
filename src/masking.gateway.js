// Claude Code 가 Anthropic 에 보내는 요청이 모두 지나가는 통로. 이 컴퓨터 안(127.0.0.1)에서만 열린다.
// 요청에 든 글(시스템 프롬프트, 질문, 도구 결과, Claude 의 지난 답 글과 도구 입력)의 개인정보를 가려서 보낸다.
// Claude 의 생각 블록은 서명이 붙어 있어 바꾸면 요청이 거절되므로 그대로 둔다.
// 응답의 답 글은 개인정보 이름표를 원래 값으로 바꿔 사람에게 보여 준다(answer-text.unmasker.js). 비밀값은 이름표로 둔다.
// 도구를 실행하기 직전 훅이 UNMASK_PATH 로 가린 값을 원래 값으로 되돌려 받는다.
// 명령 실행(Bash)은 UNMASK_WITH_SECRETS_PATH 로 비밀값까지 되돌린다. 파일 쓰기·검색에는 비밀값을 넣지 않아 파일에 남지 않게 한다.
// 요청마다 무엇이 지나갔는지 글 내용 없이 종류·개수만 기록 파일(gatewayLogFile)에 남긴다.
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import zlib from 'node:zlib';
import { createAnswerStreamUnmasker, maskPreviousAnswer, unmaskAnswerBody } from './answer-text.unmasker.js';
import { findMaskedValues, isKnownMaskedValue, maskSensitiveText, unmaskSensitiveText } from './sensitive-text.masker.js';
import { localTimeText } from './local-time.js';

const ANTHROPIC_API_ORIGIN = 'https://api.anthropic.com';
export const UNMASK_PATH = '/masking/unmask';
export const UNMASK_WITH_SECRETS_PATH = '/masking/unmask-with-secrets';
const UNMASK_PATHS = new Set([UNMASK_PATH, UNMASK_WITH_SECRETS_PATH]);
const DEFAULT_GATEWAY_LOG_FILE = path.join(import.meta.dirname, '..', 'log', 'masking-gateway.jsonl');
// 응답 글을 읽어 바꿔야 하므로 압축하지 않은 응답을 받는다(accept-encoding 을 넘기지 않는다)
const NOT_FORWARDED_HEADERS = ['host', 'connection', 'keep-alive', 'transfer-encoding', 'content-length', 'accept-encoding'];
const ERROR_BODY_LOG_LIMIT = 2000;

let maskingGatewayUrl = null;
let gatewayLogFile = DEFAULT_GATEWAY_LOG_FILE;

// listenPort 가 0 이면 비어 있는 포트를 쓴다. 프로그램이 claude 를 직접 실행하며 주소를 넘길 때 쓴다.
// 사람이 쓰는 Claude Code 앞에 둘 때는 settings.json 에 적을 고정 포트를 준다
export async function startMaskingGateway({ listenPort = 0, logFile = DEFAULT_GATEWAY_LOG_FILE } = {}) {
  gatewayLogFile = logFile;
  const gatewayServer = http.createServer((clientRequest, clientResponse) => {
    const handleRequest = UNMASK_PATHS.has(clientRequest.url) ? answerUnmask : relayRequest;
    handleRequest(clientRequest, clientResponse).catch((relayError) => failRequest(clientResponse, clientRequest.url, relayError));
  });
  await new Promise((startListening) => gatewayServer.listen(listenPort, '127.0.0.1', startListening));
  maskingGatewayUrl = `http://127.0.0.1:${gatewayServer.address().port}`;
  return maskingGatewayUrl;
}

// claude 를 실행할 때 ANTHROPIC_BASE_URL 로 넘길 주소
export function getMaskingGatewayUrl() {
  if (!maskingGatewayUrl) throw new Error('마스킹 통로가 아직 열리지 않았습니다');
  return maskingGatewayUrl;
}

async function relayRequest(clientRequest, clientResponse) {
  const startedAt = Date.now();
  const requestBody = await readStream(clientRequest);
  const { forwardBody, requestSummary } = await maskRequestBody(requestBody, clientRequest.headers);
  const upstreamResponse = await sendToAnthropic(clientRequest, forwardBody);
  clientResponse.writeHead(upstreamResponse.statusCode, withoutNotForwardedHeaders(upstreamResponse.headers));
  const responseSummary = await relayResponse(upstreamResponse, clientResponse);
  writeGatewayLog({
    path: clientRequest.url,
    status: upstreamResponse.statusCode,
    elapsedMs: Date.now() - startedAt,
    ...requestSummary,
    ...responseSummary,
  });
}

// 도구 실행 직전 훅이 보낸 도구 입력(JSON 글)의 가린 값을 원래 값으로 되돌려 돌려준다.
// 원래 값에 줄바꿈·따옴표가 있어도 JSON 이 깨지지 않도록 글자 값마다 되돌린 뒤 다시 JSON 으로 만든다.
// 가린 적 없는 이름표(neverMaskedValues)를 함께 돌려줘, 훅이 모양이 틀린 값과 원래 값이 없는 값을 나눠 알릴 수 있게 한다
async function answerUnmask(clientRequest, clientResponse) {
  const maskedToolInput = (await readStream(clientRequest)).toString('utf8');
  const unmaskOptions = { includeSecrets: clientRequest.url === UNMASK_WITH_SECRETS_PATH };
  const unmaskedToolInput = JSON.stringify(unmaskJsonStrings(JSON.parse(maskedToolInput), unmaskOptions));
  const neverMaskedValues = findMaskedValues(maskedToolInput).filter((maskedValue) => !isKnownMaskedValue(maskedValue));
  clientResponse.writeHead(200, { 'content-type': 'application/json' });
  clientResponse.end(JSON.stringify({ unmaskedToolInput, neverMaskedValues }));
  writeGatewayLog({ path: clientRequest.url, isUnmasked: unmaskedToolInput !== maskedToolInput, neverMaskedValueCount: neverMaskedValues.length });
}

function unmaskJsonStrings(jsonValue, unmaskOptions) {
  if (typeof jsonValue === 'string') return unmaskSensitiveText(jsonValue, unmaskOptions);
  if (Array.isArray(jsonValue)) return jsonValue.map((itemValue) => unmaskJsonStrings(itemValue, unmaskOptions));
  if (jsonValue && typeof jsonValue === 'object') return Object.fromEntries(Object.entries(jsonValue).map(([fieldName, fieldValue]) => [fieldName, unmaskJsonStrings(fieldValue, unmaskOptions)]));
  return jsonValue;
}

// 가릴 글을 찾아 가리고, 몇 개를 보고 몇 개를 바꿨는지 함께 돌려준다.
// 압축되어 읽을 수 없는 요청은 가리지 못한 채 보내지 않도록 실패로 끝낸다
async function maskRequestBody(requestBody, requestHeaders) {
  if (requestHeaders['content-encoding']) throw new Error(`압축된 요청은 가릴 수 없습니다 (${requestHeaders['content-encoding']})`);
  const requestJson = parseJson(requestBody);
  if (!requestJson?.messages) return { forwardBody: requestBody, requestSummary: { notMasked: '메시지가 없는 요청' } };

  const maskCount = { systemTexts: 0, userTexts: 0, toolResultTexts: 0, answerTexts: 0, toolInputs: 0, changedTexts: 0 };
  const maskCountedText = async (originalText, textKind, maskText = maskSensitiveText) => {
    maskCount[textKind] += 1;
    const maskedText = await maskText(originalText);
    if (maskedText !== originalText) maskCount.changedTexts += 1;
    return maskedText;
  };

  requestJson.system = await maskSystemPrompt(requestJson.system, maskCountedText);
  for (const message of requestJson.messages) {
    if (message.role === 'user') message.content = await maskUserContent(message.content, maskCountedText);
    if (message.role === 'assistant') message.content = await maskAssistantContent(message.content, maskCountedText);
  }
  return {
    forwardBody: Buffer.from(JSON.stringify(requestJson)),
    requestSummary: { model: requestJson.model, messages: requestJson.messages.length, ...maskCount },
  };
}

async function maskSystemPrompt(systemPrompt, maskCountedText) {
  if (typeof systemPrompt === 'string') return maskCountedText(systemPrompt, 'systemTexts');
  if (!Array.isArray(systemPrompt)) return systemPrompt;
  for (const systemBlock of systemPrompt) {
    if (systemBlock.type === 'text') systemBlock.text = await maskCountedText(systemBlock.text, 'systemTexts');
  }
  return systemPrompt;
}

async function maskUserContent(userContent, maskCountedText) {
  if (typeof userContent === 'string') return maskCountedText(userContent, 'userTexts');
  for (const contentBlock of userContent) {
    if (contentBlock.type === 'text') contentBlock.text = await maskCountedText(contentBlock.text, 'userTexts');
    if (contentBlock.type === 'tool_result') contentBlock.content = await maskToolResultContent(contentBlock.content, maskCountedText);
  }
  return userContent;
}

// 원래 값으로 바꿔 보여 준 답 글과, 도구 실행 직전에 원래 값으로 되돌린 입력이 대화 기록에 남아 다음 요청에 실려 오므로 다시 가린다.
// 가린 값에는 따옴표가 없어 도구 입력을 JSON 글째로 바꿔도 JSON 이 깨지지 않는다
async function maskAssistantContent(assistantContent, maskCountedText) {
  if (typeof assistantContent === 'string') return maskCountedText(assistantContent, 'answerTexts', maskPreviousAnswer);
  if (!Array.isArray(assistantContent)) return assistantContent;
  for (const contentBlock of assistantContent) {
    if (contentBlock.type === 'text') contentBlock.text = await maskCountedText(contentBlock.text, 'answerTexts', maskPreviousAnswer);
    if (contentBlock.type === 'tool_use') contentBlock.input = JSON.parse(await maskCountedText(JSON.stringify(contentBlock.input), 'toolInputs'));
  }
  return assistantContent;
}

async function maskToolResultContent(toolResultContent, maskCountedText) {
  if (typeof toolResultContent === 'string') return maskCountedText(toolResultContent, 'toolResultTexts');
  if (!Array.isArray(toolResultContent)) return toolResultContent;
  for (const resultBlock of toolResultContent) {
    if (resultBlock.type === 'text') resultBlock.text = await maskCountedText(resultBlock.text, 'toolResultTexts');
  }
  return toolResultContent;
}

function sendToAnthropic(clientRequest, forwardBody) {
  return new Promise((receiveResponse, failSending) => {
    const upstreamRequest = https.request(new URL(clientRequest.url, ANTHROPIC_API_ORIGIN), {
      method: clientRequest.method,
      headers: { ...withoutNotForwardedHeaders(clientRequest.headers), 'content-length': forwardBody.length },
    }, receiveResponse);
    upstreamRequest.on('error', failSending);
    upstreamRequest.end(forwardBody);
  });
}

// 응답을 사람에게 넘긴다. 스트리밍 응답은 받는 대로 답 글을 바꿔 넘기고, JSON 응답은 다 받은 뒤 바꿔 넘긴다.
// 실패 응답은 그대로 넘기고 이유를 기록하려고 본문을 돌려준다
async function relayResponse(upstreamResponse, clientResponse) {
  const contentType = upstreamResponse.headers['content-type'] ?? '';
  if (upstreamResponse.statusCode >= 400) return { errorBody: await relayErrorResponse(upstreamResponse, clientResponse) };
  if (contentType.includes('text/event-stream')) return { unmaskedAnswerTexts: await relayAnswerStream(upstreamResponse, clientResponse) };
  if (contentType.includes('application/json')) return { unmaskedAnswerTexts: await relayAnswerBody(upstreamResponse, clientResponse) };
  upstreamResponse.pipe(clientResponse);
  return {};
}

async function relayAnswerStream(upstreamResponse, clientResponse) {
  const answerStreamUnmasker = createAnswerStreamUnmasker();
  for await (const streamChunk of upstreamResponse) clientResponse.write(answerStreamUnmasker.unmaskStreamChunk(streamChunk));
  clientResponse.end(answerStreamUnmasker.finishStream());
  return answerStreamUnmasker.unmaskedAnswerCount();
}

async function relayAnswerBody(upstreamResponse, clientResponse) {
  const { shownBodyText, unmaskedAnswerCount } = unmaskAnswerBody((await readStream(upstreamResponse)).toString('utf8'));
  clientResponse.end(shownBodyText);
  return unmaskedAnswerCount;
}

async function relayErrorResponse(upstreamResponse, clientResponse) {
  const errorBodyBuffer = await readStream(upstreamResponse);
  clientResponse.end(errorBodyBuffer);
  return decodeErrorBody(errorBodyBuffer, upstreamResponse.headers['content-encoding']);
}

function failRequest(clientResponse, requestPath, relayError) {
  writeGatewayLog({ path: requestPath, status: 502, relayError: relayError.message });
  if (!clientResponse.headersSent) clientResponse.writeHead(502, { 'content-type': 'application/json' });
  clientResponse.end(JSON.stringify({ type: 'error', error: { type: 'api_error', message: '마스킹 통로에서 요청을 보내지 못했습니다' } }));
}

function writeGatewayLog(logEntry) {
  fs.mkdirSync(path.dirname(gatewayLogFile), { recursive: true });
  fs.appendFileSync(gatewayLogFile, `${JSON.stringify({ time: localTimeText(), ...logEntry })}\n`);
}

function readStream(readableStream) {
  return new Promise((finishReading, failReading) => {
    const bodyChunks = [];
    readableStream.on('data', (chunk) => bodyChunks.push(chunk));
    readableStream.on('end', () => finishReading(Buffer.concat(bodyChunks)));
    readableStream.on('error', failReading);
  });
}

function withoutNotForwardedHeaders(headers) {
  return Object.fromEntries(Object.entries(headers).filter(([headerName]) => !NOT_FORWARDED_HEADERS.includes(headerName)));
}

function parseJson(bodyBuffer) {
  try {
    return JSON.parse(bodyBuffer.toString('utf8'));
  } catch {
    return null;
  }
}

function decodeErrorBody(errorBodyBuffer, contentEncoding) {
  const decoders = { gzip: zlib.gunzipSync, br: zlib.brotliDecompressSync, deflate: zlib.inflateSync };
  try {
    const decodedBody = decoders[contentEncoding] ? decoders[contentEncoding](errorBodyBuffer) : errorBodyBuffer;
    return decodedBody.toString('utf8').slice(0, ERROR_BODY_LOG_LIMIT);
  } catch {
    return `(본문을 풀지 못함: ${contentEncoding})`;
  }
}
