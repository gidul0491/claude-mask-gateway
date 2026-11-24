// Claude 가 쓴 답 글(text 블록)의 개인정보 이름표를 원래 값으로 바꿔 사람에게 보여 준다. 비밀값은 이름표로 둔다.
// 생각 블록(서명이 있다)과 도구 입력(실행 직전 훅이 되돌린다)은 바꾸지 않는다.
// 바꿔 보여 준 답 글은 다음 요청의 대화 기록에 그대로 실려 오므로, 그때 Claude 가 처음 쓴 가린 글로 되돌려 보낸다.
//
// 스트리밍 응답은 이벤트(event: …\ndata: {json}\n\n)가 조각으로 온다. 이름표가 두 조각에 걸칠 수 있어,
// 닫히지 않은 [ 부터는 다음 조각이 올 때까지 붙잡아 두었다가 함께 바꾼다.
import { StringDecoder } from 'node:string_decoder';
import { maskSensitiveText, unmaskSensitiveText } from './sensitive-text.masker.js';

// 이름표 하나의 최대 길이. 이보다 길게 닫히지 않은 [ 는 이름표가 아니라 보고 붙잡지 않는다
const MASKED_VALUE_MAX_LENGTH = 80;
const SHOWN_ANSWER_CHAR_LIMIT = 20_000_000;

// 보여 준 답 글 → Claude 가 처음 쓴 가린 글. 넣은 순서대로 남아 있어 오래된 것부터 지운다
const maskedAnswerByShownAnswer = new Map();
let shownAnswerCharCount = 0;

// 스트리밍 응답 하나를 이어서 바꾸는 변환기. 받은 조각을 넣으면 사람에게 보낼 글을 돌려준다
export function createAnswerStreamUnmasker() {
  const utf8Decoder = new StringDecoder('utf8');
  const answerBlockByIndex = new Map();
  let unparsedStreamText = '';
  let unmaskedAnswerCount = 0;

  function unmaskStreamChunk(streamChunk) {
    unparsedStreamText += utf8Decoder.write(streamChunk);
    const completeEvents = unparsedStreamText.split('\n\n');
    unparsedStreamText = completeEvents.pop();
    return completeEvents.map(rewriteStreamEvent).join('');
  }

  function finishStream() {
    return unparsedStreamText + utf8Decoder.end();
  }

  function rewriteStreamEvent(streamEventText) {
    const eventData = parseEventData(streamEventText);
    const answerBlock = answerBlockByIndex.get(eventData?.index);
    if (eventData?.type === 'content_block_start' && eventData.content_block?.type === 'text') {
      answerBlockByIndex.set(eventData.index, { maskedText: '', shownText: '', heldText: '' });
    }
    if (eventData?.type === 'content_block_delta' && eventData.delta?.type === 'text_delta' && answerBlock) {
      return toTextDeltaEvent(eventData, takeShownText(answerBlock, eventData.delta.text));
    }
    if (eventData?.type === 'content_block_stop' && answerBlock) {
      answerBlockByIndex.delete(eventData.index);
      const lastShownText = takeShownText(answerBlock, '', { isBlockEnd: true });
      if (rememberShownAnswer(answerBlock.shownText, answerBlock.maskedText)) unmaskedAnswerCount += 1;
      return toTextDeltaEvent({ type: 'content_block_delta', index: eventData.index, delta: { type: 'text_delta', text: '' } }, lastShownText) + `${streamEventText}\n\n`;
    }
    return `${streamEventText}\n\n`;
  }

  return { unmaskStreamChunk, finishStream, unmaskedAnswerCount: () => unmaskedAnswerCount };
}

// 스트리밍이 아닌 응답 본문(JSON)의 답 글을 바꾼다. 몇 개를 바꿨는지 함께 돌려준다
export function unmaskAnswerBody(responseBodyText) {
  const responseJson = parseJson(responseBodyText);
  if (!Array.isArray(responseJson?.content)) return { shownBodyText: responseBodyText, unmaskedAnswerCount: 0 };
  let unmaskedAnswerCount = 0;
  for (const contentBlock of responseJson.content) {
    if (contentBlock.type !== 'text') continue;
    const maskedText = contentBlock.text;
    contentBlock.text = unmaskSensitiveText(maskedText);
    if (rememberShownAnswer(contentBlock.text, maskedText)) unmaskedAnswerCount += 1;
  }
  return { shownBodyText: JSON.stringify(responseJson), unmaskedAnswerCount };
}

// 대화 기록에 실려 온 지난 답 글을 다시 가린다. 이 통로가 바꿔 보여 준 글이면 Claude 가 처음 쓴 글 그대로 돌려놓는다
export function maskPreviousAnswer(previousAnswerText) {
  return maskedAnswerByShownAnswer.get(previousAnswerText) ?? maskSensitiveText(previousAnswerText);
}

// 닫히지 않은 [ 앞까지만 바꿔 내보내고 나머지는 붙잡아 둔다. 블록이 끝나면 붙잡은 것까지 모두 내보낸다
function takeShownText(answerBlock, newMaskedText, { isBlockEnd = false } = {}) {
  answerBlock.maskedText += newMaskedText;
  const pendingText = answerBlock.heldText + newMaskedText;
  const heldStart = isBlockEnd ? pendingText.length : openMaskedValueStart(pendingText);
  answerBlock.heldText = pendingText.slice(heldStart);
  const shownText = unmaskSensitiveText(pendingText.slice(0, heldStart));
  answerBlock.shownText += shownText;
  return shownText;
}

function openMaskedValueStart(pendingText) {
  const lastOpenIndex = pendingText.lastIndexOf('[');
  const isOpenMaskedValue = lastOpenIndex !== -1 && !pendingText.includes(']', lastOpenIndex) && pendingText.length - lastOpenIndex <= MASKED_VALUE_MAX_LENGTH;
  return isOpenMaskedValue ? lastOpenIndex : pendingText.length;
}

// 보낼 글이 없으면 이벤트를 보내지 않는다
function toTextDeltaEvent(eventData, shownText) {
  if (!shownText) return '';
  return `event: content_block_delta\ndata: ${JSON.stringify({ ...eventData, delta: { ...eventData.delta, text: shownText } })}\n\n`;
}

function rememberShownAnswer(shownText, maskedText) {
  if (shownText === maskedText) return false;
  maskedAnswerByShownAnswer.set(shownText, maskedText);
  shownAnswerCharCount += shownText.length + maskedText.length;
  for (const [oldestShownText, oldestMaskedText] of maskedAnswerByShownAnswer) {
    if (shownAnswerCharCount <= SHOWN_ANSWER_CHAR_LIMIT) break;
    maskedAnswerByShownAnswer.delete(oldestShownText);
    shownAnswerCharCount -= oldestShownText.length + oldestMaskedText.length;
  }
  return true;
}

function parseEventData(streamEventText) {
  const dataLine = streamEventText.split('\n').find((eventLine) => eventLine.startsWith('data: '));
  return dataLine ? parseJson(dataLine.slice('data: '.length)) : null;
}

function parseJson(jsonText) {
  try {
    return JSON.parse(jsonText);
  } catch {
    return null;
  }
}
