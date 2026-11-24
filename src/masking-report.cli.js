// 파일을 마스킹해 보고, 무엇을 무엇으로 가렸는지 줄마다 찍는다. 원래 값(비밀번호·키 포함)이 그대로 나오므로 사람만 쓴다.
//   node src/masking-report.cli.js <파일>
import fs from 'node:fs';
import { findMaskedValues, maskSensitiveText, unmaskSensitiveText } from './sensitive-text.masker.js';

const filePath = process.argv[2];
const maskedLines = maskSensitiveText(fs.readFileSync(filePath, 'utf8')).split('\n');

maskedLines.forEach((maskedLine, lineIndex) => {
  for (const maskedValue of findMaskedValues(maskedLine)) {
    const originalValue = unmaskSensitiveText(maskedValue, { includeSecrets: true });
    console.log(`${lineIndex + 1}줄  ${originalValue.replaceAll('\n', '⏎')}  →  ${maskedValue}`);
  }
});
