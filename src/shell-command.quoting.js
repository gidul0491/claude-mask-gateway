// 셸 명령 안의 가린 값을, 그 자리의 따옴표 규칙에 맞춰 원래 값으로 바꾼다.
// 원래 값에 $ ` " ' \ 같은 글자가 있어도 셸이 다른 뜻으로 읽지 않고 그 글자 그대로 받게 한다.
//   따옴표 밖      → 작은따옴표로 감싼다 (영문·숫자 등 안전한 글자만 있으면 그대로)
//   '...' 안       → ' 만 '\'' 로 바꾼다
//   "..." 안       → \ $ ` " 앞에 \ 를 붙인다
//   히어독 안      → 끝말을 따옴표로 감쌌으면(<<'EOF') 그대로, 아니면 \ $ ` 앞에 \ 를 붙인다

const SAFE_UNQUOTED_VALUE = /^[A-Za-z0-9_@%+=:,./-]+$/;
const HEREDOC_START = /^<<(-?)[ \t]*(?:'([^'\n]+)'|"([^"\n]+)"|\\?([A-Za-z_][A-Za-z0-9_]*))/;

// valueByMaskedValue: 가린 값 → 원래 값. 표에 없는 가린 값은 그대로 둔다
export function unmaskShellCommand(shellCommand, valueByMaskedValue) {
  const maskedValues = [...valueByMaskedValue.keys()].sort((first, second) => second.length - first.length);
  const unmaskedParts = [];
  const quoteScanner = new ShellQuoteScanner(shellCommand);
  while (!quoteScanner.isDone()) {
    const maskedValue = maskedValues.find((candidate) => shellCommand.startsWith(candidate, quoteScanner.readIndex));
    if (maskedValue) {
      unmaskedParts.push(quoteForContext(valueByMaskedValue.get(maskedValue), quoteScanner.quoteContext()));
      quoteScanner.skip(maskedValue.length);
    } else {
      unmaskedParts.push(quoteScanner.readChar());
    }
  }
  return unmaskedParts.join('');
}

function quoteForContext(originalValue, quoteContext) {
  if (quoteContext === 'single') return originalValue.replaceAll("'", "'\\''");
  if (quoteContext === 'double') return originalValue.replace(/[\\$`"]/g, '\\$&');
  if (quoteContext === 'heredoc') return originalValue.replace(/[\\$`]/g, '\\$&');
  if (quoteContext === 'literal-heredoc') return originalValue;
  return SAFE_UNQUOTED_VALUE.test(originalValue) ? originalValue : `'${originalValue.replaceAll("'", "'\\''")}'`;
}

// 글자를 하나씩 읽으며 지금 자리가 어느 따옴표 안인지 따라간다
class ShellQuoteScanner {
  constructor(shellCommand) {
    this.shellCommand = shellCommand;
    this.readIndex = 0;
    this.openQuote = null; // "'" 또는 '"'
    this.pendingHeredocs = []; // 이 줄이 끝나면 시작할 히어독: { endWord, isLiteral, allowsTabIndent }
    this.currentHeredoc = null;
  }

  isDone() {
    return this.readIndex >= this.shellCommand.length;
  }

  quoteContext() {
    if (this.currentHeredoc) return this.currentHeredoc.isLiteral ? 'literal-heredoc' : 'heredoc';
    if (this.openQuote === "'") return 'single';
    if (this.openQuote === '"') return 'double';
    return 'unquoted';
  }

  skip(skippedLength) {
    this.readIndex += skippedLength;
  }

  // 글자(이스케이프면 두 글자)를 읽어 돌려주고 따옴표 상태를 바꾼다
  readChar() {
    const shellChar = this.shellCommand[this.readIndex];
    if (this.currentHeredoc) return this.readHeredocChar(shellChar);
    if (shellChar === '\\' && this.openQuote !== "'") return this.readTwoChars();
    if (shellChar === "'" && this.openQuote !== '"') this.openQuote = this.openQuote ? null : "'";
    else if (shellChar === '"' && this.openQuote !== "'") this.openQuote = this.openQuote ? null : '"';
    else if (shellChar === '<' && !this.openQuote) return this.readHeredocStart();
    else if (shellChar === '\n' && !this.openQuote) this.startPendingHeredoc();
    this.readIndex += 1;
    return shellChar;
  }

  readTwoChars() {
    const escapedText = this.shellCommand.slice(this.readIndex, this.readIndex + 2);
    this.readIndex += escapedText.length;
    return escapedText;
  }

  readHeredocStart() {
    const heredocMatch = this.shellCommand.slice(this.readIndex).match(HEREDOC_START);
    if (!heredocMatch || this.shellCommand.startsWith('<<<', this.readIndex)) {
      this.readIndex += 1;
      return '<';
    }
    const [heredocHead, tabIndentMark, singleQuotedWord, doubleQuotedWord, plainWord] = heredocMatch;
    this.pendingHeredocs.push({
      endWord: singleQuotedWord ?? doubleQuotedWord ?? plainWord,
      isLiteral: !plainWord || heredocHead.includes('\\'),
      allowsTabIndent: tabIndentMark === '-',
    });
    this.readIndex += heredocHead.length;
    return heredocHead;
  }

  startPendingHeredoc() {
    this.currentHeredoc = this.pendingHeredocs.shift() ?? null;
  }

  // 히어독 안에서는 줄이 시작할 때마다 그 줄이 끝말인지 본다. 끝말 줄을 지나면 다시 명령으로 읽는다
  readHeredocChar(shellChar) {
    const lineText = this.readLineText();
    if (this.shellCommand[this.readIndex - 1] === '\n' && this.isHeredocEndLine(lineText)) {
      this.readIndex += lineText.length;
      this.currentHeredoc = null;
      return lineText;
    }
    if (shellChar === '\\' && !this.currentHeredoc.isLiteral) return this.readTwoChars();
    this.readIndex += 1;
    return shellChar;
  }

  readLineText() {
    const lineEnd = this.shellCommand.indexOf('\n', this.readIndex);
    return this.shellCommand.slice(this.readIndex, lineEnd === -1 ? undefined : lineEnd);
  }

  isHeredocEndLine(lineText) {
    const comparedLine = this.currentHeredoc.allowsTabIndent ? lineText.replace(/^\t+/, '') : lineText;
    return comparedLine === this.currentHeredoc.endWord;
  }
}
