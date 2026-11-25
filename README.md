# claude-mask-gateway

Claude Code 가 Anthropic 에 보내는 글에서 개인정보·비밀값을 가리고, 도구를 실행하기 직전에 원래 값으로 되돌리는 통로.

- 가리는 글: 시스템 프롬프트, 사람이 쓴 글, 도구 결과(명령 출력·파일 내용), Claude 의 지난 답 글과 도구 입력
- 개인정보: 주민번호, 카드번호, 운전면허번호, 휴대폰·전화번호, 이메일, 차량번호(한국 형식)
- 비밀값: 접속 주소·SQL·암호화 함수 안의 비밀번호와 키, [gitleaks](https://github.com/gitleaks/gitleaks) 규칙에 걸리는 서비스 키·토큰, `password`·`secret`·`token` 같은 이름에 붙은 값, 따옴표 안의 무작위 긴 값
- 이름·주소처럼 모양이 정해지지 않은 개인정보는 찾지 못한다.

## 동작

가린 값에는 이름표가 붙는다.

```
010-1234-5678   →  [휴대폰-xxxxxx ###-####-####]
DB_PASS=값      →  DB_PASS=[비밀값-xxxxxx]
```

- `xxxxxx` 는 값마다 정해지는 6글자다. 마스킹 키로 만든 해시라서 키 없이는 원래 값을 알 수 없다.
- Claude 는 원래 값을 모른 채 이름표를 명령·검색어에 쓴다. 도구 실행 직전 훅(`src/unmask-tool-input.hook.js`)이 통로에 물어 원래 값으로 바꾼다.
- 개인정보는 모든 도구 입력에서 되돌린다. 비밀값은 명령 실행(Bash)에서만 되돌려서 파일에 비밀값이 남지 않는다.
- Claude 가 쓴 답 글은 통로가 개인정보 이름표를 원래 값으로 바꿔 화면에 보여 준다. 비밀값은 이름표로 둔다. 생각 블록은 바꾸지 않는다.
- 바꿔 보여 준 답 글은 다음 요청에 실려 올 때 Claude 가 처음 쓴 가린 글로 되돌려 보낸다.
- 개인정보 이름표 뒤의 모양(`###-####-####`)은 Claude 가 바꿔 쓸 수 있다. `###########` 로 쓰면 하이픈 없이 되돌린다. DB 마다 저장 모양이 달라도 맞는 모양으로 조회할 수 있다.
- 되돌리기 표는 통로 메모리에만 있다. 통로를 다시 켜면 그 전에 나온 이름표는 되돌리지 못하니 다시 조회한다.
- 요청마다 가린 개수만 `log/masking-gateway.jsonl` 에 남긴다. 글 내용은 남기지 않는다.
- 통로는 이 컴퓨터 안(`127.0.0.1`)에서만 열린다.

## 설치 (macOS·윈도우)

Node 22 이상이 필요하다. `install.js` 를 실행할 때의 node 로 고정된다. 윈도우는 Git Bash 나 PowerShell 에서 실행한다.

```bash
git clone https://github.com/gidul0491/claude-mask-gateway.git ~/git/claude-mask-gateway
node ~/git/claude-mask-gateway/install.js
```

1. `install.js` 가 통로를 로그인할 때 뜨고 멈추면 다시 뜨게 등록한 뒤 바로 띄운다. 포트는 47821 이고, `MASKING_GATEWAY_PORT=포트 node install.js` 로 바꿀 수 있다.
   - macOS: `~/Library/LaunchAgents/claude-mask-gateway.plist`
   - 윈도우: 시작 프로그램 폴더의 `claude-mask-gateway.vbs`. 창 없이 띄우고, 멈추면 3초 뒤 다시 띄운다. 관리자 권한은 필요 없다.
2. 출력된 값을 `~/.claude/settings.json`(윈도우는 `%USERPROFILE%\.claude\settings.json`)의 `env`, `hooks` 에 넣는다.
3. 새 대화부터 적용된다. `log/masking-gateway.jsonl` 에 요청이 쌓이면 통로를 지나는 것이다.

- 마스킹 키는 처음 실행할 때 `~/.config/claude-mask-gateway/masking-key` 에 만들고 본인만 읽게 한다(윈도우는 `icacls`). 여러 컴퓨터에 같은 키를 두면 같은 값은 같은 이름표로 가려진다.
- 통로가 멈추면 Claude Code 가 응답하지 않는다. `curl http://127.0.0.1:47821` 로 응답이 오는지 보고, 급하면 settings.json 에서 넣은 두 항목을 빼면 원래대로 돌아간다. 통로의 출력은 `log/masking-gateway.out.log` 에 남는다.
- 요청 주소를 따로 정하는 앱(예: Claude 데스크톱 앱의 Code 탭)은 `ANTHROPIC_BASE_URL` 을 따르지 않아 통로를 지나지 않는다. 이때 훅은 아무 일도 하지 않는다.

## 가리는 결과 보기

파일을 가려 보고 무엇을 무엇으로 바꿨는지 줄마다 찍는다. 원래 값이 그대로 나오므로 사람만 쓴다.

```bash
node src/masking-report.cli.js <파일>
```

## 다른 프로그램에서 쓰기

`claude` 를 직접 실행하는 프로그램은 통로를 빈 포트로 띄우고 그 주소를 `ANTHROPIC_BASE_URL` 로 넘긴다.

```json
"dependencies": { "claude-mask-gateway": "github:gidul0491/claude-mask-gateway#v1.2.0" }
```

```js
import { startMaskingGateway } from 'claude-mask-gateway/gateway';

const maskingGatewayUrl = await startMaskingGateway({ logFile: '/경로/masking-gateway.jsonl' });
// claude 실행 환경변수: ANTHROPIC_BASE_URL=maskingGatewayUrl
// 도구 실행 전 훅: node node_modules/claude-mask-gateway/src/unmask-tool-input.hook.js
```

- `claude-mask-gateway/masker`: `maskSensitiveText`, `unmaskSensitiveText`, `containsSensitiveValues`, `findMaskedValues`, `isKnownMaskedValue`, `markNeverMaskedValues`, `isSecretMaskedValue`
- 마스킹 표는 통로를 띄운 프로세스 안에 있다. 되돌리기는 그 프로세스에서 하거나 통로(`/masking/unmask`)에 묻는다.

## gitleaks 규칙 새로 받기

`src/gitleaks/rules.json` 은 gitleaks 의 `config/gitleaks.toml` 을 JavaScript 정규식으로 바꾼 것이다(MIT, `src/gitleaks/LICENSE`).

```bash
curl -o src/gitleaks/gitleaks.toml https://raw.githubusercontent.com/gitleaks/gitleaks/<커밋>/config/gitleaks.toml
python3 src/gitleaks/convert-rules.py <커밋> <커밋 날짜>
```
