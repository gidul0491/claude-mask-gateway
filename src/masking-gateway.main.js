// 사람이 쓰는 Claude Code 앞에 마스킹 통로를 띄우는 진입점.
// Claude Code 설정(~/.claude/settings.json)의 ANTHROPIC_BASE_URL 을 이 주소로 두고, 도구 실행 전 훅으로 unmask-tool-input.hook.js 를 건다.
// 포트는 MASKING_GATEWAY_PORT 로 바꿀 수 있다. 되돌리기 표는 이 프로그램 안에만 있어서, 다시 켜면 그 전에 나온 가린 값은 되돌리지 못한다.
import { startMaskingGateway } from './masking.gateway.js';
import { localTimeText } from './local-time.js';

const DEFAULT_GATEWAY_PORT = 47821;

const maskingGatewayUrl = await startMaskingGateway({ listenPort: Number(process.env.MASKING_GATEWAY_PORT ?? DEFAULT_GATEWAY_PORT) });
console.log(`[${localTimeText()}] 마스킹 통로 열림: ${maskingGatewayUrl}`);
