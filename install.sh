#!/usr/bin/env bash
# 로그인하면 마스킹 통로가 뜨고 멈추면 다시 뜨게 등록한다 (macOS).
# 실행할 때의 node 로 고정한다. 그 node 를 지우거나 바꾸면 다시 실행한다.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
NODE_PATH="$(command -v node)"
GATEWAY_PORT="${MASKING_GATEWAY_PORT:-47821}"
AGENT_LABEL="claude-mask-gateway"
AGENT_FILE="$HOME/Library/LaunchAgents/$AGENT_LABEL.plist"

NODE_MAJOR="$("$NODE_PATH" -p 'process.versions.node.split(".")[0]')"
if [ "$NODE_MAJOR" -lt 22 ]; then
  echo "Node 22 이상이 필요합니다 (지금 $("$NODE_PATH" -v))" >&2
  exit 1
fi

mkdir -p "$REPO_DIR/log" "$(dirname "$AGENT_FILE")"
cat > "$AGENT_FILE" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$AGENT_LABEL</string>
  <key>WorkingDirectory</key><string>$REPO_DIR</string>
  <key>ProgramArguments</key>
  <array>
    <string>$NODE_PATH</string>
    <string>$REPO_DIR/src/masking-gateway.main.js</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict><key>MASKING_GATEWAY_PORT</key><string>$GATEWAY_PORT</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$REPO_DIR/log/masking-gateway.out.log</string>
  <key>StandardErrorPath</key><string>$REPO_DIR/log/masking-gateway.out.log</string>
</dict>
</plist>
PLIST

launchctl bootout "gui/$(id -u)/$AGENT_LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$AGENT_FILE"

echo "마스킹 통로 등록: http://127.0.0.1:$GATEWAY_PORT ($AGENT_FILE)"
echo "~/.claude/settings.json 에 넣을 값:"
cat <<JSON
{
  "env": { "ANTHROPIC_BASE_URL": "http://127.0.0.1:$GATEWAY_PORT" },
  "hooks": { "PreToolUse": [{ "matcher": "Bash|Grep|Glob|Read|Write|Edit|MultiEdit|NotebookEdit",
    "hooks": [{ "type": "command", "command": "$NODE_PATH $REPO_DIR/src/unmask-tool-input.hook.js", "timeout": 10 }] }] }
}
JSON
