#!/usr/bin/env node
// 로그인하면 마스킹 통로가 뜨고 멈추면 다시 뜨게 등록하고, ~/.claude/settings.json 에 넣을 값을 보여 준다 (macOS·윈도우).
// 실행할 때의 node 로 고정한다. 그 node 를 지우거나 바꾸면 다시 실행한다.
// 포트는 MASKING_GATEWAY_PORT 로 바꿀 수 있다.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const REPO_DIR = import.meta.dirname;
const NODE_PATH = fs.realpathSync(process.execPath);
const GATEWAY_PORT = process.env.MASKING_GATEWAY_PORT ?? '47821';
const GATEWAY_MAIN_FILE = path.join(REPO_DIR, 'src', 'masking-gateway.main.js');
const HOOK_FILE = path.join(REPO_DIR, 'src', 'unmask-tool-input.hook.js');
const GATEWAY_OUTPUT_LOG_FILE = path.join(REPO_DIR, 'log', 'masking-gateway.out.log');
const AGENT_NAME = 'claude-mask-gateway';

checkNodeVersion();
fs.mkdirSync(path.dirname(GATEWAY_OUTPUT_LOG_FILE), { recursive: true });
if (process.platform === 'darwin') registerMacLaunchAgent();
else if (process.platform === 'win32') registerWindowsStartup();
else failInstall(`${process.platform} 는 자동 실행 등록을 지원하지 않습니다. node ${GATEWAY_MAIN_FILE} 를 직접 띄우세요.`);
printClaudeSettings();

function checkNodeVersion() {
  const nodeMajorVersion = Number(process.versions.node.split('.')[0]);
  if (nodeMajorVersion < 22) failInstall(`Node 22 이상이 필요합니다 (지금 ${process.version})`);
}

// launchd 가 로그인할 때 띄우고(RunAtLoad), 멈추면 다시 띄운다(KeepAlive)
function registerMacLaunchAgent() {
  const agentFile = path.join(os.homedir(), 'Library', 'LaunchAgents', `${AGENT_NAME}.plist`);
  fs.mkdirSync(path.dirname(agentFile), { recursive: true });
  fs.writeFileSync(agentFile, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${AGENT_NAME}</string>
  <key>WorkingDirectory</key><string>${REPO_DIR}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${NODE_PATH}</string>
    <string>${GATEWAY_MAIN_FILE}</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict><key>MASKING_GATEWAY_PORT</key><string>${GATEWAY_PORT}</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${GATEWAY_OUTPUT_LOG_FILE}</string>
  <key>StandardErrorPath</key><string>${GATEWAY_OUTPUT_LOG_FILE}</string>
</dict>
</plist>
`);
  const launchDomain = `gui/${os.userInfo().uid}`;
  spawnSync('launchctl', ['bootout', `${launchDomain}/${AGENT_NAME}`], { stdio: 'ignore' });
  bootstrapAfterBootout(launchDomain, agentFile);
  console.log(`마스킹 통로 등록: http://127.0.0.1:${GATEWAY_PORT} (${agentFile})`);
}

// bootout 은 끝나기 전에 돌아와서, 바로 bootstrap 하면 실패(5: Input/output error)한다. 1초씩 기다리며 다시 한다
function bootstrapAfterBootout(launchDomain, agentFile) {
  for (let bootstrapTry = 1; bootstrapTry <= 10; bootstrapTry += 1) {
    const bootstrapRun = spawnSync('launchctl', ['bootstrap', launchDomain, agentFile], { encoding: 'utf8' });
    if (bootstrapRun.status === 0) return;
    if (bootstrapTry === 10) failInstall(`launchctl bootstrap 실패: ${bootstrapRun.stderr.trim()}`);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
  }
}

// 시작 프로그램 폴더의 VBScript 가 로그인할 때 창 없이 통로를 띄우고, 멈추면 3초 뒤 다시 띄운다.
// 시작 프로그램 폴더는 관리자 권한 없이 쓸 수 있다
function registerWindowsStartup() {
  const startupFolder = path.join(process.env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup');
  const launcherFile = path.join(startupFolder, `${AGENT_NAME}.vbs`);
  stopWindowsGateway(launcherFile);
  fs.mkdirSync(startupFolder, { recursive: true });
  fs.writeFileSync(launcherFile, windowsLauncherScript());
  spawn('wscript.exe', ['//B', launcherFile], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
  console.log(`마스킹 통로 등록: http://127.0.0.1:${GATEWAY_PORT} (${launcherFile})`);
}

// 다시 설치할 때 예전 런처와 그 런처가 띄운 통로를 끈다
function stopWindowsGateway(launcherFile) {
  const processFilter = [launcherFile, GATEWAY_MAIN_FILE]
    .map((processFile) => `$_.CommandLine -like '*${processFile.replaceAll("'", "''")}*'`)
    .join(' -or ');
  spawnSync('powershell.exe', ['-NoProfile', '-Command',
    // 이 PowerShell 도 명령줄에 두 경로를 담고 있어서 제외한다
    `Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and (${processFilter}) } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }`,
  ], { stdio: 'ignore' });
}

function windowsLauncherScript() {
  const gatewayCommand = `cmd /c ""${NODE_PATH}" "${GATEWAY_MAIN_FILE}" >> "${GATEWAY_OUTPUT_LOG_FILE}" 2>&1"`;
  return [
    'Set shell = CreateObject("WScript.Shell")',
    `shell.CurrentDirectory = ${vbsString(REPO_DIR)}`,
    `shell.Environment("Process")("MASKING_GATEWAY_PORT") = ${vbsString(GATEWAY_PORT)}`,
    'Do',
    `  shell.Run ${vbsString(gatewayCommand)}, 0, True`,
    '  WScript.Sleep 3000',
    'Loop',
    '',
  ].join('\r\n');
}

function vbsString(plainText) {
  return `"${plainText.replaceAll('"', '""')}"`;
}

// 경로의 \ 를 / 로 바꿔, 훅 명령을 Git Bash·cmd 어느 셸이 실행해도 같은 경로로 읽히게 한다
function printClaudeSettings() {
  const toCommandPath = (filePath) => `"${filePath.replaceAll('\\', '/')}"`;
  const claudeSettings = {
    env: { ANTHROPIC_BASE_URL: `http://127.0.0.1:${GATEWAY_PORT}` },
    hooks: { PreToolUse: [{ matcher: 'Bash|Grep|Glob|Read|Write|Edit|MultiEdit|NotebookEdit',
      hooks: [{ type: 'command', command: `${toCommandPath(NODE_PATH)} ${toCommandPath(HOOK_FILE)}`, timeout: 10 }] }] },
  };
  console.log(`${path.join(os.homedir(), '.claude', 'settings.json')} 에 넣을 값:`);
  console.log(JSON.stringify(claudeSettings, null, 2));
}

function failInstall(failMessage) {
  console.error(failMessage);
  process.exit(1);
}
