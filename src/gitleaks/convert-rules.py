"""gitleaks.toml 을 마스킹 모듈이 읽는 rules.json 으로 바꾼다.

gitleaks(https://github.com/gitleaks/gitleaks, MIT, LICENSE 참고)의 비밀값 탐지 규칙을 그대로 가져다 쓴다.
규칙을 새로 받으려면 gitleaks.toml 을 저장소의 config/gitleaks.toml 로 바꾸고 이 파일을 실행한다.
    python3 convert-rules.py <gitleaks 커밋> <커밋 날짜>

gitleaks 정규식은 Go(RE2) 문법이라 JavaScript 문법으로 바꾼다.
- 중간에 끼운 (?i) 는 JavaScript 가 받지 않아 지우고 대소문자 무시 플래그로 대신한다
- \\z, \\A 는 $, ^ 로, [:alnum:] 같은 POSIX 묶음은 글자 범위로, (?P<이름> 은 (?<이름> 으로 바꾼다
파일 경로로 판단하는 규칙(path)은 글만 보는 마스킹에 쓸 수 없어 뺀다.
"""
import json
import pathlib
import re
import sys
import tomllib

RULES_FOLDER = pathlib.Path(__file__).parent
POSIX_CLASS_RANGES = {
    '[:alnum:]': 'A-Za-z0-9', '[:alpha:]': 'A-Za-z', '[:digit:]': '0-9', '[:lower:]': 'a-z',
    '[:upper:]': 'A-Z', '[:space:]': '\\s', '[:xdigit:]': '0-9A-Fa-f', '[:word:]': '\\w', '[:punct:]': '!-/:-@\\[-`{-~',
}


def main():
    source_commit, source_date = sys.argv[1], sys.argv[2]
    gitleaks_config = tomllib.loads((RULES_FOLDER / 'gitleaks.toml').read_text())
    usable_rules = [rule for rule in gitleaks_config['rules'] if rule.get('regex') and not rule.get('path')]
    skipped_rule_ids = [rule['id'] for rule in gitleaks_config['rules'] if rule not in usable_rules]
    rules_document = {
        'source': {'repository': 'https://github.com/gitleaks/gitleaks', 'file': 'config/gitleaks.toml', 'commit': source_commit, 'date': source_date, 'license': 'MIT'},
        'skippedRuleIds': skipped_rule_ids,
        'globalAllowlist': convert_allowlist(gitleaks_config.get('allowlist', {})),
        'rules': [convert_rule(rule) for rule in usable_rules],
    }
    (RULES_FOLDER / 'rules.json').write_text(json.dumps(rules_document, ensure_ascii=False, indent=1))
    print(f"규칙 {len(rules_document['rules'])}개 저장, 뺀 규칙 {len(skipped_rule_ids)}개: {', '.join(skipped_rule_ids)}")


def convert_rule(gitleaks_rule):
    return {
        'id': gitleaks_rule['id'],
        **convert_pattern(gitleaks_rule['regex']),
        'keywords': [keyword.lower() for keyword in gitleaks_rule.get('keywords', [])],
        'entropy': gitleaks_rule.get('entropy', 0),
        'secretGroup': gitleaks_rule.get('secretGroup', 0),
        'allowlists': [convert_allowlist(allowlist) for allowlist in gitleaks_rule.get('allowlists', [])],
    }


def convert_allowlist(gitleaks_allowlist):
    return {
        'regexes': [convert_pattern(pattern) for pattern in gitleaks_allowlist.get('regexes', [])],
        'regexTarget': gitleaks_allowlist.get('regexTarget', 'secret'),
        'stopwords': [stopword.lower() for stopword in gitleaks_allowlist.get('stopwords', [])],
        'condition': gitleaks_allowlist.get('condition', 'OR'),
    }


def convert_pattern(go_pattern):
    is_case_insensitive = '(?i)' in go_pattern
    js_pattern = go_pattern.replace('(?i)', '').replace('\\z', '$').replace('\\A', '^').replace('(?P<', '(?<')
    for posix_class, char_range in POSIX_CLASS_RANGES.items():
        js_pattern = js_pattern.replace(posix_class, char_range)
    return {'pattern': js_pattern, 'flags': 'i' if is_case_insensitive else ''}


if __name__ == '__main__':
    main()
