"""gitleaks.toml 을 마스킹 모듈이 읽는 rules.json 으로 바꾼다.

gitleaks(https://github.com/gitleaks/gitleaks, MIT, LICENSE 참고)의 비밀값 탐지 규칙을 그대로 가져다 쓴다.
규칙을 새로 받으려면 gitleaks.toml 을 저장소의 config/gitleaks.toml 로 바꾸고 이 파일을 실행한다.
    python3 convert-rules.py <gitleaks 커밋> <커밋 날짜>

gitleaks 정규식은 Go(RE2) 문법이라 JavaScript 문법으로 바꾼다.
- 중간에 끼운 (?i) 는 JavaScript 가 받지 않아 지우고 대소문자 무시 플래그로 대신한다
- \\z, \\A 는 $, ^ 로, [:alnum:] 같은 POSIX 묶음은 글자 범위로, (?P<이름> 은 (?<이름> 으로 바꾼다
- 묶음 안에서만 플래그를 바꾸는 (?i:...) (?-i:...) (?s:...) 는 Node 22 가 읽지 못해 플래그 없이 풀어 쓴다 (ModifierGroupRewriter)
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
    if not any(modifier_group in js_pattern for modifier_group in MODIFIER_GROUPS):
        return {'pattern': js_pattern, 'flags': 'i' if is_case_insensitive else ''}
    return {'pattern': ModifierGroupRewriter(js_pattern, is_case_insensitive).rewrite(), 'flags': ''}


# Node 22 는 묶음 안에서만 플래그를 바꾸는 (?i:...) (?-i:...) (?s:...) 를 읽지 못한다(Node 23 부터 읽는다).
# 이런 묶음이 있는 정규식은 플래그 없이 같은 뜻이 되게 풀어 쓴다.
# - 대소문자를 무시하는 자리의 글자는 [aA] 로, 글자 묶음 [a-f] 는 [a-fA-F] 로 쓴다
# - (?s:...) 안의 . 은 줄바꿈까지 받는 [\s\S] 로 쓴다
MODIFIER_GROUPS = {'(?i:': (True, None), '(?-i:': (False, None), '(?s:': (None, True)}
NON_CAPTURING_GROUP_HEADS = ('(?:', '(?=', '(?!', '(?<=', '(?<!')


class ModifierGroupRewriter:
    def __init__(self, js_pattern, is_case_insensitive):
        self.js_pattern = js_pattern
        self.read_index = 0
        # 묶음마다 (대소문자 무시, . 이 줄바꿈도 받음). 묶음이 닫히면 바깥 묶음의 값으로 돌아간다
        self.flag_stack = [(is_case_insensitive, False)]
        self.rewritten_parts = []

    def rewrite(self):
        while self.read_index < len(self.js_pattern):
            self.rewrite_next_token()
        return ''.join(self.rewritten_parts)

    def rewrite_next_token(self):
        pattern_char = self.js_pattern[self.read_index]
        is_case_insensitive, is_dot_all = self.flag_stack[-1]
        if pattern_char == '\\':
            self.rewritten_parts.append(self.read_escape())
        elif pattern_char == '[':
            self.rewritten_parts.append(self.rewrite_char_class(is_case_insensitive))
        elif pattern_char == '(':
            self.open_group(is_case_insensitive, is_dot_all)
        elif pattern_char == ')':
            self.flag_stack.pop()
            self.copy_text(')')
        elif pattern_char == '{':
            quantifier_match = re.match(r'\{\d*,?\d*\}', self.js_pattern[self.read_index:])
            self.copy_text(quantifier_match.group(0) if quantifier_match else '{')
        elif pattern_char == '.' and is_dot_all:
            self.read_index += 1
            self.rewritten_parts.append('[\\s\\S]')
        elif is_case_insensitive and pattern_char.isascii() and pattern_char.isalpha():
            self.read_index += 1
            self.rewritten_parts.append(f'[{pattern_char.lower()}{pattern_char.upper()}]')
        else:
            self.copy_text(pattern_char)

    def open_group(self, is_case_insensitive, is_dot_all):
        remaining_pattern = self.js_pattern[self.read_index:]
        for modifier_group, (group_case_insensitive, group_dot_all) in MODIFIER_GROUPS.items():
            if remaining_pattern.startswith(modifier_group):
                self.read_index += len(modifier_group)
                self.rewritten_parts.append('(?:')
                self.flag_stack.append((
                    is_case_insensitive if group_case_insensitive is None else group_case_insensitive,
                    is_dot_all if group_dot_all is None else group_dot_all,
                ))
                return
        named_group_head = re.match(r'\(\?<[A-Za-z_]\w*>', remaining_pattern)
        group_head = named_group_head.group(0) if named_group_head else next((head for head in NON_CAPTURING_GROUP_HEADS if remaining_pattern.startswith(head)), '(')
        if group_head.startswith('(?') and not named_group_head and group_head not in NON_CAPTURING_GROUP_HEADS:
            raise ValueError(f'풀어 쓰지 못하는 묶음: {remaining_pattern[:20]}')
        self.copy_text(group_head)
        self.flag_stack.append((is_case_insensitive, is_dot_all))

    # [...] 안의 글자·범위에 대소문자 짝을 더한다. 부정 묶음 [^...] 도 짝을 더해야 대소문자를 무시한 뜻이 된다
    def rewrite_char_class(self, is_case_insensitive):
        class_start = self.read_index
        self.read_index += 2 if self.js_pattern.startswith('[^', self.read_index) else 1
        class_items = []
        while self.js_pattern[self.read_index] != ']':
            range_start = self.read_class_char()
            if self.js_pattern[self.read_index] == '-' and self.js_pattern[self.read_index + 1] != ']':
                self.read_index += 1
                class_items.append((range_start, self.read_class_char()))
            else:
                class_items.append((range_start, None))
        self.read_index += 1
        original_class = self.js_pattern[class_start:self.read_index]
        if not is_case_insensitive:
            return original_class
        other_case_text = ''.join(other_case_range for class_item in class_items for other_case_range in other_case_ranges_of(class_item))
        class_body = original_class[:-1]
        # 끝의 - 는 글자 - 다. 그 뒤에 범위를 붙이면 -A 가 범위로 읽히므로 - 앞에 넣는다
        if class_body.endswith('-') and not class_body.endswith('\\-'):
            return class_body[:-1] + other_case_text + '-]'
        return class_body + other_case_text + ']'

    # 묶음 안 글자 하나: 원래 쓴 글과, 범위 계산에 쓸 글자(\w 같은 묶음 이스케이프면 None)
    def read_class_char(self):
        if self.js_pattern[self.read_index] != '\\':
            class_char = self.js_pattern[self.read_index]
            self.read_index += 1
            return class_char
        escape_text = self.read_escape()
        hex_escape = re.fullmatch(r'\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4}))', escape_text)
        if hex_escape:
            return chr(int(hex_escape.group(1) or hex_escape.group(2), 16))
        return escape_text[1] if len(escape_text) == 2 and not escape_text[1].isalnum() else None

    def read_escape(self):
        escape_match = re.match(r'\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|.)', self.js_pattern[self.read_index:], flags=re.S)
        self.read_index += len(escape_match.group(0))
        return escape_match.group(0)

    def copy_text(self, copied_text):
        if self.js_pattern.startswith(copied_text, self.read_index):
            self.read_index += len(copied_text)
        self.rewritten_parts.append(copied_text)


# 범위(또는 글자 하나)에 든 영문자의 다른 대소문자를 범위로 돌려준다
# \w 같은 묶음 이스케이프(None)는 이미 대소문자를 다 받으므로 더하지 않는다
def other_case_ranges_of(class_item):
    range_start, range_end = class_item[0], class_item[1] or class_item[0]
    if range_start is None or range_end is None:
        return []
    other_case_ranges = []
    for letter_start, letter_end in (('a', 'z'), ('A', 'Z')):
        overlap_start, overlap_end = max(range_start, letter_start), min(range_end, letter_end)
        if overlap_start <= overlap_end:
            other_case_ranges.append(class_range_text(overlap_start.swapcase(), overlap_end.swapcase()))
    return other_case_ranges


def class_range_text(range_start, range_end):
    return range_start if range_start == range_end else f'{range_start}-{range_end}'


if __name__ == '__main__':
    main()
