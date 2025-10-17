import json
import requests
import os
import subprocess
import urllib.parse
import re


USERNAME = 'fuzzerofducks'

REPO_OWNER = 'duckdb'
REPO_NAME = 'duckdb-fuzzer'

fuzzer_desc = '''Issue found by ${FUZZER} on git commit hash [${SHORT_HASH}](https://github.com/duckdb/duckdb/commit/${FULL_HASH}) using seed ${SEED}.
'''

sql_header = '''### To Reproduce
```sql
'''

exception_header = '''
```

### Error Message
```
'''

trace_header = '''
```

### Stack Trace
```
'''

footer = '''
```'''


# github stuff
def issue_url():
    return 'https://api.github.com/repos/%s/%s/issues' % (REPO_OWNER, REPO_NAME)


def issues_by_title_url(issue_title):
    base_url = "https://api.github.com/search/issues"
    query_string = urllib.parse.quote(f"repo:{REPO_OWNER}/{REPO_NAME} {issue_title} in:title is:open")
    return f"{base_url}?q={query_string}"


def get_token():
    if 'FUZZEROFDUCKSKEY' not in os.environ:
        print("FUZZEROFDUCKSKEY not found in environment variables")
        exit(1)
    token = os.environ['FUZZEROFDUCKSKEY']
    if len(token) == 0:
        print("FUZZEROFDUCKSKEY is set but is empty")
        exit(1)

    if len(token) != 40:
        print("Incorrect length for FUZZEROFDUCKSKEY")
        exit(1)
    return token


def create_session():
    # Create an authenticated session to create the issue
    session = requests.Session()
    session.headers.update({'Authorization': 'token %s' % (get_token(),)})
    return session


def make_github_issue(title, body):
    if len(title) > 240:
        #  avoid title is too long error (maximum is 256 characters)
        title = title[:240] + '...'
    if len(body) > 60000:
        body = body[:60000] + '... (body of github issue is truncated)'
    session = create_session()
    url = issue_url()
    issue = {'title': title, 'body': body}
    r = session.post(url, json.dumps(issue))
    if r.status_code == 201:
        print('Successfully created Issue "%s"' % title)
    else:
        print('Could not create Issue "%s"' % title)
        print('Response:', r.content.decode('utf8'))
        raise Exception("Failed to create issue")


def get_github_issues_per_page(page: int) -> list[dict]:
    session = create_session()
    url = issue_url() + '?per_page=100&page=' + str(page)
    r = session.get(url)
    if r.status_code != 200:
        print('Failed to get list of issues')
        print('Response:', r.content.decode('utf8'))
        raise Exception("Failed to get list of issues")
    return json.loads(r.content.decode('utf8'))


def get_github_issues_by_title(issue_title) -> list[dict]:
    session = create_session()
    url = issues_by_title_url(issue_title)
    r = session.get(url)
    if r.status_code != 200:
        print('Failed to query the issues')
        print('Response:', r.content.decode('utf8'))
        raise Exception("Failed to query the issues")
    issue_list = r.json().get("items", [])
    return issue_list


def close_github_issue(number):
    session = create_session()
    url = issue_url() + '/' + str(number)
    params = {'state': 'closed'}
    r = session.patch(url, json.dumps(params))
    if r.status_code == 200:
        print(f'Successfully closed Issue "{number}"')
    else:
        print(f'Could not close Issue "{number}" (status code {r.status_code})')
        print('Response:', r.content.decode('utf8'))
        raise Exception("Failed to close issue")


def label_github_issue(number, label):
    session = create_session()
    url = issue_url() + '/' + str(number)
    params = {'labels': [label]}
    r = session.patch(url, json.dumps(params))
    if r.status_code == 200:
        print(f'Successfully labeled Issue "{number}"')
    else:
        print(f'Could not label Issue "{number}" (status code {r.status_code})')
        print('Response:', r.content.decode('utf8'))
        raise Exception("Failed to label issue")


def extract_issue(body, nr):
    try:
        if trace_header in body:
            sql = body.split(sql_header)[1].split(exception_header)[0]
            error = body.split(exception_header)[1].split(trace_header)[0]
            trace = body.split(trace_header)[1].split(footer)[0]
        else:
            splits = body.split(exception_header)
            sql = splits[0].split(sql_header)[1]
            error = splits[1][: -len(footer)]
            trace = ""
        return (sql, error, trace)
    except:
        print(f"Failed to extract SQL/error message from issue {nr}")
        print(body)
        return None


def run_shell_command_batch(shell, cmd):
    command = [shell, '--batch', '-init', '/dev/null']

    try:
        res = subprocess.run(
            command, input=bytearray(cmd, 'utf8'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300
        )
    except subprocess.TimeoutExpired:
        print(f"TIMEOUT... {cmd}")
        return ("", "", 0, True)
    stdout = res.stdout.decode('utf8').strip()
    stderr = res.stderr.decode('utf8').strip()
    return (stdout, stderr, res.returncode, False)


def is_reproducible_issue(shell, issue) -> bool:
    extract = extract_issue(issue['body'], issue['number'])
    if extract is None:
        # failed extract: leave the issue as-is
        return True
    sql = extract[0] + ';'
    # try max 30 times to reproduce; some errors not always occur
    for _ in range(30):
        (stdout, stderr, returncode, is_timeout) = run_shell_command_batch(shell, sql)
        if is_timeout:
            label_github_issue(issue['number'], 'timeout')
            return True
        if returncode < 0:
            return True
        if is_internal_error(stderr):
            return True
    # issue is not reproducible
    return False


def get_github_issues_list() -> list[dict]:
    issues: list[dict] = []
    for p in range(1, 10):
        issues = issues + get_github_issues_per_page(p)
    return issues


# closes non-reproducible issues; returns reproducible issues
def close_non_reproducible_issues(shell) -> dict[str, dict]:
    reproducible_issues: dict[str, dict] = {}
    for issue in get_github_issues_list():
        if any(label['name'] in ['AFL', 'timeout'] for label in issue['labels']):
            print(f"skipping issue {issue['number']}... (issues with label 'AFL' or 'timeout' are not auto-closed)")
            # We assume they are reproducible (i.e. not fixed yet)
            reproducible_issues[issue['title']] = issue
        elif is_reproducible_issue(shell, issue):
            print(f"Issue {issue['number']} reproduced succesfully")
            reproducible_issues[issue['title']] = issue
        else:
            # the issue appears to be fixed - close the issue
            print(f"Issue {issue['number']} can not be reproduced")
            close_github_issue(int(issue['number']))
    # retun open issues as dict, so they can be searched by title, which is the exception message without trace
    return reproducible_issues


def file_issue(cmd, exception_msg, stacktrace, fuzzer, seed, hash):
    # issue is new, file it
    print("Filing new issue to Github")

    title = exception_msg
    body = (
        fuzzer_desc.replace("${FUZZER}", fuzzer)
        .replace("${FULL_HASH}", hash)
        .replace("${SHORT_HASH}", hash[:5])
        .replace("${SEED}", str(seed))
    )
    body += sql_header + cmd + exception_header + exception_msg + trace_header + stacktrace + footer
    print(title, body)
    make_github_issue(title, body)


def is_internal_error(error):
    if 'differs from original result' in error:
        return True
    if 'INTERNAL' in error:
        return True
    if 'signed integer overflow' in error:
        return True
    if 'Sanitizer' in error or 'sanitizer' in error:
        return True
    if 'runtime error' in error:
        return True
    return False


def sanitize_stacktrace(err):
    err = re.sub(r'../duckdb\((.*)\)', r'\1', err)
    err = re.sub(r'[\+\[]?0x[0-9a-fA-F]+\]?', '', err)
    err = re.sub(r'/lib/x86_64-linux-gnu/libc.so(.*)\n', '', err)
    return err.strip()


def split_exception_trace(exception_msg_full: str) -> tuple[str, str]:
    # exception message does not contain newline, so split after first newline
    exception_msg, _, stack_trace = exception_msg_full.partition('\n')
    return (exception_msg.strip(), sanitize_stacktrace(stack_trace))
