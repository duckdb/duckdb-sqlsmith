import sys
import os
import subprocess
import reduce_sql
import fuzzer_helper
import random

seed = -1

fuzzer = None
db = None
shell = None
perform_checks = True
no_git_checks = False
max_queries = 1000
max_query_length = 50000
verification = False

for param in sys.argv:
    if param == '--sqlsmith':
        fuzzer = 'sqlsmith'
    elif param == '--duckfuzz':
        fuzzer = 'duckfuzz'
    elif param == '--duckfuzz_functions':
        fuzzer = 'duckfuzz_functions'
    elif param == '--alltypes':
        db = 'alltypes'
    elif param == '--tpch':
        db = 'tpch'
    elif param == '--emptyalltypes':
        db = 'emptyalltypes'
    elif param == '--no_checks':
        perform_checks = False
    elif param.startswith('--enable_verification'):
        verification = param.replace('--enable_verification=', '').lower() == 'true'
    elif param.startswith('--shell='):
        shell = param.replace('--shell=', '')
    elif param.startswith('--seed='):
        seed = int(param.replace('--seed=', ''))
    elif param.startswith('--max_queries='):
        max_queries = int(param.replace('--max_queries=', ''))
    elif param.startswith('--max_query_length='):
        max_query_length = int(param.replace('--max_query_length=', ''))
    elif param.startswith('--no-git-checks'):
        no_git_checks = param.replace('--no-git-checks=', '').lower() == 'true'

if fuzzer is None:
    print("Unrecognized fuzzer to run, expected e.g. --sqlsmith or --duckfuzz")
    exit(1)

if db is None:
    print("Unrecognized database to run on, expected either --tpch, --alltypes or --emptyalltypes")
    exit(1)

if shell is None:
    print("Unrecognized path to shell, expected e.g. --shell=build/debug/duckdb")
    exit(1)

if seed < 0:
    seed = random.randint(0, 2**30)

git_hash = os.getenv('DUCKDB_HASH')


def get_create_db_statement(db):
    if db == 'alltypes':
        return 'create table all_types as select * exclude(small_enum, medium_enum, large_enum) from test_all_types();'
    elif db == 'tpch':
        return 'call dbgen(sf=0.1);'
    elif db == 'emptyalltypes':
        return 'create table all_types as select * exclude(small_enum, medium_enum, large_enum) from test_all_types() limit 0;'
    else:
        raise Exception("Unknown database creation script")


def get_fuzzer_call_statement(fuzzer):
    if fuzzer == 'sqlsmith':
        return "call sqlsmith(max_queries=${MAX_QUERIES}, max_query_length=${MAX_QUERY_LENGTH}, seed=${SEED}, verbose_output=1, log='${LAST_LOG_FILE}', complete_log='${COMPLETE_LOG_FILE}');"
    elif fuzzer == 'duckfuzz':
        return "call fuzzyduck(max_queries=${MAX_QUERIES}, max_query_length=${MAX_QUERY_LENGTH}, seed=${SEED}, verbose_output=1, log='${LAST_LOG_FILE}', complete_log='${COMPLETE_LOG_FILE}', enable_verification='${ENABLE_VERIFICATION}');"
    elif fuzzer == 'duckfuzz_functions':
        return "call fuzz_all_functions(seed=${SEED}, max_query_length=${MAX_QUERY_LENGTH}, verbose_output=1, log='${LAST_LOG_FILE}', complete_log='${COMPLETE_LOG_FILE}');"
    else:
        raise Exception("Unknown fuzzer type")


def get_fuzzer_name_printable(fuzzer):
    if fuzzer == 'sqlsmith':
        return 'SQLSmith'
    elif fuzzer == 'duckfuzz':
        return 'DuckFuzz'
    elif fuzzer == 'duckfuzz_functions':
        return 'DuckFuzz (Functions)'
    else:
        return 'Unknown'


def run_shell_command(cmd):
    command = [shell, '--batch', '-init', '/dev/null']
    res = subprocess.run(command, input=bytearray(cmd, 'utf8'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = res.stdout.decode('utf8', 'ignore').strip()
    stderr = res.stderr.decode('utf8', 'ignore').strip()
    return (stdout, stderr, res.returncode)


def is_known_issue(exception_msg):
    if len(exception_msg) > 240:
        #  avoid title is too long error (maximum is 256 characters)
        title = exception_msg[:240] + '...'
    else:
        title = exception_msg
    existing_issues = fuzzer_helper.get_github_issues_by_title(title)
    if existing_issues:
        print("Skip filing duplicate issue")
        print(
            "Issue already exists: https://github.com/duckdb/duckdb-fuzzer/issues/"
            + str(existing_issues[0]['number'])
        )
        return True
    else:
        return False


# ==========================================
#              START OF SCRIPT
# ==========================================

# Don't go on and fuzz if perform checks = true
if perform_checks:
    fuzzer_helper.close_non_reproducible_issues(shell)
    exit(0)

last_query_log_file = 'sqlsmith.log'
complete_log_file = 'sqlsmith.complete.log'

print(
    f'''==========================================
        RUNNING {fuzzer} on {db}
=========================================='''
)


create_db_statement = get_create_db_statement(db)
call_fuzzer_statement = (
    get_fuzzer_call_statement(fuzzer)
    .replace('${MAX_QUERIES}', str(max_queries))
    .replace('${MAX_QUERY_LENGTH}', str(max_query_length))
    .replace('${LAST_LOG_FILE}', last_query_log_file)
    .replace('${COMPLETE_LOG_FILE}', complete_log_file)
    .replace('${SEED}', str(seed))
    .replace('${ENABLE_VERIFICATION}', str(verification))
)

print(create_db_statement)
print(call_fuzzer_statement)

cmd = create_db_statement + "\n" + call_fuzzer_statement

print("==========================================")

(stdout, stderr, returncode) = run_shell_command(cmd)

print(
    f'''==========================================
        FINISHED RUNNING
=========================================='''
)

print(returncode)
if returncode == 0:
    print("==============  SUCCESS  ================")
    exit(0)
else:
    print("==============  STDOUT  ================")
    print(stdout)
    print("==============  STDERR  =================")
    print(stderr)
    print("==========================================")

print("==============  FAILURE  ================")
print("Attempting to reproduce and file issue...")

# run the last query, and see if the issue persists
with open(last_query_log_file, 'r') as f:
    last_query = f.read()

with open(complete_log_file, 'r') as f:
    all_queries = f.read()

# try max 30 times to reproduce; some errors not always occur
cmd = create_db_statement + '\n' + all_queries
reproducible = False
for _ in range(30):
    (stdout, stderr, returncode) = run_shell_command(cmd)
    if returncode < 0 or (returncode != 0 and fuzzer_helper.is_internal_error(stderr)):
        reproducible = True
        break

print("==============  STDOUT  ================")
print(stdout)
print("==============  STDERR  =================")
print(stderr)
print("==========================================")

if not reproducible:
    print("Failed to reproduce the internal error")
    exit(0)

exception_msg, stacktrace = fuzzer_helper.split_exception_trace(stderr)

print("=========================================")
print("         Reproduced successfully         ")
print("=========================================")

# check if this is a duplicate issue
if (not no_git_checks) and is_known_issue(exception_msg):
    exit(0)

print("=========================================")
print("        Attempting to reduce query       ")
print("=========================================")
# try to reduce the query as much as possible
# reduce_multi_statement checks just the last statement first as a heuristic to see if
# only the last statement causes the error.
required_queries = reduce_sql.reduce_multi_statement(all_queries, shell, create_db_statement)
reduced_cmd = create_db_statement + '\n' + required_queries

# get a new error message.
(stdout, stderr, returncode) = run_shell_command(reduced_cmd)
reduced_exception_msg, stacktrace = fuzzer_helper.split_exception_trace(stderr)

# check if this is a duplicate issue
if (not no_git_checks) and is_known_issue(reduced_exception_msg):
    exit(0)

if returncode < 0 or (returncode != 0 and fuzzer_helper.is_internal_error(stderr)):
    exception_msg = reduced_exception_msg
    cmd = reduced_cmd

print(f"================MARKER====================")
print(f"After reducing: the below sql causes an internal error \n `{cmd}`")
print(f"{exception_msg}")
print(f"================MARKER====================")

if not no_git_checks:
    fuzzer_name_printable = get_fuzzer_name_printable(fuzzer)
    fuzzer_helper.file_issue(cmd, exception_msg, stacktrace, fuzzer_name_printable, seed, git_hash)
