"""End-to-end tests of lint-no-inline-secrets.py, the check behind the lint-workflow-expressions action.

Each class of violation is planted in a throwaway git repository, the check runs on it, and the verdict and the message are asserted. The same
files without the expression must pass. The check's own self-test is proved the other way round: a copy of the script with one class removed
must stop by name. A worktree with a hook's GIT_* variables is replayed too, because a `git init` that reaches the shared configuration there
turns the main checkout into a bare repository; the configuration is compared byte for byte afterwards.

Run: python test-lint-no-inline-secrets.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CHECK = Path(__file__).resolve().with_name("lint-no-inline-secrets.py")
ACTION = CHECK.with_name("action.yml")
work = Path(tempfile.mkdtemp(prefix="test-lint-workflow-expressions-"))
results = []


def check(ok, label, detail=""):
    results.append((bool(ok), label))
    if not ok:
        print("FAILED:", label, str(detail).encode("ascii", "backslashreplace").decode()[:900])


def clean_env():
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def git(cwd, *args, env=None):
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=cwd, capture_output=True, text=True, env=env or clean_env())


def make_repo(name, files, track=True):
    root = work / name
    root.mkdir()
    assert git(root, "init", "-q").returncode == 0
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8", newline="\n")
    if track:
        assert git(root, "add", "-A").returncode == 0
    return root


def run(root, script=CHECK, env=None, encoding=None):
    # `encoding` is how the test decodes what the check printed: it must be the encoding the check was told to print in
    return subprocess.run([sys.executable, str(script), str(root)], capture_output=True, text=True, encoding=encoding, env=env or clean_env(), timeout=120)


WORKFLOW = ".github/workflows/w.yml"


def workflow(step):
    return f"name: w\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - name: the step\n{step}\n"


try:
    # --- the violation classes: each is refused, the file and the step are named; the same file without the expression passes
    cases = {
        "run with an indexed secret": (WORKFLOW, workflow("        run: echo \"${{ secrets['X'] }}\""), workflow("        run: echo hello"), "w.yml"),
        "run with a spaced secret": (WORKFLOW, workflow('        run: echo "${{ secrets.X }}"'), workflow("        run: echo hello"), "w.yml"),
        "run with a function": (WORKFLOW, workflow('        run: echo "${{ toJSON(github.event) }}"'), workflow("        run: echo hello"), "w.yml"),
        "shell of a composite step": (".github/actions/a/action.yml",
                                      "name: a\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: \"${{ inputs.sh }} {0}\"\n",
                                      "name: a\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n", "a/action.yml"),
        "defaults.run.shell of a job": (WORKFLOW,
                                        "name: w\non: push\njobs:\n  a:\n    runs-on: x\n    defaults:\n      run:\n        shell: \"${{ inputs.sh }} {0}\"\n    steps:\n      - run: echo hi\n",
                                        "name: w\non: push\njobs:\n  a:\n    runs-on: x\n    defaults:\n      run:\n        shell: bash\n    steps:\n      - run: echo hi\n", "w.yml"),
        "with.script of github-script": (WORKFLOW,
                                         workflow("        uses: actions/github-script@v7\n        with:\n          script: console.log('${{ github.event.issue.title }}')"),
                                         workflow("        uses: actions/github-script@v7\n        with:\n          script: console.log('hello')"), "w.yml"),
        "with.script of github-script, input name in another case": (WORKFLOW,
                                         workflow("        uses: actions/github-script@v7\n        with:\n          Script: console.log('${{ github.event.issue.title }}')"),
                                         workflow("        uses: actions/github-script@v7\n        with:\n          Script: console.log('hello')"), "w.yml"),
        "with.args of a docker step": (WORKFLOW,
                                       workflow("        uses: docker://alpine:3\n        with:\n          args: sh -c \"echo ${{ inputs.x }}\""),
                                       workflow("        uses: docker://alpine:3\n        with:\n          args: sh -c \"echo hi\""), "w.yml"),
        "runs.args of a docker action": (".github/actions/d/action.yml",
                                         "name: d\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint: sh\n  args:\n    - -c\n    - echo ${{ inputs.x }}\n",
                                         "name: d\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint: sh\n  args:\n    - -c\n    - echo hi\n", "d/action.yml"),
        "run of a composite action nested two levels deep": (".github/actions/group/inner/action.yml",
                                                             "name: i\nruns:\n  using: composite\n  steps:\n    - run: echo \"${{ inputs.x }}\"\n      shell: bash\n",
                                                             "name: i\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n", "inner/action.yml"),
    }
    # The line of the expression in each planted file, counted by hand from the text above
    expected_line = {
        "run with an indexed secret": 8,
        "run with a spaced secret": 8,
        "run with a function": 8,
        "shell of a composite step": 6,
        "defaults.run.shell of a job": 8,
        "with.script of github-script": 10,
        "with.script of github-script, input name in another case": 10,
        "with.args of a docker step": 10,
        "runs.args of a docker action": 8,
        "run of a composite action nested two levels deep": 5,
    }
    assert set(expected_line) == set(cases), "every case needs its line"
    for label, (rel, bad, good, filename) in cases.items():
        root = make_repo("bad-" + str(len(results)), {rel: bad})
        r = run(root)
        check(r.returncode == 1 and filename in r.stdout, f"refused: {label}", r.stdout + r.stderr)
        check(f"{rel}:{expected_line[label]}: " in r.stdout, f"the finding names file and line {expected_line[label]}: {label}", r.stdout)
        root = make_repo("good-" + str(len(results)), {rel: good})
        r = run(root)
        check(r.returncode == 0 and "OK:" in r.stdout, f"the same file without the expression passes: {label}", r.stdout + r.stderr)

    # a step is named
    root = make_repo("named", {WORKFLOW: workflow("        run: echo \"${{ secrets['X'] }}\"")})
    r = run(root)
    check("the step" in r.stdout and "expression inside run:" in r.stdout, "the message names the step and the value", r.stdout)

    # a block scalar: the line of the expression inside the block, not the line of its `|`
    block = workflow("        run: |\n          set -e\n          echo ok\n          echo \"${{ secrets.X }}\"\n          echo done")
    r = run(make_repo("block", {WORKFLOW: block}))
    check(f"{WORKFLOW}:11: " in r.stdout and f"{WORKFLOW}:8: " not in r.stdout, "a block run: names the line of the expression inside it (11), not of the `|` (8)", r.stdout)

    # a quoted string spread over lines, and two steps with one violation each: each is named by its own line
    two = ("name: w\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n"
           "      - name: first\n        run: echo \"${{ inputs.a }}\"\n"
           "      - name: clean\n        run: echo fine\n"
           "      - name: third\n        run: \"echo one\n          echo ${{ inputs.b }}\"\n")
    r = run(make_repo("two", {WORKFLOW: two}))
    check(f"{WORKFLOW}:8: " in r.stdout and f"{WORKFLOW}:13: " in r.stdout and "first" in r.stdout and "third" in r.stdout and "clean" not in r.stdout,
          "two violating steps are named each by its own line; the clean one is not named", r.stdout)

    # files as they come from other editors: CRLF line endings, a lone CR, and the Unicode breaks (U+0085, U+2028, U+2029) that the YAML
    # parser counts as line breaks and an editor does not: the finding names the line a person sees
    crlf = workflow("        run: echo \"${{ secrets.X }}\"").replace("\n", "\r\n")
    r = run(make_repo("crlf", {WORKFLOW: crlf}))
    check(f"{WORKFLOW}:8: " in r.stdout, "a file with CRLF line endings: the finding names line 8", r.stdout)
    lone_cr = workflow("        run: echo \"${{ secrets.X }}\"").replace("\n", "\r")
    r = run(make_repo("lone-cr", {WORKFLOW: lone_cr}))
    check(f"{WORKFLOW}:8: " in r.stdout, "a file with lone CR line endings: the finding names line 8", r.stdout)
    unicode_breaks = ("name: w\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n"
                      "      - name: \"a\x85b\u2028c\u2029d\"\n        run: \"echo ${{ x }}\"\n")
    r = run(make_repo("unicode", {WORKFLOW: unicode_breaks}))
    check(f"{WORKFLOW}:8: " in r.stdout and f"{WORKFLOW}:10: " not in r.stdout, "U+0085, U+2028 and U+2029 inside a value do not shift the line: 8, not 10", r.stdout)

    # the same file on a console whose code page cannot encode the name: the findings still come out, escaped, with no traceback
    legacy = dict(clean_env(), PYTHONIOENCODING="cp1251", PYTHONUTF8="0")
    r = run(make_repo("unicode-cp1251", {WORKFLOW: unicode_breaks}), env=legacy)
    check(r.returncode == 1 and "Traceback" not in r.stderr and f"{WORKFLOW}:8: " in r.stdout, "a name the console cannot encode does not end the run in a traceback", r.stdout + r.stderr)

    # a step name is the pull request author's text and goes into the log: a line break in it must not start a workflow command there
    injected = workflow("        run: echo \"${{ secrets.X }}\"").replace("the step", "a\\n::error::forged\\n::add-mask::hidden")
    injected = injected.replace("name: a\\n", "name: \"a\\n").replace("hidden\n", "hidden\"\n")
    r = run(make_repo("injected", {WORKFLOW: injected}))
    check(r.returncode == 1 and not any(line.startswith("::") for line in r.stdout.splitlines()) and "::error::forged" in r.stdout,
          "a step name with a line break and a workflow command cannot put a command at the start of a log line", r.stdout)

    # a readable name in Russian stays readable
    russian = workflow("        run: echo \"${{ secrets.X }}\"").replace("the step", "Сборка и проверка")
    r = run(make_repo("russian", {WORKFLOW: russian}), env=dict(clean_env(), PYTHONIOENCODING="utf-8"), encoding="utf-8")
    check("Сборка и проверка" in r.stdout, "a step named in Russian is printed as it is", r.stdout)

    # two jobs, one violation in the second: the job and the line
    jobs = ("name: w\non: push\njobs:\n  one:\n    runs-on: x\n    steps:\n      - run: echo fine\n"
            "  two:\n    runs-on: x\n    defaults:\n      run:\n        shell: \"${{ inputs.sh }} {0}\"\n    steps:\n      - run: echo fine\n")
    r = run(make_repo("jobs", {WORKFLOW: jobs}))
    check(f"{WORKFLOW}:12: " in r.stdout and 'job "two"' in r.stdout and 'job "one"' not in r.stdout, "defaults.run.shell: the finding names the second job and line 12", r.stdout)

    # not violations
    root = make_repo("ok-env", {WORKFLOW: workflow("        env:\n          X: ${{ secrets.X }}\n        run: printf '%s' \"$X\" | wc -c")})
    r = run(root)
    check(r.returncode == 0, "an expression in env: passes", r.stdout + r.stderr)
    root = make_repo("ok-wfshell", {WORKFLOW: workflow("        run: echo hi\n        shell: \"${{ inputs.sh }} {0}\"")})
    r = run(root)
    check(r.returncode == 0, "shell: of a workflow step is not evaluated by the runner and passes", r.stdout + r.stderr)

    # an input the caller declares as executed: refused on any action, and only once it is declared
    wrapper_step = ("        uses: some/wrapper@v1\n        with:\n          build-command: docker build --build-arg \"X=${{ github.run_id }}\" .\n"
                    "          note: ${{ github.sha }}")
    declared = dict(clean_env(), EXECUTED_INPUTS="build-command")
    root = make_repo("declared", {WORKFLOW: workflow(wrapper_step)})
    r = run(root, env=declared)
    check(r.returncode == 1 and f"{WORKFLOW}:10: " in r.stdout and "with.build-command" in r.stdout and "with.note" not in r.stdout,
          "a declared input holding an expression is refused with its line, and its undeclared neighbour is not", r.stdout + r.stderr)
    r = run(root)
    check(r.returncode == 0, "the same input is data until the caller declares it", r.stdout + r.stderr)
    root = make_repo("declared-clean", {WORKFLOW: workflow("        uses: some/wrapper@v1\n        with:\n          build-command: docker build --build-arg \"X=${RUN}\" .")})
    r = run(root, env=declared)
    check(r.returncode == 0 and "OK:" in r.stdout, "a declared input without an expression passes", r.stdout + r.stderr)
    cased = workflow("        uses: some/wrapper@v1\n        with:\n          Build-Command: docker build --build-arg \"X=${{ github.run_id }}\" .")
    r = run(make_repo("declared-cased-key", {WORKFLOW: cased}), env=declared)
    check(r.returncode == 1 and f"{WORKFLOW}:10: " in r.stdout, "an input written in another case than the declared name is read the same: GitHub matches input names without regard to case", r.stdout + r.stderr)
    r = run(make_repo("declared-cased-name", {WORKFLOW: workflow(wrapper_step)}), env=dict(clean_env(), EXECUTED_INPUTS="BUILD-COMMAND"))
    check(r.returncode == 1 and f"{WORKFLOW}:10: " in r.stdout, "a name declared in another case than the input is read the same", r.stdout + r.stderr)
    # a declared name that no step sets protects nothing: the run fails and names it, and a name that is set passes beside it
    r = run(make_repo("declared-unmatched", {WORKFLOW: workflow("        run: echo hello")}), env=declared)
    check(r.returncode == 1 and "build-command" in r.stdout and "set by no step" in r.stdout, "a declared name that no step sets fails the run and is named", r.stdout + r.stderr)
    r = run(make_repo("declared-one-unmatched", {WORKFLOW: workflow(wrapper_step.replace("${{ github.run_id }}", "${RUN}").replace("${{ github.sha }}", "x"))}),
            env=dict(clean_env(), EXECUTED_INPUTS="build-command typo-command"))
    check(r.returncode == 1 and "typo-command" in r.stdout and "build-command," not in r.stdout and "OK:" not in r.stdout,
          "of two declared names, the one no step sets is named and the other is not", r.stdout + r.stderr)
    r = run(make_repo("declared-unmatched-other-case", {WORKFLOW: workflow("        uses: some/wrapper@v1\n        with:\n          BUILD-COMMAND: docker build .")}), env=declared)
    check(r.returncode == 0 and "OK:" in r.stdout, "a declared name set under another case counts as set", r.stdout + r.stderr)
    two_names = dict(clean_env(), EXECUTED_INPUTS="other-command\nbuild-command")
    r = run(make_repo("declared-two", {WORKFLOW: workflow(wrapper_step)}), env=two_names)
    check(r.returncode == 1 and "with.build-command" in r.stdout, "several declared names, separated by a line break, are all read", r.stdout + r.stderr)

    # empty sweep is a failure, not a clean result
    root = make_repo("empty", {"README.md": "# nothing\n"})
    r = run(root)
    check(r.returncode == 1 and "no workflow or action files found" in r.stdout, "a repository with no workflow and no action: exit 1", r.stdout + r.stderr)

    # only tracked files are read
    root = make_repo("untracked", {WORKFLOW: workflow("        run: echo hello")})
    (root / ".github" / "workflows" / "loose.yml").write_text(workflow("        run: echo \"${{ secrets.X }}\""), encoding="utf-8")
    r = run(root)
    check(r.returncode == 0, "a violation in an untracked file is not read (the index is what CI sees)", r.stdout + r.stderr)
    git(root, "add", "-A")
    r = run(root)
    check(r.returncode == 1 and "loose.yml" in r.stdout, "the same file once tracked is refused", r.stdout + r.stderr)

    # a broken YAML is a finding, not a crash
    root = make_repo("broken", {WORKFLOW: "name: w\njobs: [\n"})
    r = run(root)
    check(r.returncode == 1 and "YAML parse error" in r.stdout, "an unparseable workflow is reported by name", r.stdout + r.stderr)

    # the self-test stops the check when one class is removed from it
    source = CHECK.read_text(encoding="utf-8")
    mutations = {
        "with.script dropped": ('values.extend(input_values(inputs, "script"))', "pass"),
        "input names compared with case": ("key.lower() == name.lower()", "key == name"),
        "composite shell dropped": ('values.append(("shell:", step.get("shell"), span_in(step, "shell")))', "pass"),
        "docker args dropped": ('values.extend(input_values(inputs, "args"))', "pass"),
        "job default shell dropped": ("if holds_expression(shell):", "if False:"),
        "line off by one": ('return text.count("\\n", 0, position) + 1', 'return text.count("\\n", 0, position)'),
        "block scalar line lost (the value's first line only)": ("position = text.find(EXPRESSION_OPENING, first, last)", "position = first"),
        "line breaks not normalised": ('return text.replace("\\r\\n", "\\n").replace("\\r", "\\n")', "return text"),
        "lines counted by splitlines": ('return text.count("\\n", 0, position) + 1', 'return len(text[:position].replace("\\n", "\\n#").splitlines())'),
        "declared inputs dropped": ("            values.extend(found)", "            pass"),
        "unmatched declared names not reported": ("return [name for name in executed_inputs if name.lower() not in seen]", "return []"),
        "composite actions dropped": ('if isinstance(runs, dict) and isinstance(runs.get("steps"), list):\n        found.append(("composite action", runs["steps"], True))', "pass"),
    }
    for label, (old, new) in mutations.items():
        assert old in source, f"mutation target missing: {label}"
        mutated = work / f"mutated-{len(results)}" / "lint-no-inline-secrets.py"
        mutated.parent.mkdir()
        mutated.write_text(source.replace(old, new), encoding="utf-8", newline="\n")
        root = make_repo("for-mutant-" + str(len(results)), {WORKFLOW: workflow("        run: echo hello")})
        r = run(root, script=mutated)
        check(r.returncode != 0 and ("check is broken" in r.stdout + r.stderr or "Error" in r.stderr), f"the self-test stops a check that lost a class: {label}", r.stdout + r.stderr)

    # the check that cries wolf: a mutant flagging everything is stopped too
    wolf = work / "wolf" / "lint-no-inline-secrets.py"
    wolf.parent.mkdir()
    wolf.write_text(source.replace("return isinstance(value, str) and EXPRESSION_OPENING in value", "return isinstance(value, str)"), encoding="utf-8", newline="\n")
    r = run(make_repo("for-wolf", {WORKFLOW: workflow("        run: echo hello")}), script=wolf)
    check(r.returncode != 0 and "cries wolf" in r.stdout + r.stderr, "the self-test stops a check that flags a clean step", r.stdout + r.stderr)

    # the incident: a worktree and a hook's GIT_* variables must not let the self-test's `git init` reach the shared configuration
    main_repo = make_repo("main", {WORKFLOW: workflow("        run: echo hello")})
    assert git(main_repo, "commit", "-q", "-m", "x").returncode == 0
    tree = work / "tree"
    assert git(main_repo, "worktree", "add", "-q", str(tree), "-b", "side").returncode == 0
    common = main_repo / ".git"
    config_before = (common / "config").read_bytes()
    worktree_git_dir = next((common / "worktrees").iterdir())
    hook_env = dict(os.environ, GIT_DIR=str(worktree_git_dir), GIT_INDEX_FILE=str(worktree_git_dir / "index"))
    r = subprocess.run([sys.executable, str(CHECK), str(tree)], capture_output=True, text=True, env=hook_env, cwd=tree, timeout=120)
    check(r.returncode == 0, "inside a worktree with a hook's GIT_DIR the check still answers", r.stdout + r.stderr)
    check((common / "config").read_bytes() == config_before, "the shared git configuration is byte for byte the same afterwards", r.stdout + r.stderr)
    bare = subprocess.run(["git", "config", "--get", "core.bare"], cwd=main_repo, capture_output=True, text=True, env=clean_env()).stdout.strip()
    check(bare == "false", "the main checkout is still not bare", bare)

    # the action file: no expression inside run:, the path reaches the script through env
    text = ACTION.read_text(encoding="utf-8")
    import yaml
    doc = yaml.safe_load(text)
    step = doc["runs"]["steps"][0]
    check(doc["runs"]["using"] == "composite" and "${{" not in step["run"] and step["env"]["ACTION_PATH"] == "${{ github.action_path }}", "the action binds its path through env and keeps run: free of expressions")
    check("lint-no-inline-secrets.py" in step["run"] and doc["inputs"]["root"]["default"] == ".", "the action runs the script beside it on the repository root by default")
    check(doc["inputs"]["executed-inputs"]["default"] == "" and step["env"]["EXECUTED_INPUTS"] == "${{ inputs.executed-inputs }}" and "${{" not in text.split("description:", 1)[1].split("inputs:", 1)[0],
          "the declared names reach the script through env, default to none, and the description holds no expression token")
finally:
    shutil.rmtree(work, ignore_errors=True)

failed = [x for x in results if not x[0]]
for ok, label in results:
    print("ok  " if ok else "FAIL", label)
print(f"\n{len(results) - len(failed)} of {len(results)} passed")
sys.exit(1 if failed else 0)
