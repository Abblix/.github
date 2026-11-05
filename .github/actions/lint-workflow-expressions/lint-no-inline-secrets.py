"""
Fail if any workflow or action carries a GitHub Actions expression inside a value the runner
executes as program text.

GitHub interpolates `${{ ... }}` into that text BEFORE the program parses it. If the
interpolated value contains metacharacters of the language, the step is vulnerable to code
injection. Always pass through `env:` and reference as `$VAR` (or `process.env.VAR`):

    env:
      MY_SECRET: ${{ secrets.MY_SECRET }}
    run: |
      printf '%s' "$MY_SECRET" | ...

The values read as program text:
- `run:` of every step;
- `shell:` of a composite action's step and `jobs.<job_id>.defaults.run.shell` of a workflow -
  both are evaluated by the runner (its action schema types a composite step's `shell` as a
  string with contexts, and GitHub's contexts table lists `jobs.<job_id>.defaults.run`), and the
  value becomes the command line that starts the interpreter;
- `with.script` of `actions/github-script`, which the action evaluates as JavaScript;
- `with.args` and `with.entrypoint` of a `docker://` step, the command line of the container;
- `runs.args` of a Docker container action, which the runner's action schema evaluates with the
  `inputs` context and hands to the entrypoint, a shell whenever the entrypoint is `sh -c`. Its
  `entrypoint`, `pre-entrypoint` and `post-entrypoint` are plain strings there, never evaluated;
- `with.<name>` of any step, for each name the caller lists in the environment variable
  EXECUTED_INPUTS (the action input `executed-inputs`). An action that hands one of its inputs to
  `sh -c` or `eval` holds program text there, and only its owner knows which input that is. The
  check cannot read an action that lives in another repository, so the caller names the input.

The rule is the whole of it: NO expression inside those values, whatever it reads. A list of
dangerous contexts cannot be completed - `secrets['X']`, `toJSON(secrets)` and
`format('{0}', github.event.issue.title)` all read the same values under other spellings,
and each one passed an earlier list silently. An expression exists in a value exactly when
the value holds the template's opening token `${{`: the runner has no other way to start one
and no escape for it inside the string, so the token alone decides whether a value holds an expression.

The files read are the TRACKED ones (`git ls-files`), as CI sees them: every workflow at the
top of `.github/workflows` and every `action.yml`/`action.yaml` under `.github` at any depth.

The composite action `lint-workflow-expressions` beside this file runs the check in CI, and a
repository pins it by commit. Keep one copy of the script: a copy per repository drifts without
anyone noticing, and a copy with an older list of dangerous contexts passes `secrets['X']`.

actionlint covers part of this ("potentially untrusted" `github.event.*` fields) and
none of `secrets.*` or `inputs.*`, so this check stays beside it.

Usage: python lint-no-inline-secrets.py [repository root, default the current directory]
"""
from __future__ import annotations

import collections.abc
import os
import pathlib
import subprocess
import sys
import tempfile

import yaml

EXPRESSION_OPENING = "${{"
GITHUB_DIR = ".github"
WORKFLOWS_DIR = ".github/workflows"
WORKFLOW_SUFFIXES = (".yml", ".yaml")
ACTION_FILE_NAMES = ("action.yml", "action.yaml")
GITHUB_SCRIPT = "actions/github-script"
DOCKER_IMAGE = "docker://"
# The variables through which an inherited environment names a repository; each gets a decoy in
# the self-test, and the isolated git calls drop every GIT_* variable, these included.
DIRECTORY_VARIABLES = ("GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY")


class CheckRefused(Exception):
    """The check cannot give an answer; its message says why."""


# A (first, last) pair of CHARACTER offsets of a value in the source text. Offsets, not the parser's line numbers: the parser counts
# U+0085, U+2028 and U+2029 as line breaks, an editor and GitHub's file view do not, and a finding must name the line a person sees.
Span = tuple[int, int]


class LineDict(dict):
    """A mapping that remembers where its values lie in the source text, so a finding can name the line it is on."""

    spans: dict


class LineList(list):
    """A sequence that remembers where its items lie in the source text."""

    spans: list


class LineLoader(yaml.SafeLoader):
    """SafeLoader whose mappings and sequences carry the source offsets of their values (a node knows where it began and ended)."""


def _construct_mapping(loader: LineLoader, node: yaml.MappingNode) -> LineDict:
    loader.flatten_mapping(node)
    result = LineDict()
    result.spans = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, collections.abc.Hashable):
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark, "found unhashable key", key_node.start_mark
            )
        result[key] = loader.construct_object(value_node, deep=True)
        result.spans[key] = (value_node.start_mark.index, value_node.end_mark.index)
    return result


def _construct_sequence(loader: LineLoader, node: yaml.SequenceNode) -> LineList:
    result = LineList(loader.construct_object(item, deep=True) for item in node.value)
    result.spans = [(item.start_mark.index, item.end_mark.index) for item in node.value]
    return result


LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG, _construct_sequence)


def normalize_line_breaks(text: str) -> str:
    """CRLF and a lone CR become LF, so that the offsets the parser reports and the lines a person sees count the same breaks."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def load_with_lines(text: str):
    """Parses `text` (already normalised by normalize_line_breaks) with the offsets of every value remembered."""
    return yaml.load(text, Loader=LineLoader)  # noqa: S506 - LineLoader is a SafeLoader that only adds offset bookkeeping


def span_in(container, key) -> Span | None:
    """The source offsets of container[key], when the container came from load_with_lines."""
    spans = getattr(container, "spans", None)
    if isinstance(spans, dict):
        return spans.get(key)
    if isinstance(spans, list) and isinstance(key, int) and 0 <= key < len(spans):
        return spans[key]
    return None


def token_line(span: Span | None, text: str | None) -> int | None:
    """The 1-based line of the expression token inside a value, counted by line feeds in the source text.

    A block scalar begins on the line of its `|` indicator, a quoted one may run over several lines, and
    the token is in the TEXT: the first place in the value's span that holds it is the answer, and the
    value's own first line is the fallback when an escape in the source spelled the token another way.
    """
    if span is None or text is None:
        return None
    first, last = span
    position = text.find(EXPRESSION_OPENING, first, last)
    if position < 0:
        position = first
    return text.count("\n", 0, position) + 1


def executed_values(step: dict, shell_evaluated: bool, executed_inputs: tuple[str, ...] = ()) -> list[tuple[str, object, Span | None]]:
    """The (key, value, source lines) triples of a step that the runner or its action executes as program text.

    `executed_inputs` are the input names the caller says its actions execute; they apply to every action."""
    values: list[tuple[str, object, Span | None]] = [("run:", step.get("run"), span_in(step, "run"))]
    if shell_evaluated:
        values.append(("shell:", step.get("shell"), span_in(step, "shell")))

    uses = step.get("uses")
    inputs = step.get("with")
    if isinstance(uses, str) and isinstance(inputs, dict):
        # The owner/repo part decides, whatever the ref after `@` and however it is cased:
        # GitHub resolves owner and repository names case-insensitively.
        action = uses.split("@", 1)[0].lower()
        if action == GITHUB_SCRIPT:
            values.append(("with.script", inputs.get("script"), span_in(inputs, "script")))
        if action.startswith(DOCKER_IMAGE):
            values.append(("with.args", inputs.get("args"), span_in(inputs, "args")))
            values.append(("with.entrypoint", inputs.get("entrypoint"), span_in(inputs, "entrypoint")))
        for name in executed_inputs:
            if name in inputs:
                values.append((f"with.{name}", inputs[name], span_in(inputs, name)))
    return values


def holds_expression(value) -> bool:
    return isinstance(value, str) and EXPRESSION_OPENING in value


def where(path: str, span: Span | None, text: str | None) -> str:
    """`path:line` (the form editors and CI logs make clickable), or the bare path when the line is unknown."""
    line = token_line(span, text)
    return f"{path}:{line}" if line else path


def violations_in(doc, path: str, text: str | None = None, executed_inputs: tuple[str, ...] = ()) -> list[str]:
    """The findings of one parsed document. `text` is the source it was parsed from (after normalize_line_breaks):
    with it every finding names the line the expression is on, without it only the file."""
    if not isinstance(doc, dict):
        return []

    violations: list[str] = []
    for context, steps, shell_evaluated in step_lists(doc):
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            step_label = step.get("name") or f"step #{idx}"
            for key, value, span in executed_values(step, shell_evaluated, executed_inputs):
                if holds_expression(value):
                    violations.append(f"{where(path, span, text)}: {context} / {step_label}: expression inside {key}")

    jobs = doc.get("jobs")
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            shell, span = job_default_shell(job)
            if holds_expression(shell):
                violations.append(f'{where(path, span, text)}: job "{job_name}": expression inside defaults.run.shell')

    runs = doc.get("runs")
    args = runs.get("args") if isinstance(runs, dict) else None
    if isinstance(args, list):
        for idx, arg in enumerate(args):
            if holds_expression(arg):
                violations.append(f"{where(path, span_in(args, idx), text)}: docker action: expression inside runs.args[{idx}]")
    return violations


def job_default_shell(job) -> tuple[object, Span | None]:
    """The job's defaults.run.shell and its source lines, (None, None) when the job sets none."""
    if not isinstance(job, dict):
        return None, None
    defaults = job.get("defaults")
    run = defaults.get("run") if isinstance(defaults, dict) else None
    if not isinstance(run, dict):
        return None, None
    return run.get("shell"), span_in(run, "shell")


def step_lists(doc: dict) -> list[tuple[str, list, bool]]:
    """Yield (context label, steps, whether a step's shell: is evaluated) for both document shapes.

    A workflow keeps its steps under jobs.<name>.steps; a composite action keeps a single
    list under runs.steps. Composite actions carry the same run: blocks with the same
    secrets, so leaving them unscanned would enforce the rule on half the surface it was
    written for. A workflow step's `shell:` is not evaluated (GitHub's contexts table has no
    row for it and the runner's workflow schema gives it no contexts), a composite step's is.
    """
    found: list[tuple[str, list, bool]] = []

    jobs = doc.get("jobs")
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if isinstance(job, dict) and isinstance(job.get("steps"), list):
                found.append((f'job "{job_name}"', job["steps"], False))

    runs = doc.get("runs")
    if isinstance(runs, dict) and isinstance(runs.get("steps"), list):
        found.append(("composite action", runs["steps"], True))

    return found


def scan_file(root: pathlib.Path, rel: str, executed_inputs: tuple[str, ...] = ()) -> list[str]:
    text = normalize_line_breaks((root / rel).read_text(encoding="utf-8"))
    try:
        doc = load_with_lines(text)
    except yaml.YAMLError as exc:
        return [f"{rel}: YAML parse error: {exc}"]
    return violations_in(doc, rel, text, executed_inputs)


def tracked_files(root: pathlib.Path, isolated: bool = False) -> list[str]:
    """Every path in the index, relative and with forward slashes, that exists on disk.

    `safe.directory` is passed on the command line, which git honours there: a CI container
    checks the repository out under another user, and git then refuses to read it.
    """
    paths = git(root, "ls-files", "-z", isolated=isolated).split("\0")
    return sorted(p for p in paths if p and (root / p).is_file())


def git(root: pathlib.Path, *args: str, isolated: bool = False) -> str:
    """Runs git in root. `isolated` drops the GIT_* variables a hook inherits from `git commit`.

    Inside a hook GIT_INDEX_FILE names the index of the commit being made, and git obeys it over
    `-C`: the self-test's planted repository would stage its files into the real commit. In a
    worktree GIT_DIR names the worktree's directory under the main checkout, and `git init` with
    it writes `core.bare = true` into the configuration the main checkout shares.
    """
    absolute = root.resolve().as_posix()
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")} if isolated else None
    try:
        result = subprocess.run(
            ["git", "-c", f"safe.directory={absolute}", "-C", absolute, *args],
            capture_output=True,
            check=False,
            env=env,
        )
    except FileNotFoundError as exc:
        raise CheckRefused("git is not on PATH - cannot list the tracked files") from exc
    if result.returncode != 0:
        raise CheckRefused(f"git {args[0]} failed: {result.stderr.decode('utf-8', 'replace').strip()}")
    return decode_output(result.stdout)


def decode_output(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CheckRefused(f"git listed a path that is not UTF-8 ({raw[max(0, exc.start - 40):exc.end]!r})") from exc


def discover(tracked: list[str]) -> list[str]:
    """Workflows as GitHub reads them (top level of .github/workflows) and every action file under .github."""
    found = []
    for rel in tracked:
        path = pathlib.PurePosixPath(rel)
        is_workflow = str(path.parent) == WORKFLOWS_DIR and path.suffix in WORKFLOW_SUFFIXES
        is_action = rel.startswith(GITHUB_DIR + "/") and path.name in ACTION_FILE_NAMES
        if is_workflow or is_action:
            found.append(rel)
    return found


def self_test_row(name: str, action):
    """Runs one self-test row; anything but a deliberate refusal fails the row by name, not as a traceback."""
    try:
        return action()
    except CheckRefused:
        raise
    except Exception as exc:  # A row that crashes has not been answered, whatever the exception.
        sys.exit(f"lint-no-inline-secrets: self-test row '{name}' was not refused cleanly ({type(exc).__name__}: {exc}) - the check is broken.")


def self_test() -> None:
    """Refuses to run when a planted expression is not found, or a clean step is flagged."""

    # The row wrapper itself: a crashing row must end the run by name, not escape as an exception.
    try:
        self_test_row("probe", lambda: int("not a number"))
        sys.exit("lint-no-inline-secrets: a crashing self-test row is not stopped - the check is broken.")
    except SystemExit as stopped:
        expected = (
            "lint-no-inline-secrets: self-test row 'probe' was not refused cleanly "
            "(ValueError: invalid literal for int() with base 10: 'not a number') - the check is broken."
        )
        if stopped.code != expected:
            raise

    def findings_of(name: str, source: str) -> list[str]:
        return self_test_row(name, lambda: violations_in(load_with_lines(normalize_line_breaks(source)), "planted", normalize_line_breaks(source)))

    def flagged(name: str, source: str) -> bool:
        return bool(findings_of(name, source))

    planted = {
        "spaced": 'jobs:\n  a:\n    steps:\n      - run: echo "${{ secrets.X }}"\n',
        "unspaced": 'jobs:\n  a:\n    steps:\n      - run: echo "${{secrets.X}}"\n',
        # An index and a function read the same secrets under spellings a context list misses.
        "indexed": "jobs:\n  a:\n    steps:\n      - run: echo \"${{ secrets['X'] }}\"\n",
        "function": 'jobs:\n  a:\n    steps:\n      - run: echo "${{ toJSON(github.event) }}"\n',
        "deep in a block": (
            "jobs:\n  a:\n    steps:\n      - run: |\n          set -e\n"
            "          echo ok\n          echo \"${{ github.event.issue.title }}\"\n"
        ),
        "composite action": 'runs:\n  steps:\n    - run: echo "${{ inputs.x }}"\n',
        "composite shell": 'runs:\n  steps:\n    - run: echo hi\n      shell: "${{ inputs.sh }} {0}"\n',
        "job default shell": (
            'jobs:\n  a:\n    defaults:\n      run:\n        shell: "${{ inputs.sh }} {0}"\n'
            "    steps:\n      - run: echo hi\n"
        ),
        "github-script": (
            "jobs:\n  a:\n    steps:\n      - uses: actions/github-script@0123456789abcdef0123456789abcdef01234567\n"
            "        with:\n          script: console.log('${{ github.event.issue.title }}')\n"
        ),
        "github-script, other case and tag": (
            "jobs:\n  a:\n    steps:\n      - uses: Actions/GitHub-Script@v7\n"
            "        with:\n          script: console.log('${{ inputs.x }}')\n"
        ),
        "github-script in a composite action": (
            "runs:\n  steps:\n    - uses: actions/github-script@v7\n"
            "      with:\n        script: console.log('${{ inputs.x }}')\n"
        ),
        "docker args": (
            "jobs:\n  a:\n    steps:\n      - uses: docker://alpine:3\n"
            "        with:\n          args: sh -c \"echo ${{ inputs.x }}\"\n"
        ),
        "docker entrypoint": (
            "jobs:\n  a:\n    steps:\n      - uses: docker://alpine:3\n"
            "        with:\n          entrypoint: ${{ inputs.x }}\n"
        ),
        "docker action args, not the first": (
            "runs:\n  using: docker\n  image: Dockerfile\n  entrypoint: sh\n"
            "  args:\n    - -c\n    - echo ${{ inputs.x }}\n"
        ),
        # U+0085, U+2028 and U+2029 are line breaks to the YAML parser and not to an editor; CRLF and a lone CR are breaks to both.
        # The finding names the line a person sees.
        "unicode line breaks before the value": 'jobs:\n  a:\n    steps:\n      - name: "a\x85b\u2028c\u2029d"\n        run: "echo ${{ x }}"\n',
        "carriage returns before the value": 'jobs:\r\n  a:\r\n    steps:\r      - name: x\r\n        run: "echo ${{ x }}"\r\n',
    }
    missed = [name for name, source in planted.items() if not flagged(name, source)]
    if missed:
        sys.exit(f"lint-no-inline-secrets: planted expression not found ({', '.join(missed)}) - the check is broken.")

    # The line each finding names, counted by hand from the planted source above: a block scalar's finding is the
    # line of the expression inside it, not the line of its `|`; a nested value is the line of its own key.
    expected_lines = {
        "spaced": 4,
        "deep in a block": 7,
        "composite action": 3,
        "composite shell": 4,
        "job default shell": 5,
        "github-script": 6,
        "docker args": 6,
        "docker entrypoint": 6,
        "docker action args, not the first": 7,
        "unicode line breaks before the value": 5,
        "carriage returns before the value": 5,
    }
    off = {
        name: findings_of(name, planted[name])
        for name, line in expected_lines.items()
        if not any(f.startswith(f"planted:{line}: ") for f in findings_of(name, planted[name]))
    }
    if off:
        sys.exit(f"lint-no-inline-secrets: a finding names the wrong line ({off}) - the check is broken.")

    clean = {
        "env and with": (
            "jobs:\n  a:\n    steps:\n      - env:\n          X: ${{ secrets.X }}\n"
            "        with:\n          y: ${{ inputs.y }}\n"
            '        run: printf \'%s\' "$X" | wc -c\n'
        ),
        # The same keys on other actions are ordinary inputs, handed over as data.
        "args and script on other actions": (
            "jobs:\n  a:\n    steps:\n      - uses: some/action@v1\n"
            "        with:\n          args: ${{ inputs.x }}\n          entrypoint: ${{ inputs.x }}\n"
            "          script: ${{ inputs.x }}\n"
        ),
        "github-script reading env": (
            "jobs:\n  a:\n    steps:\n      - uses: actions/github-script@v7\n"
            "        env:\n          T: ${{ github.event.issue.title }}\n"
            "        with:\n          github-token: ${{ secrets.X }}\n"
            "          script: console.log(process.env.T)\n"
        ),
        "plain shells": (
            "jobs:\n  a:\n    defaults:\n      run:\n        shell: bash\n"
            "    steps:\n      - run: echo hi\n        shell: pwsh\n"
        ),
        # Not evaluated by the runner, so the token there is not program text (see step_lists).
        "workflow step shell": 'jobs:\n  a:\n    steps:\n      - run: echo hi\n        shell: "${{ inputs.sh }} {0}"\n',
        "docker action env": (
            "runs:\n  using: docker\n  image: Dockerfile\n  env:\n    X: ${{ inputs.x }}\n  args:\n    - plain\n"
        ),
        # The runner's action schema gives these plain strings with no contexts: never evaluated.
        "docker action entrypoints": (
            "runs:\n  using: docker\n  image: Dockerfile\n  entrypoint: ${{ inputs.x }}\n"
            "  pre-entrypoint: ${{ inputs.x }}\n  post-entrypoint: ${{ inputs.x }}\n"
        ),
    }
    noisy = [name for name, source in clean.items() if flagged(name, source)]
    if noisy:
        sys.exit(f"lint-no-inline-secrets: a clean step is flagged ({', '.join(noisy)}) - the check cries wolf.")

    self_test_declared_inputs()
    self_test_discovery()


def self_test_declared_inputs() -> None:
    """An input the caller names is checked on any action; an input it does not name is data."""
    source = normalize_line_breaks(
        "jobs:\n  a:\n    steps:\n      - uses: some/wrapper@v1\n        with:\n"
        '          build-command: docker build --build-arg "X=${{ github.run_id }}" .\n'
        "          note: ${{ github.sha }}\n"
    )

    def findings(name: str, declared: tuple[str, ...]) -> list[str]:
        return self_test_row(name, lambda: violations_in(load_with_lines(source), "planted", source, declared))

    named = findings("declared input", ("build-command",))
    if not any(f.startswith("planted:6: ") and "with.build-command" in f for f in named):
        sys.exit("lint-no-inline-secrets: a planted expression in a declared executed input is not found - the check is broken.")
    if len(named) != 1:
        sys.exit("lint-no-inline-secrets: an input that was not declared is flagged next to a declared one - the check cries wolf.")
    if findings("undeclared input", ()):
        sys.exit("lint-no-inline-secrets: an input nobody declared is flagged - the check cries wolf.")


def self_test_discovery() -> None:
    """Plants a repository and refuses to run when discovery misreads it or git reaches a real repository."""
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        planted_files = [
            ".github/workflows/w.yml",
            ".github/workflows/w2.yaml",
            ".github/actions/group/x/action.yml",
            ".github/actions/y/action.yaml",
            ".github/action.yml",
        ]
        nested_workflow = ".github/workflows/nested/not-a-workflow.yml"
        untracked_action = ".github/actions/z/node_modules/dep/action.yml"
        for rel in [*planted_files, nested_workflow, untracked_action]:
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("{}\n", encoding="utf-8")
        # The real repository's shared configuration, read through the caller's own environment:
        # in a worktree every worktree and the main checkout share it, so a planted repository's
        # git call that reached it (core.bare, say) would break all of them at once. Outside any
        # repository (a CI step that checked nothing out) there is none to guard.
        real_config = None
        real_config_before = None
        try:
            common_dir = git(pathlib.Path("."), "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
            real_config = pathlib.Path(common_dir) / "config"
            real_config_before = real_config.read_bytes()
        except CheckRefused:
            pass

        # A hook's repository variables, planted as decoys: if the isolation stops dropping them,
        # the planted repository's git calls land there - in a real hook, in the real repository.
        decoys = {name: root / f"decoy-{name.lower()}" for name in DIRECTORY_VARIABLES}
        inherited = {name: os.environ.get(name) for name in DIRECTORY_VARIABLES}
        os.environ.update({name: str(path) for name, path in decoys.items()})
        # A leak usually makes a LATER git call fail, so a git error is held until the leak checks
        # below have run: otherwise the cause would be reported as an ordinary git failure.
        git_error = None
        try:
            git(root, "init", "-q", isolated=True)
            git(root, "add", "--", *planted_files, nested_workflow, isolated=True)
            tracked = tracked_files(root, isolated=True)
        except CheckRefused as exc:
            git_error = exc
        finally:
            for name, value in inherited.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        reached = [name for name, path in decoys.items() if path.exists()]
        if reached:
            sys.exit(f"lint-no-inline-secrets: the self-test's git reached an inherited {', '.join(reached)} - in a hook that is the real repository.")
        if real_config is not None and real_config.read_bytes() != real_config_before:
            # Worktrees share this file, so another git process may have written it meanwhile.
            sys.exit(f"lint-no-inline-secrets: {real_config} changed during the self-test - its planted repository or another git process wrote it.")
        if git_error is not None:
            sys.exit(f"lint-no-inline-secrets: {git_error}")
        found = discover(tracked)
        if found != sorted(planted_files):
            sys.exit(f"lint-no-inline-secrets: discovery read {found}, planted {sorted(planted_files)} - the check is broken.")

        try:
            self_test_row("path not UTF-8", lambda: decode_output(b".github/workflows/\xff.yml\0"))
            sys.exit("lint-no-inline-secrets: a path that is not UTF-8 is accepted - the check is broken.")
        except CheckRefused:
            pass


def printable(text: str) -> str:
    """The text with every character that is not plainly printable written as an escape.

    A finding quotes names that come from the repository under check - a step's name, a job's key, a
    path - and in a pull request that is the author's text. The runner reads workflow commands (`::error::`,
    `::add-mask::`) from the START OF A LINE of the log, so a name holding a line break would let the author
    plant one; control characters and the Unicode line separators (U+0085, U+2028, U+2029) are escaped for that
    reason, and any other character is left as it is, so a step named in Russian stays readable.
    """
    return "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in text)


def self_test_printable() -> None:
    quoted = printable("a\nb\r::error::x c\x85d\te")
    if any(ch in quoted for ch in "\n\r \x85\t") or "::error::x" not in quoted:
        sys.exit("lint-no-inline-secrets: a finding can still carry a line break of its own - the check is broken.")
    if printable("Сборка и проверка") != "Сборка и проверка":
        sys.exit("lint-no-inline-secrets: a readable name is mangled - the check cries wolf.")


def main(argv: list[str]) -> int:
    # A console whose code page cannot encode a character of a name must not end the run in a traceback that hides the findings,
    # on either stream: a message of a failed self-test goes to stderr.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    self_test()
    self_test_printable()

    root = pathlib.Path(argv[1] if len(argv) > 1 else ".")
    try:
        tracked = tracked_files(root)
    except CheckRefused as exc:
        print(f"lint-no-inline-secrets: {printable(str(exc))}")
        return 1

    files = discover(tracked)
    if not files:
        print("no workflow or action files found - the check is looking in the wrong place")
        return 1
    executed_inputs = tuple(os.environ.get("EXECUTED_INPUTS", "").split())
    all_violations: list[str] = []
    for rel in files:
        all_violations.extend(scan_file(root, rel, executed_inputs))

    if all_violations:
        print(
            "GitHub Actions expression detected inside a value executed as program text.\n"
            "Bind the value in env: and reference it as $VAR (process.env.VAR in github-script).\n"
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"
            "#using-an-intermediate-environment-variable\n"
        )
        for violation in all_violations:
            print(f"  - {printable(violation)}")
        return 1

    print(f"OK: no expression inside an executed value across {len(files)} workflow/action file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
