"""Publish matching Go submodule tags from an existing root release."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


MODULES = ("adapter/base", "adapter/gorm", "adapter/kafka", "adapter/nats", "adapter/redis")
VERSION = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?")


def run(*args, cwd, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()


def remote_tags(repo, remote, tags):
    refs = [ref for tag in tags for ref in (f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}")]
    output = run("git", "ls-remote", "--tags", remote, *refs, cwd=repo)
    values = dict(line.split()[::-1] for line in output.splitlines())
    return {tag: values.get(f"refs/tags/{tag}^{{}}", values.get(f"refs/tags/{tag}")) for tag in tags}


def publish(repo, version, remote="origin", dry_run=False):
    match = VERSION.fullmatch(version)
    if not match or any(part.isdigit() and len(part) > 1 and part[0] == "0"
                        for part in (match[4] or "").split(".")):
        raise ValueError(f"Expected a Go release version such as v0.3.0 or v0.3.0-rc.1: {version}")

    source = run("git", "rev-parse", f"refs/tags/{version}^{{commit}}", cwd=repo)
    if remote_tags(repo, remote, [version])[version] != source:
        raise ValueError("The root tag must already exist on the remote and match the local tag")

    go_env = dict(os.environ, GOWORK="off", GOTOOLCHAIN="local")
    with tempfile.TemporaryDirectory(prefix="go-casbin-release-") as tmp:
        checkout = Path(tmp) / "source"
        run("git", "worktree", "add", "--detach", str(checkout), source, cwd=repo)
        try:
            root = json.loads(run("go", "mod", "edit", "-json", cwd=checkout, env=go_env))["Module"]["Path"]
            major = int(match[1])
            if major >= 2:
                raise ValueError("The current module paths support v0/v1; v2+ requires versioned submodule paths")
            base = f"{root}/adapter/base"
            for module in MODULES:
                directory = checkout / module
                metadata = json.loads(run("go", "mod", "edit", "-json", cwd=directory, env=go_env))
                if metadata["Module"]["Path"] != f"{root}/{module}":
                    raise ValueError(f"Unexpected module path in {module}/go.mod")
                if module != "adapter/base":
                    if not any(req["Path"] == base for req in metadata.get("Require", [])):
                        raise ValueError(f"Missing base dependency in {module}/go.mod")
                    run("go", "mod", "edit", f"-require={base}@{version}", cwd=directory, env=go_env)

            # Keep the root tag and branch untouched. Only the four require versions
            # differ in this deterministic release commit, shared by all module tags.
            run("git", "add", "--", *(f"{module}/go.mod" for module in MODULES[1:]), cwd=checkout)
            tree = run("git", "write-tree", cwd=checkout)
            commit_env = dict(os.environ,
                              GIT_AUTHOR_NAME="github-actions[bot]",
                              GIT_AUTHOR_EMAIL="41898282+github-actions[bot]@users.noreply.github.com",
                              GIT_COMMITTER_NAME="github-actions[bot]",
                              GIT_COMMITTER_EMAIL="41898282+github-actions[bot]@users.noreply.github.com",
                              GIT_AUTHOR_DATE=run("git", "show", "-s", "--format=%cI", source, cwd=repo),
                              GIT_COMMITTER_DATE=run("git", "show", "-s", "--format=%cI", source, cwd=repo))
            commit = run("git", "commit-tree", tree, "-p", source, "-m",
                         f"📦 release: 同步适配器依赖到 {version}", cwd=checkout, env=commit_env)
        finally:
            run("git", "worktree", "remove", "--force", str(checkout), cwd=repo)

    tags = [f"{module}/{version}" for module in MODULES]
    existing = remote_tags(repo, remote, tags)
    conflicts = [tag for tag in tags if existing[tag] and existing[tag] != commit]
    if conflicts:
        raise ValueError(f"Existing tags point to a different release; refusing to overwrite: {conflicts}")
    missing = [tag for tag in tags if not existing[tag]]
    if missing and not dry_run:
        run("git", "push", "--atomic", remote,
            *(f"{commit}:refs/tags/{tag}" for tag in missing), cwd=repo)
    for tag in tags:
        state = "exists" if existing[tag] else "dry-run" if dry_run else "published"
        print(f"{state}: {tag} -> {commit}")
    return commit


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        publish(Path.cwd(), args.version, args.remote, args.dry_run)
    except (ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Release failed: {exc}\n")
