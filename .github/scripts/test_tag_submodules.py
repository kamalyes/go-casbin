"""Exercise release tags and consumer installation using a local bare remote."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

from tag_submodules import MODULES, publish, remote_tags, run


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="go-casbin-release-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.remote = str(self.root / "remote.git")
        run("git", "init", "--bare", self.remote, cwd=self.root)
        run("git", "init", cwd=self.repo)
        run("git", "config", "user.name", "Release Test", cwd=self.repo)
        run("git", "config", "user.email", "test@example.invalid", cwd=self.repo)
        run("git", "config", "commit.gpgsign", "false", cwd=self.repo)
        run("git", "remote", "add", "origin", self.remote, cwd=self.repo)
        (self.repo / "go.mod").write_text("module example.com/casbin\n\ngo 1.25.0\n")
        for index, module in enumerate(MODULES):
            directory = self.repo / module
            directory.mkdir(parents=True)
            manifest = f"module example.com/casbin/{module}\n\ngo 1.25.0\n"
            code = "package adapter\n\nfunc Value() int { return 42 }\n"
            if index:
                manifest += "\nrequire example.com/casbin/adapter/base v0.0.0\n"
                manifest += "\nreplace example.com/casbin/adapter/base => ../base\n"
                code = ('package adapter\n\nimport base "example.com/casbin/adapter/base"\n'
                        '\nfunc Value() int { return base.Value() }\n')
            (directory / "go.mod").write_text(manifest)
            (directory / "adapter.go").write_text(code)
        run("git", "add", ".", cwd=self.repo)
        run("git", "commit", "-m", "fixture", cwd=self.repo)
        self.source = run("git", "rev-parse", "HEAD", cwd=self.repo)
        run("git", "tag", "v0.3.0", cwd=self.repo)
        run("git", "push", "origin", "refs/tags/v0.3.0", cwd=self.repo)

    def test_release_is_installable_and_repeatable(self):
        commit = publish(self.repo, "v0.3.0")
        tags = [f"{module}/v0.3.0" for module in MODULES]
        self.assertEqual(set(remote_tags(self.repo, "origin", tags).values()), {commit})
        self.assertEqual(publish(self.repo, "v0.3.0"), commit)
        self.assertEqual(run("git", "rev-parse", "HEAD", cwd=self.repo), self.source)
        self.assertEqual(run("git", "rev-parse", "v0.3.0", cwd=self.repo), self.source)
        self.assertEqual(run("git", "status", "--porcelain", cwd=self.repo), "")
        self.assertEqual(run("git", "show", "-s", "--format=%P", commit, cwd=self.repo), self.source)
        self.assert_installable(commit)

    def assert_installable(self, commit):
        # This proxy contains the actual tagged module files. A downstream consumer
        # ignores dependency replace directives and must resolve the pinned base tag.
        proxy = self.root / "proxy"
        for module in MODULES:
            path = f"example.com/casbin/{module}"
            versions = proxy / path / "@v"
            versions.mkdir(parents=True)
            manifest = run("git", "show", f"{commit}:{module}/go.mod", cwd=self.repo) + "\n"
            (versions / "v0.3.0.mod").write_text(manifest)
            (versions / "v0.3.0.info").write_text(json.dumps({
                "Version": "v0.3.0", "Time": "2026-11-09T11:56:00Z"}))
            with zipfile.ZipFile(versions / "v0.3.0.zip", "w") as archive:
                for filename in ("go.mod", "adapter.go"):
                    data = run("git", "show", f"{commit}:{module}/{filename}", cwd=self.repo) + "\n"
                    archive.writestr(f"{path}@v0.3.0/{filename}", data)
        consumer = self.root / "consumer"
        consumer.mkdir()
        (consumer / "go.mod").write_text("module example.com/consumer\n\ngo 1.25.0\n\nrequire (\n" +
            "".join(f"example.com/casbin/{module} v0.3.0\n" for module in MODULES[1:]) + ")\n")
        imports = "".join(f'{module.rsplit("/", 1)[-1]} "example.com/casbin/{module}"\n'
                          for module in MODULES[1:])
        checks = "".join(f'if {module.rsplit("/", 1)[-1]}.Value() != 42 {{ t.Fatal("{module}") }}\n'
                         for module in MODULES[1:])
        (consumer / "consumer_test.go").write_text(
            'package consumer\nimport (\n"testing"\n' + imports + ')\nfunc TestAdapters(t *testing.T) {\n' + checks + '}\n')
        env = dict(os.environ, GOWORK="off", GOTOOLCHAIN="local", GOFLAGS="",
                   GOPROXY=proxy.as_uri(), GOSUMDB="off", GOPRIVATE="", GONOPROXY="", GONOSUMDB="",
                   GOMODCACHE=str(self.root / "modcache"))
        subprocess.run(["go", "test", "-mod=mod", "./..."], cwd=consumer, env=env, check=True)

    def test_conflict_publishes_no_other_tags(self):
        tag = "adapter/gorm/v0.3.0"
        run("git", "push", "origin", f"{self.source}:refs/tags/{tag}", cwd=self.repo)
        with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
            publish(self.repo, "v0.3.0")
        tags = remote_tags(self.repo, "origin", [f"{module}/v0.3.0" for module in MODULES])
        self.assertEqual({key: value for key, value in tags.items() if value}, {tag: self.source})

    def test_dry_run_creates_no_remote_tags(self):
        publish(self.repo, "v0.3.0", dry_run=True)
        self.assertTrue(all(value is None for value in remote_tags(
            self.repo, "origin", [f"{module}/v0.3.0" for module in MODULES]).values()))

    def test_rejects_invalid_versions_and_unpublished_root(self):
        for version in ("v0.03.0", "v0.3.0-01", "v0.3.0;exit", "master"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                publish(self.repo, version)
        run("git", "tag", "v0.4.0", cwd=self.repo)
        with self.assertRaisesRegex(ValueError, "root tag must already exist"):
            publish(self.repo, "v0.4.0")


if __name__ == "__main__":
    unittest.main()
