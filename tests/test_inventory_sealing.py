from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from py_security_suite.inventory import (
    inventory_target_with_evidence,
    sealed_source_snapshot,
)
from py_security_suite.execution import resolve_executable, run_command


class InventorySealingTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git"), "Git is required")
    def test_sealed_snapshot_retains_verified_git_history(self) -> None:
        git = resolve_executable("git")
        assert git is not None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _git(git, ["init", "-q", str(root)], root)
            _git(
                git,
                ["-C", str(root), "config", "user.email", "test@example.invalid"],
                root,
            )
            _git(git, ["-C", str(root), "config", "user.name", "Test"], root)
            (root / "app.py").write_text("print('first')\n", encoding="utf-8")
            _git(git, ["-C", str(root), "add", "app.py"], root)
            _git(git, ["-C", str(root), "commit", "-q", "-m", "first"], root)
            (root / "app.py").write_text("print('second')\n", encoding="utf-8")
            _git(git, ["-C", str(root), "commit", "-qam", "second"], root)
            (root / "app.py").write_text("print('worktree')\n", encoding="utf-8")
            inventory, source = inventory_target_with_evidence(root)

            self.assertTrue(inventory.vcs_revision_verified)
            with sealed_source_snapshot(
                root, source, vcs_revision=inventory.vcs_revision
            ) as snapshot:
                self.assertTrue((snapshot / ".git").is_dir())
                count = _git(
                    git,
                    ["-C", str(snapshot), "rev-list", "--count", "HEAD"],
                    snapshot,
                )
                self.assertEqual(count.strip(), "2")
                changed = _git(
                    git,
                    ["-C", str(snapshot), "diff", "--name-only", "HEAD"],
                    snapshot,
                )
                self.assertEqual(changed.strip(), "app.py")

    def test_symbolic_links_are_explicitly_counted_as_unsealed_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real.py").write_text("value = 1\n", encoding="utf-8")
            try:
                (root / "alias.py").symlink_to(root / "real.py")
            except OSError:
                self.skipTest("symbolic-link creation is unavailable")
            inventory, _source = inventory_target_with_evidence(root)
            self.assertEqual(inventory.skipped_symlinks, 1)
            self.assertFalse(inventory.source_integrity_verified)

    def test_lfs_pointer_placeholder_is_rejected_from_sealed_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "model.bin").write_text(
                "version https://git-lfs.github.com/spec/v1\n"
                "oid sha256:" + "a" * 64 + "\nsize 12345\n",
                encoding="utf-8",
            )
            inventory, source = inventory_target_with_evidence(root)
            with self.assertRaisesRegex(ValueError, "LFS object is not materialized"):
                with sealed_source_snapshot(
                    root, source, vcs_revision=inventory.vcs_revision
                ):
                    pass

    @unittest.skipUnless(shutil.which("git"), "Git is required")
    def test_submodule_history_is_recursively_sealed(self) -> None:
        git = resolve_executable("git")
        assert git is not None
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            module = parent / "module-source"
            root = parent / "root"
            _git(git, ["init", "-q", str(module)], parent)
            _configure_identity(git, module)
            (module / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
            _git(git, ["-C", str(module), "add", "module.py"], module)
            _git(git, ["-C", str(module), "commit", "-q", "-m", "module"], module)
            _git(git, ["init", "-q", str(root)], parent)
            _configure_identity(git, root)
            _git(
                git,
                [
                    "-c",
                    "protocol.file.allow=always",
                    "-C",
                    str(root),
                    "submodule",
                    "add",
                    "-q",
                    str(module),
                    "vendor/module",
                ],
                root,
            )
            _git(git, ["-C", str(root), "commit", "-qam", "submodule"], root)
            inventory, source = inventory_target_with_evidence(root)
            with sealed_source_snapshot(
                root, source, vcs_revision=inventory.vcs_revision
            ) as snapshot:
                nested = snapshot / "vendor" / "module"
                self.assertTrue((nested / ".git").is_dir())
                self.assertEqual(
                    _git(
                        git, ["-C", str(nested), "rev-list", "--count", "HEAD"], nested
                    ).strip(),
                    "1",
                )

    @unittest.skipUnless(shutil.which("git"), "Git is required")
    def test_sparse_checkout_repository_is_rejected(self) -> None:
        git = resolve_executable("git")
        assert git is not None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _git(git, ["init", "-q", str(root)], root)
            _configure_identity(git, root)
            (root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
            _git(git, ["-C", str(root), "add", "app.py"], root)
            _git(git, ["-C", str(root), "commit", "-q", "-m", "initial"], root)
            _git(git, ["-C", str(root), "config", "core.sparseCheckout", "true"], root)
            inventory, source = inventory_target_with_evidence(root)

            with self.assertRaisesRegex(ValueError, "sparse-checkout"):
                with sealed_source_snapshot(
                    root, source, vcs_revision=inventory.vcs_revision
                ):
                    pass

    @unittest.skipUnless(shutil.which("git"), "Git is required")
    def test_production_git_provenance_rejects_sha1_history(self) -> None:
        git = resolve_executable("git")
        assert git is not None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _git(git, ["init", "-q", "--object-format=sha1", str(root)], root)
            _configure_identity(git, root)
            (root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
            _git(git, ["-C", str(root), "add", "app.py"], root)
            _git(git, ["-C", str(root), "commit", "-q", "-m", "initial"], root)
            inventory, source = inventory_target_with_evidence(root)

            with self.assertRaisesRegex(ValueError, "SHA-256 objects"):
                with sealed_source_snapshot(
                    root,
                    source,
                    vcs_revision=inventory.vcs_revision,
                    require_signed_git_provenance=True,
                ):
                    pass

    @unittest.skipUnless(shutil.which("git"), "Git is required")
    def test_replace_refs_are_rejected(self) -> None:
        git = resolve_executable("git")
        assert git is not None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _git(git, ["init", "-q", str(root)], root)
            _configure_identity(git, root)
            (root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
            _git(git, ["-C", str(root), "add", "app.py"], root)
            _git(git, ["-C", str(root), "commit", "-q", "-m", "first"], root)
            first = _git(git, ["-C", str(root), "rev-parse", "HEAD"], root).strip()
            (root / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
            _git(git, ["-C", str(root), "commit", "-qam", "second"], root)
            second = _git(git, ["-C", str(root), "rev-parse", "HEAD"], root).strip()
            _git(git, ["-C", str(root), "replace", second, first], root)
            inventory, source = inventory_target_with_evidence(root)

            with self.assertRaisesRegex(ValueError, "replace refs"):
                with sealed_source_snapshot(
                    root, source, vcs_revision=inventory.vcs_revision
                ):
                    pass


def _git(executable: str, arguments: list[str], cwd: Path) -> str:
    result = run_command(
        [executable, *arguments],
        cwd=cwd,
        timeout_seconds=30,
        max_output_bytes=64 * 1024,
    )
    if result.exit_code != 0:
        raise AssertionError(result.stderr)
    return result.stdout


def _configure_identity(executable: str, root: Path) -> None:
    _git(
        executable,
        ["-C", str(root), "config", "user.email", "test@example.invalid"],
        root,
    )
    _git(executable, ["-C", str(root), "config", "user.name", "Test"], root)
