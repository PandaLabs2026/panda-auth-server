import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-local.sh"


@unittest.skipUnless(os.name == "posix", "POSIX command shims are scoped to WSL/Linux runs")
class ServerVerifyCapacityTests(unittest.TestCase):
    def invoke(self, gate_exit="0", dotnet_exit="0", managed=False):
        temporary = tempfile.TemporaryDirectory(prefix="panda-auth-server-capacity-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        gate_log = root / "gate-args"
        dotnet_log = root / "dotnet-args"
        fake_meta_script = root / "home" / "dev" / "pandalabs" / "meta" / "scripts" / "capacity_preflight.py"
        fake_meta_script.parent.mkdir(parents=True)
        fake_meta_script.write_text(
            "import os, sys\n"
            "from pathlib import Path\n"
            "Path(os.environ['GATE_LOG']).write_text('\\n'.join(sys.argv[1:]))\n"
            "raise SystemExit(int(os.environ['GATE_EXIT']))\n",
            encoding="utf-8",
        )
        python = bin_dir / "python3"
        python.write_text("#!/bin/sh\nexec \"$REAL_PYTHON\" \"$@\"\n", encoding="utf-8")
        python.chmod(0o755)
        dotnet = bin_dir / "dotnet"
        dotnet.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\" >> \"$DOTNET_LOG\"\n"
            "exit \"$DOTNET_EXIT\"\n",
            encoding="utf-8",
        )
        dotnet.chmod(0o755)
        task_tmp = root / "task-tmp"
        task_tmp.mkdir()
        env = dict(os.environ)
        env.update(
            {
                "HOME": str(root / "home"),
                "PATH": f"{bin_dir}{os.pathsep}{env.get('PATH', '')}",
                "REAL_PYTHON": sys.executable,
                "TMPDIR": str(task_tmp),
                "TMP": str(task_tmp),
                "TEMP": str(task_tmp),
                "GATE_LOG": str(gate_log),
                "DOTNET_LOG": str(dotnet_log),
                "GATE_EXIT": gate_exit,
                "DOTNET_EXIT": dotnet_exit,
            }
        )
        if managed:
            env.update({"PANDALABS_MANAGED_EXECUTION": "1", "PANDALABS_BASELINE_ID": "test-baseline"})
        else:
            env.pop("PANDALABS_MANAGED_EXECUTION", None)
            env.pop("PANDALABS_BASELINE_ID", None)
        result = subprocess.run(["bash", str(SCRIPT)], cwd=ROOT, env=env, check=False)
        return result.returncode, gate_log.read_text(encoding="utf-8") if gate_log.exists() else "", (
            dotnet_log.read_text(encoding="utf-8").splitlines() if dotnet_log.exists() else []
        )

    def test_capacity_rejection_prevents_restore_build_and_tests(self):
        status, gate_args, dotnet_commands = self.invoke(gate_exit="17")
        self.assertEqual(status, 17)
        self.assertEqual(dotnet_commands, [])
        self.assertIn("--default", gate_args)

    def test_full_admission_covers_server_share_tests_and_restores_sequence(self):
        status, gate_args, dotnet_commands = self.invoke()
        self.assertEqual(status, 0)
        self.assertIn("--default", gate_args)
        self.assertNotIn("--docker", gate_args)
        for path in (ROOT, ROOT / "src", ROOT / "tests", ROOT.parent / "panda-auth-share"):
            self.assertIn(str(path), gate_args)
        self.assertIn(".nuget/packages", gate_args)
        self.assertEqual(
            dotnet_commands,
            [
                "restore PandaAuth.Server.slnx",
                "build PandaAuth.Server.slnx --no-restore",
                "test tests/PandaAuth.Tests/PandaAuth.Tests.csproj --no-restore",
            ],
        )

    def test_restore_failure_stops_build_and_test(self):
        status, _, dotnet_commands = self.invoke(dotnet_exit="23")
        self.assertEqual(status, 23)
        self.assertEqual(dotnet_commands, ["restore PandaAuth.Server.slnx"])

    def test_managed_admission_keeps_local_path_check_and_dotnet_sequence(self):
        status, gate_args, dotnet_commands = self.invoke(managed=True)
        self.assertEqual(status, 0)
        self.assertIn("--outer-capacity-admitted", gate_args)
        self.assertNotIn("--default", gate_args)
        self.assertIn(str(ROOT / "src"), gate_args)
        self.assertEqual(len(dotnet_commands), 3)


if __name__ == "__main__":
    unittest.main()
