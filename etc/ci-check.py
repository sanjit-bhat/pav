import subprocess
import unittest
from pathlib import Path

proj_root = Path(__file__).parents[1]


class Tests(unittest.TestCase):
    def test_ktserde_compiled(self):
        cmd = "go run ./serde --in ktserde/serde.go && git diff --exit-code ktserde/serde.out.go"
        res = subprocess.run(
            cmd, cwd=proj_root, shell=True, capture_output=True, text=True
        )
        self.assertEqual(
            res.returncode,
            0,
            f"Command failed with error message: {res.stderr} and output: {res.stdout}",
        )

    def test_merkle_serde_compiled(self):
        cmd = "go run ./serde --in merkle/serde.go && git diff --exit-code merkle/serde.out.go"
        res = subprocess.run(
            cmd, cwd=proj_root, shell=True, capture_output=True, text=True
        )
        self.assertEqual(
            res.returncode,
            0,
            f"Command failed with error message: {res.stderr} and output: {res.stdout}",
        )

    # TODO: compiler doesn't yet support objects from diff pkgs.
    """
    def test_server_serde_compiled(self):
        cmd = "go run ./serde --in server/serde.go && git diff --exit-code server/serde.out.go"
        res = subprocess.run(
            cmd, cwd=proj_root, shell=True, capture_output=True, text=True
        )
        self.assertEqual(
            res.returncode,
            0,
            f"Command failed with error message: {res.stderr} and output: {res.stdout}",
        )

    def test_auditor_serde_compiled(self):
        cmd = "go run ./serde --in auditor/serde.go && git diff --exit-code auditor/serde.out.go"
        res = subprocess.run(
            cmd, cwd=proj_root, shell=True, capture_output=True, text=True
        )
        self.assertEqual(
            res.returncode,
            0,
            f"Command failed with error message: {res.stderr} and output: {res.stdout}",
        )
    """


if __name__ == "__main__":
    unittest.main()
