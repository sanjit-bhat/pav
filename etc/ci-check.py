import subprocess
import unittest
from pathlib import Path

proj_root = Path(__file__).parents[1]


# TODO: once compiler supports objects from diff pkgs, test:
# {server,auditor}/serde.go.


class Tests(unittest.TestCase):
    def test_ktcore_serde(self):
        cmd = "go run ./serde --in ktcore/serde.go && git diff --exit-code ktcore/serde.out.go"
        res = subprocess.run(
            cmd, cwd=proj_root, shell=True, capture_output=True, text=True
        )
        self.assertEqual(
            res.returncode,
            0,
            f"Command failed with error message: {res.stderr} and output: {res.stdout}",
        )

    def test_merkle_serde(self):
        cmd = "go run ./serde --in merkle/serde.go && git diff --exit-code merkle/serde.out.go"
        res = subprocess.run(
            cmd, cwd=proj_root, shell=True, capture_output=True, text=True
        )
        self.assertEqual(
            res.returncode,
            0,
            f"Command failed with error message: {res.stderr} and output: {res.stdout}",
        )


if __name__ == "__main__":
    unittest.main()
