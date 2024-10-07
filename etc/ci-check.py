import subprocess
import unittest
from pathlib import Path

proj_root = Path(__file__).parents[1]


class Tests(unittest.TestCase):
    def test_kt_serde_compiled(self):
        cmd = "go run ./serde --in kt/serde.go && git diff --exit-code kt/serde.out.go"
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
