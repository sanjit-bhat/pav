import subprocess
import unittest
from pathlib import Path

proj_root = Path(__file__).parents[1]


class Tests(unittest.TestCase):
    def test_ktmerkle_compiled(self):
        cmd = "go run ./rpc --in ktmerkle/rpc.go && git diff --exit-code ktmerkle/rpc.out.go"
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
