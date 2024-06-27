import subprocess
import unittest
from pathlib import Path

proj_root = Path(__file__).parents[1]


class Tests(unittest.TestCase):
    def test_ktmerkle_compiled(self):
        command = "go run ./rpc --in ktmerkle/rpc.go && git diff --exit-code ktmerkle/rpc.out.go"
        result = subprocess.run(
            command, cwd=proj_root, shell=True, capture_output=True, text=True
        )
        self.assertEqual(
            result.returncode,
            0,
            f"Command failed with error message: {result.stderr} and output: {result.stdout}",
        )


if __name__ == "__main__":
    unittest.main()
