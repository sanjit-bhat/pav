import sys
import subprocess as sp

bench_class = sys.argv[1]
if bench_class == "serv":
    bench_tests = [
        "TestBenchPutOne",
        "TestBenchPutMulti",
        "TestBenchPutScale",
        "TestBenchPutBatch",
        "TestBenchPutSize",
        "TestBenchPutVerify",
        "TestBenchGetOne",
        "TestBenchGetScale",
        "TestBenchGetSizeOne",
        "TestBenchGetSizeMulti",
        "TestBenchGetVerify",
        "TestBenchSelfMonOne",
        "TestBenchSelfMonScale",
        "TestBenchSelfMonSize",
        "TestBenchSelfMonVerify",
        "TestBenchAuditOne",
        "TestBenchAuditSize",
    ]
elif bench_class == "serv_slow":
    bench_tests = [
        "TestBenchServScale",
    ]
elif bench_class == "cli":
    bench_tests = [
        "TestBenchPutCli",
        "TestBenchGetCli",
        "TestBenchSelfMonCli",
    ]
else:
    print("invalid bench_class:", bench_class)
    sys.exit(1)

for name in bench_tests:
    p = sp.run(["go", "test", "-v", "-count=1", "-timeout=0", "-run", name, "./kt"])
