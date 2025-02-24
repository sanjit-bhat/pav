import sys
import subprocess as sp

bench_class = sys.argv[1]
if bench_class == "serv":
    bench_tests = [
        "TestBenchPutOne",
        "TestBenchPutBatch",
        "TestBenchPutScale",
        "TestBenchPutSize",
        "TestBenchGetOne",
        "TestBenchGetScale",
        "TestBenchGetSizeOne",
        "TestBenchGetSizeMulti",
        "TestBenchSelfMonOne",
        "TestBenchSelfMonScale",
        "TestBenchSelfMonSize",
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
