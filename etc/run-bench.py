import sys
import subprocess as sp

bench_class = sys.argv[1]
if bench_class == "serv":
    bench_tests = [
        "TestBenchPutOne",
        "TestBenchPutScale",
        "TestBenchPutBatch",
        "TestBenchPutSize",
        "TestBenchPutVerify",
        "TestBenchGetOne",
        "TestBenchGetScale",
        "TestBenchGetSize",
        "TestBenchGetVerify",
        "TestBenchSelfMonOne",
        "TestBenchSelfMonScale",
        "TestBenchSelfMonSize",
        "TestBenchSelfMonVerify",
        "TestBenchAuditBatch",
        "TestBenchAuditSize",
    ]
elif bench_class == "serv_slow":
    bench_tests = [
        "TestBenchServScale",
    ]
elif bench_class == "cli":
    print("note: remember to uncomment signature gen")
    bench_tests = [
        "TestBenchPutCli",
        "TestBenchGetCli",
        "TestBenchSelfMonCli",
    ]
elif bench_class == "one":
    bench_tests = [
        "TestBenchPutOne",
        "TestBenchGetOne",
        "TestBenchSelfMonOne",
        "TestBenchAuditBatch",
    ]
elif bench_class == "size":
    bench_tests = [
        "TestBenchPutSize",
        "TestBenchGetSize",
        "TestBenchSelfMonSize",
        "TestBenchAuditSize",
    ]
elif bench_class == "verify":
    bench_tests = [
        "TestBenchPutVerify",
        "TestBenchGetVerify",
        "TestBenchSelfMonVerify",
    ]
elif bench_class == "scale":
    bench_tests = [
        "TestBenchPutScale",
        "TestBenchPutBatch",
        "TestBenchGetScale",
        "TestBenchSelfMonScale",
    ]
else:
    print("invalid bench_class:", bench_class)
    sys.exit(1)

for name in bench_tests:
    sp.run(["go", "test", "-v", "-count=1", "-timeout=0", "-run", name, "./kt"])
