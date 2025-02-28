import sys

system = sys.argv[1]
if system == 'pav':
    start = 'TestBench'
elif system == 'akd':
    start = 'bench_'
else:
    print('invalid system')
    sys.exit(1)

inf = open('in', 'r')
outf = open('out', 'w')

for line in inf.readlines():
    if line.strip().startswith(start):
        outf.write(line)

inf.close()
outf.close()
