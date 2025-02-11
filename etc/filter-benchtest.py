inf = open('in', 'r')
outf = open('out', 'w')

for line in inf.readlines():
    if line.strip().startswith('TestBench'):
        outf.write(line)

inf.close()
outf.close()
