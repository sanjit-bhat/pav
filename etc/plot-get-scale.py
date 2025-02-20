data = []
inf = open("data/25-02-18-get-scale.txt", "r")
for line in inf.readlines():
    line = line.strip()
    if not line:
        continue
    parts = line.split()
    if len(parts) < 11:
        continue
    try:
        n_cli = float(parts[2])
        tput = float(parts[4])
        p99 = float(parts[10])
        data.append((n_cli, tput, p99))
    except (ValueError, IndexError):
        continue

coords = "\n    ".join(f"({p99:.3f}, {tput:.0f})" for _, tput, p99 in data)
plot = f"""\\begin{{tikzpicture}}
\\begin{{axis}}[
    xlabel={{p99 Latency (\\si{{\\micro\\second}})}},
    ylabel={{Throughput (op/s)}},
    grid=major,
    legend pos=north west,
]
\\addplot[mark=*, blue] coordinates {{
    {coords}
}};
\\legend{{Throughput}}
\\end{{axis}}
\\end{{tikzpicture}}"""
print(plot)
