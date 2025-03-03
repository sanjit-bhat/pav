data_pav_gen = []
data_pav_ver = []
inf = open("data/25-02-28-verify-pav.txt", "r")
for line in inf.readlines():
    line = line.strip()
    if not line.startswith("TestBenchGetVerify"):
        continue
    parts = line.split()
    data_pav_gen.append(float(parts[2]))
    data_pav_ver.append(float(parts[6]))

data_akd_gen = []
data_akd_ver = []
inf = open("data/25-02-28-verify-akd.txt", "r")
for line in inf.readlines():
    line = line.strip()
    if not line.startswith("bench_get_verify"):
        continue
    parts = line.split()
    data_akd_gen.append(float(parts[2]))
    data_akd_ver.append(float(parts[6]))

coords_pav_gen = "\n    ".join(
    f"({ver + 1}, {lat})" for ver, lat in enumerate(data_pav_gen)
)
coords_akd_gen = "\n    ".join(
    f"({ver + 1}, {lat})" for ver, lat in enumerate(data_akd_gen)
)
plot_gen = f"""\\begin{{tikzpicture}}
\\begin{{axis}}[
    xlabel={{Num versions}},
    ylabel={{Get Generate Latency (\\si{{\\micro\\second}}/op)}},
    grid=major,
    legend pos=north west,
]
\\addplot[mark=x, blue] coordinates {{
    {coords_pav_gen}
}};
\\addplot[mark=*, red] coordinates {{
    {coords_akd_gen}
}};
\\legend{{\\vkt,AKD}}
\\end{{axis}}
\\end{{tikzpicture}}"""
print("Generate plot:")
print(plot_gen)

coords_pav_ver = "\n    ".join(
    f"({ver + 1}, {lat})" for ver, lat in enumerate(data_pav_ver)
)
coords_akd_ver = "\n    ".join(
    f"({ver + 1}, {lat})" for ver, lat in enumerate(data_akd_ver)
)
plot_ver = f"""\\begin{{tikzpicture}}
\\begin{{axis}}[
    xlabel={{Num versions}},
    ylabel={{Get Verify Latency (\\si{{\\micro\\second}}/op)}},
    grid=major,
    legend pos=north west,
]
\\addplot[mark=x, blue] coordinates {{
    {coords_pav_ver}
}};
\\addplot[mark=*, red] coordinates {{
    {coords_akd_ver}
}};
\\legend{{\\vkt,AKD}}
\\end{{axis}}
\\end{{tikzpicture}}"""
print("---\nVerify plot:")
print(plot_ver)

data_pav_size = []
inf = open("data/25-02-28-size-pav.txt", "r")
for line in inf.readlines():
    line = line.strip()
    if not line.startswith("TestBenchGetSize"):
        continue
    parts = line.split()
    data_pav_size.append(float(parts[2]))

data_akd_size = []
inf = open("data/25-02-28-size-akd.txt", "r")
for line in inf.readlines():
    line = line.strip()
    if not line.startswith("bench_get_size"):
        continue
    parts = line.split()
    data_akd_size.append(float(parts[2]))

coords_pav_size = "\n    ".join(
    f"({ver + 1}, {sz})" for ver, sz in enumerate(data_pav_size)
)
coords_akd_size = "\n    ".join(
    f"({ver + 1}, {sz})" for ver, sz in enumerate(data_akd_size)
)
plot_size = f"""\\begin{{tikzpicture}}
\\begin{{axis}}[
    xlabel={{Num versions}},
    ylabel={{Proof Size (B)}},
    grid=major,
    legend pos=north west,
]
\\addplot[mark=x, blue] coordinates {{
    {coords_pav_size}
}};
\\addplot[mark=*, red] coordinates {{
    {coords_akd_size}
}};
\\legend{{\\vkt,AKD}}
\\end{{axis}}
\\end{{tikzpicture}}"""
print("---\nSize plot:")
print(plot_size)
