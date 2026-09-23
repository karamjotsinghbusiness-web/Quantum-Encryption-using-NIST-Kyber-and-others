"""
graph.py -- CipherShield standalone benchmark chart
=====================================================
Renders a PNG chart from a benchmark_results.json file exported by
main.py's "Benchmark & Compare" tab (File > Export benchmark results,
or the Export JSON button on that tab).

This replaces the old version of this script, which plotted four
hardcoded "security scores" (45/60/95/92) that were never based on any
measurement -- the comment even said "Example performance scores." A
single number can't honestly capture "how secure" an algorithm is, so
that chart is gone. This one charts what was actually measured: timing
and ciphertext/signature size, with quantum-safe algorithms (Kyber,
Dilithium) picked out in a different color from classical ones (RSA,
ECC, ECDSA).

Usage:
    python3 graph.py [path-to-benchmark_results.json]

If no path is given, it looks for benchmark_results.json in the
current directory.
"""

import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt

QUANTUM_SAFE_COLOR = "#00A896"
CLASSICAL_COLOR = "#E85D4A"


def load_results(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["results"]


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("benchmark_results.json")
    if not path.exists():
        print(f"Couldn't find {path}.")
        print("Run main.py, use the 'Benchmark & Compare' tab, then export the JSON "
              "(File > Export benchmark results, or the Export JSON button), and pass "
              "that file to this script.")
        sys.exit(1)

    results = load_results(path)
    if not results:
        print("That file has no results in it.")
        sys.exit(1)

    names = [r["name"] for r in results]
    total_ms = [r["keygen_ms"] + r["op_ms"] for r in results]
    sizes = [r["size_bytes"] for r in results]
    colors = [QUANTUM_SAFE_COLOR if r["quantum_safe"] else CLASSICAL_COLOR for r in results]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 6))
    fig.suptitle("CipherShield Benchmark -- Measured Results", fontsize=15, fontweight="bold")

    bars1 = ax1.bar(names, total_ms, color=colors)
    ax1.set_title("Avg. keygen + operation time")
    ax1.set_ylabel("Milliseconds")
    ax1.tick_params(axis="x", rotation=25)
    ax1.grid(axis="y", alpha=0.3)
    for bar in bars1:
        h = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width() / 2, h, f"{h:.2f}", ha="center", va="bottom", fontsize=9)

    bars2 = ax2.bar(names, sizes, color=colors)
    ax2.set_title("Ciphertext / signature size")
    ax2.set_ylabel("Bytes")
    ax2.tick_params(axis="x", rotation=25)
    ax2.grid(axis="y", alpha=0.3)
    for bar in bars2:
        h = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width() / 2, h, f"{int(h)}", ha="center", va="bottom", fontsize=9)

    handles = [
        plt.Rectangle((0, 0), 1, 1, color=QUANTUM_SAFE_COLOR),
        plt.Rectangle((0, 0), 1, 1, color=CLASSICAL_COLOR),
    ]
    fig.legend(handles, ["Post-quantum (NIST standard)", "Classical (quantum-vulnerable)"],
               loc="lower center", ncol=2, frameon=False)

    fig.tight_layout(rect=(0, 0.06, 1, 0.95))

    out_path = path.with_name(path.stem + "_chart.png")
    fig.savefig(out_path, dpi=150)
    print(f"Saved chart to {out_path}")
    plt.show()


if __name__ == "__main__":
    main()
