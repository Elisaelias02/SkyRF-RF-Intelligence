"""SkyRF CLI — interfaz de terminal del framework.

Uso:
    python -m skyrf.cli train                 # entrena con tráfico sintético
    python -m skyrf.cli scan --demo           # demo de clasificación en vivo
    python -m skyrf.cli scan --synthetic ble  # clasifica stream sintético
"""

from __future__ import annotations

import argparse
import sys

from rich import box
from rich.console import Console
from rich.table import Table

from skyrf import SIGNATURE, __version__

CYAN = "#00e5ff"
console = Console()

BANNER = r"""
[#00e5ff]      /\_____/\
      /  o   o  \        S K Y R F  v{ver}
     ( ==  ^  == )       RF intelligence framework
      )         (        {sig}
     (           )
    ( (  )   (  ) )
   (__(__)___(__)__)[/#00e5ff]
"""


def print_banner() -> None:
    console.print(BANNER.format(ver=__version__, sig=SIGNATURE))


def cmd_train(args: argparse.Namespace) -> int:
    from skyrf.classify.train import train

    console.print(f"[bold {CYAN}][*][/] Generando dataset sintético "
                  f"({args.samples} streams/protocolo)…")
    model, report, cm, labels = train(samples=args.samples,
                                      model_path=args.model)

    console.print(f"\n[bold {CYAN}][+] Modelo entrenado[/] → {args.model}\n")
    console.print(report)

    t = Table(title="Matriz de confusión", box=box.ROUNDED,
              header_style=f"bold {CYAN}")
    t.add_column("real \\ pred")
    for lab in labels:
        t.add_column(lab, justify="right")
    for lab, row in zip(labels, cm):
        t.add_row(lab, *[str(v) for v in row])
    console.print(t)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    import time

    from skyrf.classify.predict import classify_stream, load_model
    from skyrf.capture.synthetic_source import generate

    try:
        model, features = load_model(args.model)
    except FileNotFoundError:
        console.print("[bold red][!] No hay modelo. Corre primero: "
                      "python -m skyrf.cli train[/]")
        return 1

    proto = args.synthetic
    console.print(f"[bold {CYAN}][*][/] Capturando stream sintético "
                  f"'{proto}' ({args.duration}s)…\n")
    time.sleep(0.4)  # dramaturgia de terminal

    stream = generate(proto, duration_s=args.duration, seed=None)
    results = classify_stream(model, stream, window_s=args.window)

    t = Table(box=box.ROUNDED, header_style=f"bold {CYAN}",
              title=f"Clasificación por ventana ({args.window}s)")
    t.add_column("ventana", justify="right")
    t.add_column("paquetes", justify="right")
    t.add_column("protocolo", style=f"bold {CYAN}")
    t.add_column("confianza", justify="right")

    correct = 0
    for i, r in enumerate(results):
        ok = r["label"] == proto
        correct += ok
        conf = f"{r['confidence']:.1%}"
        style = "" if ok else "bold red"
        t.add_row(f"{r['t_start']:>6.1f}s", str(r["n_packets"]),
                  r["label"], conf, style=style)
    console.print(t)

    if results:
        acc = correct / len(results)
        color = CYAN if acc >= 0.8 else "yellow"
        console.print(f"\n[bold {color}][=] Accuracy sobre stream "
                      f"'{proto}': {acc:.1%}[/] ({correct}/{len(results)} "
                      "ventanas)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="skyrf", description="SkyRF — RF intelligence framework")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_train = sub.add_parser("train", help="entrena el clasificador (sintético)")
    p_train.add_argument("--samples", type=int, default=40)
    p_train.add_argument("--model", default="skyrf_protocol_model.joblib")
    p_train.set_defaults(func=cmd_train)

    p_scan = sub.add_parser("scan", help="clasifica un stream")
    p_scan.add_argument("--synthetic", default="zigbee",
                        choices=["zigbee", "ble", "thread", "lora"])
    p_scan.add_argument("--duration", type=float, default=60.0)
    p_scan.add_argument("--window", type=float, default=5.0)
    p_scan.add_argument("--model", default="skyrf_protocol_model.joblib")
    p_scan.set_defaults(func=cmd_scan)

    p_bridge = sub.add_parser("bridge", help="puente CatSniffer → dashboard (WebSocket)")
    p_bridge.set_defaults(func=cmd_bridge)

    p_selftest = sub.add_parser("selftest", help="verifica los playbooks (round-trip crypto)")
    p_selftest.set_defaults(func=cmd_selftest)

    args = parser.parse_args(argv)
    print_banner()
    return args.func(args)


def cmd_bridge(args: argparse.Namespace) -> int:
    from skyrf.bridge import main as bridge_main
    return bridge_main()


def cmd_selftest(args: argparse.Namespace) -> int:
    from skyrf.playbooks.selftest import main as selftest_main
    return selftest_main()


if __name__ == "__main__":
    sys.exit(main())
