# -*- coding: utf-8 -*-
"""Scoring metrics under Track B's half-credit verdict rule.

Gold labels are binary (malicious / benign). Engine verdicts are three-way.
Per the rules:
  malicious truth: malicious -> TP=1 ; suspicious -> TP=0.5, FN=0.5 ; benign -> FN=1
  benign truth   : benign    -> TN=1 ; suspicious -> TN=0.5, FP=0.5 ; malicious -> FP=1

F2 = 5*P*R / (4*P + R)   (recall-weighted, beta=2)
specificity = TN / (TN + FP)
"""


def _f(x):
    return round(float(x), 4)


def compute(pairs):
    """pairs: iterable of (gold_label, verdict). Returns a metrics dict."""
    # 2x3 confusion matrix counts.
    m = {
        "malicious": {"benign": 0, "suspicious": 0, "malicious": 0},
        "benign": {"benign": 0, "suspicious": 0, "malicious": 0},
    }
    for gold, verdict in pairs:
        g = "malicious" if gold == "malicious" else "benign"
        v = verdict if verdict in ("benign", "suspicious", "malicious") else "suspicious"
        m[g][v] += 1

    n_mal = sum(m["malicious"].values())
    n_ben = sum(m["benign"].values())

    # Half-credit accounting.
    tp = m["malicious"]["malicious"] + 0.5 * m["malicious"]["suspicious"]
    fn = m["malicious"]["benign"] + 0.5 * m["malicious"]["suspicious"]
    fp = m["benign"]["malicious"] + 0.5 * m["benign"]["suspicious"]
    tn = m["benign"]["benign"] + 0.5 * m["benign"]["suspicious"]

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    f2 = (5 * precision * recall / (4 * precision + recall)
          if (4 * precision + recall) else 0.0)
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)

    return {
        "n_total": n_mal + n_ben,
        "n_malicious": n_mal,
        "n_benign": n_ben,
        "matrix": m,
        "tp": _f(tp), "fp": _f(fp), "fn": _f(fn), "tn": _f(tn),
        "precision": _f(precision),
        "recall": _f(recall),
        "specificity": _f(specificity),
        "f1": _f(f1),
        "f2": _f(f2),
        # Gray-zone usage (suspicious distribution).
        "suspicious_on_malicious": m["malicious"]["suspicious"],
        "suspicious_on_benign": m["benign"]["suspicious"],
        "missed_malicious": m["malicious"]["benign"],     # full FN
        "false_alarms": m["benign"]["malicious"],          # full FP
    }


def format_report(metrics, title="Self-test metrics"):
    m = metrics
    cm = m["matrix"]
    lines = []
    lines.append("== %s ==" % title)
    lines.append("samples: %d (malicious=%d, benign=%d)"
                 % (m["n_total"], m["n_malicious"], m["n_benign"]))
    lines.append("")
    lines.append("confusion (rows=truth, cols=verdict):")
    lines.append("            benign  suspicious  malicious")
    lines.append("malicious   %6d  %10d  %9d"
                 % (cm["malicious"]["benign"], cm["malicious"]["suspicious"],
                    cm["malicious"]["malicious"]))
    lines.append("benign      %6d  %10d  %9d"
                 % (cm["benign"]["benign"], cm["benign"]["suspicious"],
                    cm["benign"]["malicious"]))
    lines.append("")
    lines.append("half-credit: TP=%.1f FP=%.1f FN=%.1f TN=%.1f"
                 % (m["tp"], m["fp"], m["fn"], m["tn"]))
    lines.append("precision=%.4f  recall=%.4f  specificity=%.4f"
                 % (m["precision"], m["recall"], m["specificity"]))
    lines.append("F1=%.4f  F2=%.4f" % (m["f1"], m["f2"]))
    lines.append("missed malicious (full FN)=%d  false alarms (full FP)=%d"
                 % (m["missed_malicious"], m["false_alarms"]))
    return "\n".join(lines)
