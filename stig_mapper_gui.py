"""
STIG Compliance Mapper
Group 6 - CSE 484 Network Security

Traces every rule in a DISA STIG benchmark (XCCDF) to its Control Correlation
Identifiers (CCIs) and on to NIST SP 800-53 security controls, then presents the
result in a desktop GUI with filtering, rule details, and CSV / HTML exports.

Standard library only. Run with:  python stig_mapper_gui.py
"""

import csv
import datetime
import html
import os
import re
import webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import main as core  # parsing and STIG -> CCI -> NIST linking live in main.py

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
APP_TITLE = "STIG Compliance Mapper"
APP_SUBTITLE = "STIG Rule  →  CCI  →  NIST SP 800-53 Traceability"
TEAM = "Group 6  ·  CSE 484 Network Security"
VERSION = "1.0"

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CCI = os.path.join(HERE, "CCI_List.xml")
DEFAULT_STIG = os.path.join(HERE, "U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml")

# Label shown in the GUI -> exact "title" attribute used in the CCI list
REVISIONS = {
    "NIST SP 800-53 Revision 5": "NIST SP 800-53 Revision 5",
    "NIST SP 800-53 Revision 4": "NIST SP 800-53 Revision 4",
}

FAMILIES = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "PII Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}
NEEDS_REVIEW = "NEEDS REVIEW"
REVIEW_NAME = "Unmapped — requires analyst review"

SEVERITY_CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# Palette
NAVY = "#0b2545"
NAVY_2 = "#13315c"
GOLD = "#c9a227"
BG = "#eef1f5"
CARD = "#ffffff"
BORDER = "#d3d9e2"
TEXT = "#1b2430"
MUTED = "#5b6676"
SELECT = "#1f4e89"
CAT1 = "#b3261e"
CAT2 = "#b26a00"
CAT3 = "#2e6b9e"
OK = "#2e7d32"
FONT = "Segoe UI"
MONO = "Consolas"


# --------------------------------------------------------------------------- #
# Data layer
# --------------------------------------------------------------------------- #
def family_name(code):
    if code == NEEDS_REVIEW:
        return REVIEW_NAME
    return FAMILIES.get(code, "Unknown family")


def load_documents(cci_path, stig_path, revision):
    """Run main.py's loaders and add the few display fields the GUI needs."""
    core.REVISION = f'title="{revision}"'
    lookup = core.load_cci_lookup(cci_path)
    rules = core.load_stig(stig_path)

    # main.py reads the raw XML text, so XML escapes like &quot; are still in it
    for r in rules:
        for key in ("title", "check", "fix"):
            r[key] = html.unescape(r[key]).strip()
        r["discussion"] = html.unescape(html.unescape(r["discussion"])).strip()  # escaped twice in XCCDF
        r["severity"] = r["severity"].lower()

    rows = core.connect(rules, lookup)
    index = {r["vuln_id"]: i for i, r in enumerate(rules)}
    for row in rows:
        row["rule"] = index[row["vuln_id"]]
        row["cat"] = SEVERITY_CAT.get(row["severity"], row["severity"])
        row["family"] = row["family"] or NEEDS_REVIEW
        if row["note"] == "NO REV 5 CODE":
            row["note"] = "NOT MAPPED"  # main.py's label assumes Rev 5; the GUI also offers Rev 4
        row["definition"] = html.unescape(lookup.get(row["cci"], {}).get("definition", ""))

    cci_text = open(cci_path, encoding="utf-8-sig").read()
    stig_text = open(stig_path, encoding="utf-8-sig").read()
    meta = {
        "title": html.unescape(core.between(stig_text, "<title>", "</title>")),
        "version": core.between(stig_text, "<version>", "</version>"),
        "release": core.between(stig_text, '<plain-text id="release-info">', "</plain-text>"),
    }
    cci_version = core.between(cci_text, "<version>", "</version>")
    return meta, rules, rows, cci_version


def compute_stats(rules, rows):
    sev = [r["severity"] for r in rules]
    return {
        "rules": len(rules),
        "high": sev.count("high"),
        "medium": sev.count("medium"),
        "low": sev.count("low"),
        "ccis": len({r["cci"] for r in rows if r["cci"]}),
        "controls": len({r["nist"] for r in rows if r["nist"]}),
        "review": len({r["vuln_id"] for r in rows if r["family"] == NEEDS_REVIEW}),
        "rows": len(rows),
    }


def family_summary(rows):
    fams = {}
    for r in rows:
        d = fams.setdefault(r["family"], {"rows": 0, "rules": {}})
        d["rows"] += 1
        d["rules"][r["vuln_id"]] = r["severity"]
    out = []
    for code, d in fams.items():
        sev = list(d["rules"].values())
        out.append({
            "family": code, "name": family_name(code), "rows": d["rows"],
            "rules": len(sev), "high": sev.count("high"),
            "medium": sev.count("medium"), "low": sev.count("low"),
        })
    out.sort(key=lambda f: (f["family"] == NEEDS_REVIEW, f["family"]))
    return out


# --------------------------------------------------------------------------- #
# Exports
# --------------------------------------------------------------------------- #
CSV_COLUMNS = [
    ("Vuln ID", "vuln_id"), ("STIG ID", "stig_id"), ("Severity", "severity"),
    ("Category", "cat"), ("CCI", "cci"), ("NIST Control", "nist"),
    ("Control Family", "family"), ("Note", "note"), ("Rule Title", "title"),
    ("CCI Definition", "definition"),
]


def save_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow([c for c, _ in CSV_COLUMNS])
        for r in rows:
            w.writerow([r[k] for _, k in CSV_COLUMNS])


def build_report_html(meta, cci_version, revision, stats, families, rows):
    e = html.escape
    now = datetime.datetime.now().strftime("%d %b %Y %H:%M")
    sev_cls = {"high": "c1", "medium": "c2", "low": "c3"}

    fam_rows = "".join(
        f"<tr><td class='code'>{e(f['family'])}</td><td>{e(f['name'])}</td>"
        f"<td class='n'>{f['rules']}</td><td class='n'>{f['high']}</td>"
        f"<td class='n'>{f['medium']}</td><td class='n'>{f['low']}</td>"
        f"<td class='n'>{f['rows']}</td></tr>" for f in families)

    def matrix(rs):
        return "".join(
            f"<tr><td class='code'>{e(r['vuln_id'])}</td><td class='code'>{e(r['stig_id'])}</td>"
            f"<td><span class='badge {sev_cls.get(r['severity'], '')}'>{e(r['cat'])}</span></td>"
            f"<td class='code'>{e(r['cci']) or '&mdash;'}</td>"
            f"<td class='code'>{e(r['nist']) if r['nist'] else '<span class=flag>' + e(r['note']) + '</span>'}</td>"
            f"<td>{e(r['title'])}</td></tr>" for r in rs)

    review = [r for r in rows if r["family"] == NEEDS_REVIEW]
    review_html = (
        f"<table><thead><tr><th>Vuln ID</th><th>STIG ID</th><th>Severity</th><th>CCI</th>"
        f"<th>Issue</th><th>Rule Title</th></tr></thead><tbody>{matrix(review)}</tbody></table>"
        if review else "<p class='okmsg'>Every rule maps to at least one control in the selected revision.</p>")

    cards = [("STIG Rules", stats["rules"], NAVY), ("CAT I", stats["high"], CAT1),
             ("CAT II", stats["medium"], CAT2), ("CAT III", stats["low"], CAT3),
             ("Unique CCIs", stats["ccis"], NAVY), ("NIST Controls", stats["controls"], NAVY),
             ("Rules Needing Review", stats["review"], CAT2 if stats["review"] else OK)]
    cards_html = "".join(
        f"<div class='card' style='border-left-color:{c}'><div class='v' style='color:{c}'>{v:,}</div>"
        f"<div class='k'>{e(k)}</div></div>" for k, v, c in cards)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>STIG Traceability Report</title>
<style>
 :root {{ --navy:{NAVY}; --gold:{GOLD}; --bg:{BG}; --border:{BORDER}; --text:{TEXT}; --muted:{MUTED}; }}
 * {{ box-sizing:border-box; }}
 body {{ margin:0; font-family:"Segoe UI",system-ui,sans-serif; color:var(--text); background:var(--bg); }}
 header {{ background:var(--navy); color:#fff; padding:28px 40px 22px; border-bottom:4px solid var(--gold); }}
 header h1 {{ margin:0; font-size:26px; letter-spacing:.3px; }}
 header p {{ margin:6px 0 0; opacity:.85; }}
 main {{ max-width:1200px; margin:0 auto; padding:28px 40px 60px; }}
 h2 {{ color:var(--navy); font-size:17px; text-transform:uppercase; letter-spacing:1px;
       border-bottom:2px solid var(--border); padding-bottom:6px; margin-top:36px; }}
 .meta {{ display:grid; grid-template-columns:200px 1fr; gap:6px 16px; background:#fff;
          border:1px solid var(--border); padding:16px 20px; }}
 .meta dt {{ color:var(--muted); font-weight:600; }} .meta dd {{ margin:0; }}
 .cards {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); gap:12px; }}
 .card {{ background:#fff; border:1px solid var(--border); border-left:5px solid; padding:12px 14px; }}
 .card .v {{ font-size:26px; font-weight:700; }}
 .card .k {{ font-size:11px; font-weight:700; color:var(--muted); text-transform:uppercase; letter-spacing:.6px; }}
 table {{ width:100%; border-collapse:collapse; background:#fff; font-size:13px; border:1px solid var(--border); }}
 th {{ background:var(--navy); color:#fff; text-align:left; padding:8px 10px; font-size:12px; position:sticky; top:0; }}
 td {{ padding:6px 10px; border-top:1px solid var(--border); vertical-align:top; }}
 tbody tr:nth-child(even) {{ background:#f6f8fb; }}
 td.n {{ text-align:right; font-variant-numeric:tabular-nums; }}
 td.code {{ font-family:Consolas,monospace; white-space:nowrap; }}
 .badge {{ display:inline-block; padding:1px 8px; border-radius:3px; color:#fff; font-size:11px; font-weight:700; white-space:nowrap; }}
 .c1 {{ background:{CAT1}; }} .c2 {{ background:{CAT2}; }} .c3 {{ background:{CAT3}; }}
 .flag {{ color:{CAT2}; font-weight:700; font-family:"Segoe UI",sans-serif; font-size:12px; }}
 .okmsg {{ color:{OK}; font-weight:600; }}
 footer {{ color:var(--muted); font-size:12px; margin-top:40px; border-top:1px solid var(--border); padding-top:12px; }}
 @media print {{ body {{ background:#fff; }} th {{ position:static; }} header {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }} }}
 @media (max-width:700px) {{ header, main {{ padding-left:16px; padding-right:16px; }} .meta {{ grid-template-columns:1fr; }} table {{ display:block; overflow-x:auto; }} }}
</style></head><body>
<header><h1>STIG Compliance Traceability Report</h1>
<p>{e(APP_SUBTITLE)} &nbsp;&middot;&nbsp; {e(TEAM)}</p></header>
<main>
<h2>Document Information</h2>
<dl class="meta">
 <dt>Benchmark</dt><dd>{e(meta.get('title', ''))}</dd>
 <dt>Version / Release</dt><dd>Version {e(meta.get('version', ''))} &middot; {e(meta.get('release', ''))}</dd>
 <dt>CCI List Version</dt><dd>{e(cci_version)}</dd>
 <dt>Control Baseline</dt><dd>{e(revision)}</dd>
 <dt>Report Generated</dt><dd>{e(now)}</dd>
</dl>
<h2>Executive Summary</h2>
<div class="cards">{cards_html}</div>
<h2>Coverage by Control Family</h2>
<table><thead><tr><th>Family</th><th>Name</th><th>Rules</th><th>CAT I</th><th>CAT II</th><th>CAT III</th><th>Mappings</th></tr></thead>
<tbody>{fam_rows}</tbody></table>
<h2>Items Requiring Review</h2>
{review_html}
<h2>Full Traceability Matrix ({len(rows):,} mappings)</h2>
<table><thead><tr><th>Vuln ID</th><th>STIG ID</th><th>Severity</th><th>CCI</th><th>NIST Control</th><th>Rule Title</th></tr></thead>
<tbody>{matrix(rows)}</tbody></table>
<footer>Generated by {e(APP_TITLE)} v{VERSION} &middot; {e(TEAM)}. Source data: DISA STIG XCCDF benchmark and DISA CCI list.</footer>
</main></body></html>"""


# --------------------------------------------------------------------------- #
# GUI widgets
# --------------------------------------------------------------------------- #
class StatCard(tk.Frame):
    def __init__(self, parent, caption, color):
        super().__init__(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        self.color = color
        self.stripe = tk.Frame(self, bg=color, width=5)
        self.stripe.pack(side="left", fill="y")
        inner = tk.Frame(self, bg=CARD)
        inner.pack(side="left", fill="both", expand=True, padx=12, pady=8)
        self.value = tk.Label(inner, text="—", font=(FONT, 20, "bold"), fg=color, bg=CARD, anchor="w")
        self.value.pack(fill="x")
        tk.Label(inner, text=caption.upper(), font=(FONT, 8, "bold"), fg=MUTED, bg=CARD,
                 anchor="w").pack(fill="x")

    def set(self, value, color=None):
        self.value.config(text=f"{value:,}")
        if color:
            self.value.config(fg=color)
            self.stripe.config(bg=color)


class App(tk.Tk):
    MATRIX_COLS = [
        ("vuln_id", "Vuln ID", 90, False), ("stig_id", "STIG ID", 140, False),
        ("cat", "Severity", 75, False), ("cci", "CCI", 100, False),
        ("nist", "NIST Control", 150, False), ("family", "Family", 70, False),
        ("title", "Rule Title", 420, True),
    ]
    FAMILY_COLS = [
        ("family", "Family", 75), ("name", "Name", 260), ("rules", "Rules", 65),
        ("high", "CAT I", 65), ("medium", "CAT II", 70), ("low", "CAT III", 75),
        ("rows", "Mappings", 90),
    ]

    def __init__(self):
        super().__init__()
        self.title(f"{APP_TITLE} — {TEAM}")
        self.geometry("1360x880")
        self.minsize(1100, 700)
        self.configure(bg=BG)

        self.meta, self.rules, self.rows, self.view = {}, [], [], []
        self.cci_version, self.stats, self.families = "", {}, []
        self.sort_col, self.sort_rev = None, False

        self.cci_path = tk.StringVar(value=DEFAULT_CCI)
        self.stig_path = tk.StringVar(value=DEFAULT_STIG)
        self.revision = tk.StringVar(value=next(iter(REVISIONS)))
        self.search = tk.StringVar()
        self.sev_filter = tk.StringVar(value="All severities")
        self.fam_filter = tk.StringVar(value="All families")
        self.review_only = tk.BooleanVar()
        self.status = tk.StringVar(value="Select source documents and click Load & Map.")

        self._style()
        self._build_header()
        self._build_statusbar()  # packed before the body so it is never squeezed out
        self._build_body()
        try:
            self.state("zoomed")  # open maximized on Windows
        except tk.TclError:
            pass

        for v in (self.search, self.sev_filter, self.fam_filter, self.review_only):
            v.trace_add("write", lambda *_: self.apply_filters())

        if os.path.exists(DEFAULT_CCI) and os.path.exists(DEFAULT_STIG):
            self.after(150, self.load)
        else:
            self.after(150, self.select_missing_files)

    def select_missing_files(self):
        """Ask for any source file that isn't next to the script, then load."""
        for kind, var in (("cci", self.cci_path), ("stig", self.stig_path)):
            if not os.path.isfile(var.get()) and not self.browse(kind):
                self.status.set("Select both source documents, then click Load & Map.")
                return
        self.load()

    # ---- styling ---------------------------------------------------------- #
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", font=(FONT, 10), background=BG, foreground=TEXT)
        s.configure("TFrame", background=BG)
        s.configure("Card.TFrame", background=CARD)
        s.configure("TLabel", background=BG, foreground=TEXT)
        s.configure("Card.TLabel", background=CARD)
        s.configure("Muted.TLabel", background=CARD, foreground=MUTED, font=(FONT, 9))
        s.configure("Field.TLabel", background=CARD, foreground=NAVY, font=(FONT, 9, "bold"))
        s.configure("TCheckbutton", background=CARD)
        s.map("TCheckbutton", background=[("active", CARD)])
        s.configure("TEntry", fieldbackground="white", bordercolor=BORDER, padding=4)
        s.configure("TCombobox", fieldbackground="white", bordercolor=BORDER, padding=3)
        s.configure("TButton", padding=(12, 5), background="#e3e8ef", bordercolor=BORDER)
        s.map("TButton", background=[("active", "#d5dce6")])
        s.configure("Accent.TButton", background=NAVY, foreground="white",
                    font=(FONT, 10, "bold"), padding=(18, 7), bordercolor=NAVY)
        s.map("Accent.TButton", background=[("active", NAVY_2), ("disabled", "#9aa5b1")])
        s.configure("Treeview", rowheight=26, background="white", fieldbackground="white",
                    bordercolor=BORDER, font=(FONT, 9))
        s.configure("Treeview.Heading", background=NAVY, foreground="white",
                    font=(FONT, 9, "bold"), relief="flat", padding=(6, 5))
        s.map("Treeview.Heading", background=[("active", NAVY_2)])
        s.map("Treeview", background=[("selected", SELECT)], foreground=[("selected", "white")])
        s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 4, 0, 0))
        s.configure("TNotebook.Tab", padding=(18, 7), font=(FONT, 10, "bold"),
                    background="#dde3eb", foreground=MUTED, bordercolor=BORDER)
        s.map("TNotebook.Tab", background=[("selected", CARD)], foreground=[("selected", NAVY)])

    # ---- layout ----------------------------------------------------------- #
    def _build_header(self):
        bar = tk.Frame(self, bg=NAVY)
        bar.pack(fill="x")
        left = tk.Frame(bar, bg=NAVY)
        left.pack(side="left", padx=24, pady=(14, 12))
        tk.Label(left, text=APP_TITLE.upper(), font=(FONT, 18, "bold"), fg="white",
                 bg=NAVY).pack(anchor="w")
        tk.Label(left, text=APP_SUBTITLE, font=(FONT, 10), fg="#c5d1e0", bg=NAVY).pack(anchor="w")
        right = tk.Frame(bar, bg=NAVY)
        right.pack(side="right", padx=24)
        tk.Label(right, text=TEAM, font=(FONT, 10, "bold"), fg=GOLD, bg=NAVY).pack(anchor="e")
        self.doc_label = tk.Label(right, text="No benchmark loaded", font=(FONT, 9),
                                  fg="#c5d1e0", bg=NAVY)
        self.doc_label.pack(anchor="e")
        tk.Frame(self, bg=GOLD, height=4).pack(fill="x")

    def _card(self, parent, title):
        outer = tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        tk.Label(outer, text=title.upper(), font=(FONT, 9, "bold"), fg=NAVY, bg=CARD,
                 anchor="w").pack(fill="x", padx=14, pady=(10, 4))
        body = ttk.Frame(outer, style="Card.TFrame")
        body.pack(fill="both", expand=True, padx=14, pady=(0, 12))
        return outer, body

    def _build_body(self):
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=18, pady=(14, 6))

        # Source documents
        src, inner = self._card(body, "Source Documents")
        src.pack(fill="x")
        inner.columnconfigure(1, weight=1)
        for row, (label, var, kind) in enumerate([
                ("CCI List (XML)", self.cci_path, "cci"),
                ("STIG Benchmark (XCCDF)", self.stig_path, "stig")]):
            ttk.Label(inner, text=label, style="Field.TLabel", width=24).grid(
                row=row, column=0, sticky="w", pady=3)
            ttk.Entry(inner, textvariable=var).grid(row=row, column=1, sticky="ew", padx=6, pady=3)
            ttk.Button(inner, text="Browse…", command=lambda k=kind: self.browse(k)).grid(
                row=row, column=2, pady=3)
        ttk.Label(inner, text="Control Baseline", style="Field.TLabel").grid(
            row=2, column=0, sticky="w", pady=3)
        ttk.Combobox(inner, textvariable=self.revision, values=list(REVISIONS),
                     state="readonly", width=30).grid(row=2, column=1, sticky="w", padx=6, pady=3)
        self.load_btn = ttk.Button(inner, text="Load & Map", style="Accent.TButton", command=self.load)
        self.load_btn.grid(row=0, column=3, rowspan=3, padx=(14, 0), sticky="ns")

        # Summary cards
        cards = ttk.Frame(body)
        cards.pack(fill="x", pady=12)
        self.cards = {}
        for i, (key, caption, color) in enumerate([
                ("rules", "STIG Rules", NAVY), ("high", "CAT I · High", CAT1),
                ("medium", "CAT II · Medium", CAT2), ("low", "CAT III · Low", CAT3),
                ("ccis", "Unique CCIs", NAVY), ("controls", "NIST Controls", NAVY),
                ("review", "Needs Review", CAT2)]):
            card = StatCard(cards, caption, color)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 10, 0))
            cards.columnconfigure(i, weight=1, uniform="cards")
            self.cards[key] = card

        # Actions (packed at the bottom before the tabs so they always stay visible)
        actions = ttk.Frame(body)
        actions.pack(fill="x", side="bottom", pady=(10, 0))
        ttk.Button(actions, text="Export HTML Report", style="Accent.TButton",
                   command=self.export_html).pack(side="right")
        ttk.Button(actions, text="Export Current View (CSV)",
                   command=self.export_csv).pack(side="right", padx=8)
        self.count_label = ttk.Label(actions, text="", foreground=MUTED, font=(FONT, 9))
        self.count_label.pack(side="left")

        # Tabs
        self.nb = ttk.Notebook(body)
        self.nb.pack(fill="both", expand=True)
        self._build_matrix_tab()
        self._build_family_tab()

    def _build_matrix_tab(self):
        tab = ttk.Frame(self.nb, style="Card.TFrame", padding=12)
        self.nb.add(tab, text="Traceability Matrix")

        bar = ttk.Frame(tab, style="Card.TFrame")
        bar.pack(fill="x", pady=(0, 8))
        ttk.Label(bar, text="Search", style="Field.TLabel").pack(side="left")
        ttk.Entry(bar, textvariable=self.search, width=34).pack(side="left", padx=(6, 14))
        ttk.Combobox(bar, textvariable=self.sev_filter, state="readonly", width=16,
                     values=["All severities", "CAT I", "CAT II", "CAT III"]).pack(side="left")
        self.fam_combo = ttk.Combobox(bar, textvariable=self.fam_filter, state="readonly", width=42,
                                      values=["All families"])
        self.fam_combo.pack(side="left", padx=8)
        ttk.Checkbutton(bar, text="Needs review only", variable=self.review_only).pack(side="left", padx=6)
        ttk.Button(bar, text="Clear", command=self.clear_filters).pack(side="left", padx=6)

        pane = ttk.PanedWindow(tab, orient="vertical")
        pane.pack(fill="both", expand=True)

        tree_frame = ttk.Frame(pane, style="Card.TFrame")
        self.tree = ttk.Treeview(tree_frame, columns=[c[0] for c in self.MATRIX_COLS],
                                 show="headings", selectmode="browse")
        for key, label, width, stretch in self.MATRIX_COLS:
            self.tree.heading(key, text=label, anchor="w", command=lambda k=key: self.sort_by(k))
            self.tree.column(key, width=width, minwidth=50, stretch=stretch, anchor="w")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.tag_configure("odd", background="#f6f8fb")
        self.tree.tag_configure("even", background="white")
        self.tree.tag_configure("review", background="#fff4e0", foreground="#7a4a00")
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)
        pane.add(tree_frame, weight=3)

        detail_frame = tk.Frame(pane, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        self.detail = tk.Text(detail_frame, wrap="word", font=(FONT, 10), bg=CARD, fg=TEXT,
                              relief="flat", padx=16, pady=12, height=5, cursor="arrow")
        dsb = ttk.Scrollbar(detail_frame, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=dsb.set)
        self.detail.pack(side="left", fill="both", expand=True)
        dsb.pack(side="right", fill="y")
        self.detail.tag_configure("h1", font=(FONT, 13, "bold"), foreground=NAVY, spacing3=6)
        self.detail.tag_configure("h2", font=(FONT, 9, "bold"), foreground=NAVY, spacing1=10, spacing3=2)
        self.detail.tag_configure("mono", font=(MONO, 10))
        self.detail.tag_configure("muted", foreground=MUTED)
        self.detail.tag_configure("flag", foreground=CAT2, font=(FONT, 10, "bold"))
        for sev, color in (("high", CAT1), ("medium", CAT2), ("low", CAT3)):
            self.detail.tag_configure(sev, foreground="white", background=color, font=(FONT, 9, "bold"))
        self._set_detail([("Select a row to view the rule, CCI, and control details.", "muted")])
        pane.add(detail_frame, weight=2)

    def _build_family_tab(self):
        tab = ttk.Frame(self.nb, style="Card.TFrame", padding=12)
        self.nb.add(tab, text="Control Families")
        tab.columnconfigure(0, weight=3)
        tab.columnconfigure(1, weight=2)
        tab.rowconfigure(1, weight=1)

        ttk.Label(tab, text="Double-click a family to open it in the Traceability Matrix.",
                  style="Muted.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 6))
        ttk.Label(tab, text="Rules per family by severity", style="Field.TLabel").grid(
            row=0, column=1, sticky="w", padx=(14, 0), pady=(0, 6))

        self.ftree = ttk.Treeview(tab, columns=[c[0] for c in self.FAMILY_COLS],
                                  show="headings", selectmode="browse")
        for key, label, width in self.FAMILY_COLS:
            anchor = "w" if key in ("family", "name") else "e"
            self.ftree.heading(key, text=label, anchor=anchor)
            self.ftree.column(key, width=width, anchor=anchor, stretch=(key == "name"))
        self.ftree.tag_configure("odd", background="#f6f8fb")
        self.ftree.tag_configure("review", background="#fff4e0", foreground="#7a4a00")
        self.ftree.grid(row=1, column=0, sticky="nsew")
        self.ftree.bind("<Double-1>", self.open_family)

        self.chart = tk.Canvas(tab, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        self.chart.grid(row=1, column=1, sticky="nsew", padx=(14, 0))
        self.chart.bind("<Configure>", lambda e: self.draw_chart())

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=NAVY_2)
        bar.pack(fill="x", side="bottom")
        tk.Label(bar, textvariable=self.status, font=(FONT, 9), fg="#dfe6ef", bg=NAVY_2,
                 anchor="w").pack(side="left", padx=14, pady=4)
        tk.Label(bar, text=f"v{VERSION}", font=(FONT, 9), fg="#9fb0c6", bg=NAVY_2).pack(
            side="right", padx=14)

    # ---- actions ---------------------------------------------------------- #
    def browse(self, kind):
        var = self.cci_path if kind == "cci" else self.stig_path
        title = "Select CCI List" if kind == "cci" else "Select STIG XCCDF Benchmark"
        start = os.path.dirname(var.get()) if os.path.isdir(os.path.dirname(var.get())) else HERE
        path = filedialog.askopenfilename(title=title, initialdir=start,
                                          filetypes=[("XML files", "*.xml"), ("All files", "*.*")])
        if path:
            var.set(path)
        return bool(path)

    @staticmethod
    def unique_path(path):
        """Add (1), (2), ... before the extension so an earlier export is never overwritten."""
        base, ext = os.path.splitext(path)
        counter = 0
        while os.path.exists(path):
            counter += 1
            path = f"{base}({counter}){ext}"
        return path

    def load(self):
        cci, stig = self.cci_path.get().strip(), self.stig_path.get().strip()
        for label, p in (("CCI list", cci), ("STIG benchmark", stig)):
            if not os.path.isfile(p):
                messagebox.showerror(APP_TITLE, f"The {label} file was not found:\n\n{p}")
                return
        self.status.set("Parsing source documents…")
        self.config(cursor="watch")
        self.load_btn.state(["disabled"])
        self.update_idletasks()
        try:
            self.meta, self.rules, self.rows, self.cci_version = load_documents(
                cci, stig, REVISIONS[self.revision.get()])
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"Could not read the files:\n\n{exc}")
            self.status.set("Load failed.")
            return
        finally:
            self.config(cursor="")
            self.load_btn.state(["!disabled"])

        self.stats = compute_stats(self.rules, self.rows)
        self.families = family_summary(self.rows)
        for key, card in self.cards.items():
            color = (OK if self.stats["review"] == 0 else CAT2) if key == "review" else None
            card.set(self.stats[key], color)

        self.doc_label.config(text=f"{self.meta['title']}  ·  V{self.meta['version']}  "
                                   f"·  {self.meta['release']}")
        self.fam_combo["values"] = ["All families"] + [
            f"{f['family']} — {f['name']}" for f in self.families]
        self.fam_filter.set("All families")
        self._fill_family_tree()
        self.draw_chart()
        self.apply_filters()
        self.status.set(f"Loaded {self.stats['rules']} rules "
                        f"(CCI list {self.cci_version}) → {self.stats['rows']:,} mappings "
                        f"against {self.revision.get()}.")

    def clear_filters(self):
        self.search.set("")
        self.sev_filter.set("All severities")
        self.fam_filter.set("All families")
        self.review_only.set(False)

    def apply_filters(self):
        q = self.search.get().strip().lower()
        sev = self.sev_filter.get()
        fam = self.fam_filter.get().split(" — ")[0]
        view = []
        for r in self.rows:
            if sev != "All severities" and r["cat"] != sev:
                continue
            if fam != "All families" and r["family"] != fam:
                continue
            if self.review_only.get() and r["family"] != NEEDS_REVIEW:
                continue
            if q and q not in " ".join((r["vuln_id"], r["stig_id"], r["cci"], r["nist"],
                                        r["title"], r["note"])).lower():
                continue
            view.append(r)
        if self.sort_col:
            view.sort(key=self._sort_key, reverse=self.sort_rev)
        self.view = view

        self.tree.delete(*self.tree.get_children())
        for i, r in enumerate(view):
            tag = "review" if r["family"] == NEEDS_REVIEW else ("odd" if i % 2 else "even")
            self.tree.insert("", "end", iid=str(i), tags=(tag,), values=(
                r["vuln_id"], r["stig_id"], r["cat"], r["cci"] or "—",
                r["nist"] or r["note"], r["family"] if r["nist"] else "—", r["title"]))
        rules = len({r["vuln_id"] for r in view})
        self.count_label.config(text=f"Showing {len(view):,} of {len(self.rows):,} mappings "
                                     f"· {rules} rules")

    def _sort_key(self, r):
        c = self.sort_col
        if c == "cat":
            return SEVERITY_ORDER.get(r["severity"], 9)
        if c in ("vuln_id", "cci"):
            digits = re.sub(r"\D", "", r[c])
            return int(digits) if digits else -1
        if c == "nist":
            return r["nist"] or "~" + r["note"]
        return r[c].lower()

    def sort_by(self, col):
        self.sort_rev = (not self.sort_rev) if self.sort_col == col else False
        self.sort_col = col
        for key, label, *_ in self.MATRIX_COLS:
            arrow = (" ▼" if self.sort_rev else " ▲") if key == col else ""
            self.tree.heading(key, text=label + arrow)
        self.apply_filters()

    def _set_detail(self, parts):
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        for text, *tags in parts:
            self.detail.insert("end", text, tuple(tags))
        self.detail.config(state="disabled")

    def show_detail(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        r = self.view[int(sel[0])]
        rule = self.rules[r["rule"]]
        parts = [
            (rule["title"] + "\n", "h1"),
            (f" {r['cat']} ", r["severity"]), ("   ", ),
            (f"{rule['vuln_id']}   ·   {rule['rule_id']}   ·   {rule['stig_id']}\n", "mono", "muted"),
            ("CONTROL CORRELATION IDENTIFIER\n", "h2"),
        ]
        if r["cci"]:
            parts.append((r["cci"], "mono"))
            parts.append((f"   ({r['definition'] and 'definition below' or 'no definition'})\n", "muted"))
            if r["definition"]:
                parts.append((r["definition"] + "\n", ))
        else:
            parts.append(("No CCI is referenced by this rule.\n", "flag"))
        parts.append((f"{self.revision.get().upper()} CONTROL\n", "h2"))
        if r["nist"]:
            parts.append((r["nist"], "mono"))
            parts.append((f"   —   {family_name(r['family'])}\n", ))
        else:
            reason = {"NOT MAPPED": "this CCI has no control in the selected revision",
                      "NO CCI": "the rule references no CCI",
                      "CCI NOT IN LIST": "the CCI is missing from the CCI list"}.get(r["note"], r["note"])
            parts.append((f"Not mapped — {reason}. Requires analyst review.\n", "flag"))
        others = sorted({x["nist"] for x in self.rows if x["vuln_id"] == r["vuln_id"] and x["nist"]})
        if len(others) > 1:
            parts.append(("All controls for this rule: ", "muted"))
            parts.append((", ".join(others) + "\n", "mono"))
        for heading, key in (("VULNERABILITY DISCUSSION", "discussion"),
                             ("CHECK TEXT", "check"), ("FIX TEXT", "fix")):
            if rule[key]:
                parts.append((heading + "\n", "h2"))
                parts.append((rule[key] + "\n", ))
        self._set_detail(parts)

    def _fill_family_tree(self):
        self.ftree.delete(*self.ftree.get_children())
        for i, f in enumerate(self.families):
            tag = "review" if f["family"] == NEEDS_REVIEW else ("odd" if i % 2 else "")
            values = [f[c[0]] for c in self.FAMILY_COLS]
            if f["family"] == NEEDS_REVIEW:
                values[0] = "Review"
            self.ftree.insert("", "end", iid=f["family"], tags=(tag,), values=values)

    def open_family(self, _event=None):
        sel = self.ftree.selection()
        if not sel:
            return
        fam = next(f for f in self.families if f["family"] == sel[0])
        self.clear_filters()
        self.fam_filter.set(f"{fam['family']} — {fam['name']}")
        self.nb.select(0)

    def draw_chart(self):
        c = self.chart
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        fams = self.families
        if not fams or w < 50:
            c.create_text(w / 2, h / 2, text="Load documents to see the chart", fill=MUTED,
                          font=(FONT, 10))
            return
        left, right, top, legend_h = 110, 40, 16, 34
        bar_area = h - top - legend_h - 10
        step = max(16, min(34, bar_area / len(fams)))
        bar_h = step * 0.62
        scale = (w - left - right) / max(f["rules"] for f in fams)
        for i, f in enumerate(fams):
            y = top + i * step
            label = "Review" if f["family"] == NEEDS_REVIEW else f["family"]
            c.create_text(left - 10, y + bar_h / 2, text=label, anchor="e",
                          font=(FONT, 9, "bold"), fill=CAT2 if label == "Review" else NAVY)
            x = left
            for key, color in (("high", CAT1), ("medium", CAT2), ("low", CAT3)):
                if f[key]:
                    x2 = x + f[key] * scale
                    c.create_rectangle(x, y, x2, y + bar_h, fill=color, outline="")
                    x = x2 + 1
            c.create_text(x + 6, y + bar_h / 2, text=str(f["rules"]), anchor="w",
                          font=(FONT, 9), fill=TEXT)
        ly = h - legend_h + 10
        lx = left
        for text, color in (("CAT I", CAT1), ("CAT II", CAT2), ("CAT III", CAT3)):
            c.create_rectangle(lx, ly, lx + 12, ly + 12, fill=color, outline="")
            c.create_text(lx + 18, ly + 6, text=text, anchor="w", font=(FONT, 9), fill=TEXT)
            lx += 80

    def _require_data(self):
        if not self.rows:
            messagebox.showinfo(APP_TITLE, "Load the source documents first.")
            return False
        return True

    def export_csv(self):
        if not self._require_data():
            return
        path = filedialog.asksaveasfilename(
            title="Export Current View", defaultextension=".csv", initialdir=HERE,
            initialfile=os.path.basename(self.unique_path(os.path.join(HERE, "stig_traceability.csv"))),
            filetypes=[("CSV files", "*.csv")])
        if not path:
            return
        try:
            save_csv(self.view, path)
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Could not write file:\n\n{exc}")
            return
        self.status.set(f"Exported {len(self.view):,} rows to {path}")

    def export_html(self):
        if not self._require_data():
            return
        path = filedialog.asksaveasfilename(
            title="Export HTML Report", defaultextension=".html", initialdir=HERE,
            initialfile=os.path.basename(self.unique_path(os.path.join(HERE, "STIG_Traceability_Report.html"))),
            filetypes=[("HTML files", "*.html")])
        if not path:
            return
        report = build_report_html(self.meta, self.cci_version, self.revision.get(),
                                   self.stats, self.families, self.rows)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(report)
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Could not write file:\n\n{exc}")
            return
        self.status.set(f"Report saved to {path}")
        if messagebox.askyesno(APP_TITLE, "Report saved. Open it in your browser now?"):
            webbrowser.open("file:///" + os.path.abspath(path).replace("\\", "/"))


def main():
    try:  # crisp text on high-DPI Windows displays
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa: BLE001 - not Windows / not supported
        pass
    App().mainloop()


if __name__ == "__main__":
    main()
