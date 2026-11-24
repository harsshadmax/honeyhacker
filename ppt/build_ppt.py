"""Build the Round 0 PPTX from the official template PDF.

The template's artwork (characters, castle footer, hexagon badges, cards) is kept as each slide's background
(text stripped out of the PDF); every piece of text is re-created as an editable PowerPoint text box at the
template's exact position, font, size and colour.
"""
import os
import sys

import pymupdf
from PIL import ImageFont
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Pt

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = r"C:\Parama\Clash of Commits_ Idea Submission Template.pdf"
OUT = os.path.join(HERE, "CYB-03_Living-Hacker-Trap_Round0.pptx")
BG = os.path.join(HERE, "bg")
os.makedirs(BG, exist_ok=True)

KEEP, DROP = object(), object()

# ------------------------------------------------------------------ content
CONTENT = {
    0: [  # slide 1: title, pitch, track, team name, member rows
        dict(text="Living Hacker Trap", w=345),
        dict(text="Fake systems that trap, record and block attackers.", w=345),
        dict(text="TRACK  \u00b7  CYBERSECURITY", w=300),
        KEEP,                                   # [ Team Name ]  (to be filled in by the team)
        dict(text="HARSSHAD PA \u2014 [ Email ]", w=190),
        DROP, DROP, DROP, DROP,
    ],
    1: [  # slide 2: problem definition
        dict(w=600, size=11, text="Security teams. Intruders often go unnoticed for a median of 11 days (Mandiant M-Trends 2025)."),
        dict(w=600, size=11, text="Firewalls and antivirus guard the perimeter, then teams read logs after the fact to work out what happened."),
        dict(w=600, size=11, text="It is passive: no alert until damage shows, log noise hides the intruder, and little is learned."),
        dict(w=600, size=11, text="IBM 2025: 241 days to identify and contain a breach; Mandiant 2025: 11-day median dwell time."),
    ],
    2: [  # slide 3: solution
        dict(text="LIVING HACKER TRAP", w=340),
        dict(w=560, size=12, text="A fake admin portal and a fake SSH server that lure attackers, record every move, and hand the "
                                  "defender a live alert and a ready-made block rule."),
        dict(w=190, size=11, text="Start it with one command, watch the live dashboard, replay what the attacker typed, then click for a block rule."),
        dict(w=190, size=11, text="Any touch of a decoy is suspicious, so alerts arrive in about 10 ms with the full attacker trail, not days later."),
        dict(w=190, size=11, text="Bait files carry canary tokens tied to the attacker's session, and the decoys have no internet access."),
    ],
    3: [  # slide 4: architecture. 3 boxes, then 3 cards
        dict(box=True, text="Decoys\n(web + SSH)"),
        dict(box=True, text="API + risk\nscoring"),
        dict(box=True, text="SQLite + live\ndashboard"),
        dict(w=190, size=11, text="Decoys run on an internal-only Docker network with no internet, so a trapped attacker cannot get out."),
        dict(w=190, size=11, text="Making decoys believable but safe: the fake shell only returns canned text and never runs a command."),
        dict(w=190, size=11, text="13 automated tests pass, and a scripted attack reaches the dashboard in a median of 10 ms (40 runs, local)."),
    ],
    4: [  # slide 5: feasibility
        dict(w=300, size=11, text="In: web + SSH decoys, canary bait, live dashboard, block rules.\nOut: real firewall changes, ML detection, public hosting."),
        DROP,
        dict(w=300, size=11, text="Near zero: runs on one laptop in three small containers (256 MB each), with no paid APIs or cloud."),
        dict(w=300, size=11, text="Decoys may look fake, and a live demo can fail. Fallback: run_local.py (no Docker). It only catches attackers who touch a decoy."),
        dict(w=300, size=11, text="More decoy types, a dashboard login, email or Slack alerts, and export to a SIEM."),
    ],
    5: [  # slide 6: impact
        dict(text="10 ms", center=True, w=220),
        dict(text="median attacker-to-alert time", center=True, w=230, size=11),
        dict(center=True, w=232, size=10, text="40 runs on one PC via Docker: from the event being sent to the alert reaching the dashboard. "
                                               "Median 10 ms, 95th percentile under 100 ms. A local estimate."),
        dict(w=340, size=11, text="Before: intruders unseen a median 11 days. After: alert in ~10 ms."),
        dict(w=340, size=11, text="Schools, hospitals and small firms with no 24/7 security team."),
        dict(w=340, size=11, text="A decoy could be a stepping stone; it only alerts if touched."),
        dict(w=340, size=11, text="No-internet containers, canned shell output, human-reviewed rules."),
    ],
    6: [  # slide 7: references (5 rows x 4 cells)
        "IBM & Ponemon, Cost of a Data Breach Report, 2025", "Evidence: 241-day average to identify and contain", "Borrowed (one figure, cited)", "\u00a9 IBM, cited only",
        "FastAPI, Flask, waitress, asyncssh (PyPI)", "API, web decoy and SSH server libraries", "Borrowed libraries; app code is ours", "MIT, BSD-3, ZPL-2.1, EPL-2.0",
        "Google Mandiant, M-Trends 2025", "Evidence: 11-day median dwell time", "Borrowed (one figure, cited)", "\u00a9 Google, cited only",
        "None used", "Demo events come from our own script", "Ours", "n/a",
        "None used", "Scoring is rule-based, no ML model", "Ours", "n/a",
    ],
    7: [  # slide 8: extra
        dict(w=600, size=12, text="Demo: docker compose up -d, then python attacker_demo/attack.py (dashboard at 127.0.0.1:8000). "
                                  "Built by HARSSHAD PA with Python, FastAPI, Flask, asyncssh and Docker. "
                                  "Inspired by Cowrie and Thinkst Canarytokens (ideas only, no code used)."),
    ],
}
TABLE_COLS = {"x": [122.0, 320.0, 478.3, 604.3], "w": [190, 150, 122, 90]}

# ------------------------------------------------------------------ fonts
FONT_MAP = {  # pdf font -> (pptx name, bold, italic, ttf file for width measuring)
    "ArialBlack": ("Arial Black", False, False, "ariblk.ttf"),
    "Calibri-Bold": ("Calibri", True, False, "calibrib.ttf"),
    "Calibri": ("Calibri", False, False, "calibri.ttf"),
    "Calibri-Italic": ("Calibri", False, True, "calibrii.ttf"),
    "Arial-BoldMT": ("Arial", True, False, "arialbd.ttf"),
    "ArialMT": ("Arial", False, False, "arial.ttf"),
}
_ft = {}


def natural_width(text, font, size):
    ttf = FONT_MAP[font][3]
    try:
        key = (ttf, size)
        if key not in _ft:
            _ft[key] = ImageFont.truetype(os.path.join(r"C:\Windows\Fonts", ttf), int(round(size * 10)))
        return _ft[key].getlength(text) / 10.0
    except Exception:
        return None


def spacing_for(span):
    """Letter-spacing (hundredths of a pt) the template applied to this span, from its measured width."""
    t = span["t"]
    if len(t.strip()) < 2:
        return 0
    nat = natural_width(t, span["font"], span["size"])
    if not nat:
        return 0
    w = span["bbox"][2] - span["bbox"][0]
    spc = (w - nat) / max(len(t) - 1, 1)
    return int(round(spc * 100)) if abs(spc) >= 0.2 else 0


# ------------------------------------------------------------------ step 1: strip text, render backgrounds
def make_backgrounds(spans_by_page):
    doc = pymupdf.open(TEMPLATE)
    for i, page in enumerate(doc):
        for sp in spans_by_page[i]:
            r = pymupdf.Rect(sp["bbox"]) + (-0.6, -0.6, 0.6, 0.6)
            page.add_redact_annot(r, fill=False)
        page.apply_redactions(images=0, graphics=0, text=0)  # remove text only; keep every image and shape
        pix = page.get_pixmap(dpi=200)
        pix.save(os.path.join(BG, f"bg{i + 1}.jpg"), jpg_quality=92)
    doc.close()


def read_spans():
    doc = pymupdf.open(TEMPLATE)
    out = []
    for p in doc:
        spans = []
        for b in p.get_text("dict")["blocks"]:
            for l in b.get("lines", []):
                for s in l["spans"]:
                    if s["text"].strip():
                        spans.append(dict(t=s["text"], font=s["font"], size=round(s["size"], 1),
                                          color="%06X" % s["color"], bbox=[round(x, 1) for x in s["bbox"]]))
        out.append(spans)
    doc.close()
    return out


# ------------------------------------------------------------------ pptx helpers
def E(pt):
    return Emu(int(round(pt * 12700)))


def add_box(slide, name, x, yc, w, paras, align=PP_ALIGN.LEFT, wrap=False, anchor=MSO_ANCHOR.MIDDLE, h=None, top=None):
    """paras: list of paragraphs, each a list of runs (text, span-dict-with-font/size/color, spc)."""
    size = max(r[1]["size"] for p in paras for r in p)
    nlines = len(paras)
    hh = h or size * 1.35 * nlines + 2
    y = top if top is not None else yc - hh / 2
    tb = slide.shapes.add_textbox(E(x), E(y), E(w), E(hh))
    tb.name = name
    tf = tb.text_frame
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    tf.word_wrap = wrap
    tf.vertical_anchor = anchor
    for pi, runs in enumerate(paras):
        p = tf.paragraphs[0] if pi == 0 else tf.add_paragraph()
        p.alignment = align
        for text, st, spc in runs:
            r = p.add_run()
            r.text = text
            nm, bold, ital, _ = FONT_MAP[st["font"]]
            r.font.name, r.font.bold, r.font.italic = nm, bold, ital
            r.font.size = Pt(st["size"])
            r.font.color.rgb = RGBColor.from_string(st["color"])
            if spc:
                r._r.get_or_add_rPr().set("spc", str(spc))
    return tb


def group_placeholders(spans):
    """Return (groups, other). A group = consecutive spans forming one bracketed placeholder."""
    groups, other, i = [], [], 0
    while i < len(spans):
        s = spans[i]
        if "[" in s["t"]:
            g = [i]
            while "]" not in spans[g[-1]]["t"] and g[-1] + 1 < len(spans):
                g.append(g[-1] + 1)
            groups.append(g)
            i = g[-1] + 1
        else:
            other.append(i)
            i += 1
    return groups, other


def union(spans, idx):
    b = [spans[i]["bbox"] for i in idx]
    return [min(x[0] for x in b), min(x[1] for x in b), max(x[2] for x in b), max(x[3] for x in b)]


def build():
    spans_all = read_spans()
    make_backgrounds(spans_all)

    prs = Presentation()
    prs.slide_width, prs.slide_height = Emu(9144000), Emu(5143500)
    blank = prs.slide_layouts[6]

    for pg, spans in enumerate(spans_all):
        slide = prs.slides.add_slide(blank)
        pic = slide.shapes.add_picture(os.path.join(BG, f"bg{pg + 1}.jpg"), 0, 0, prs.slide_width, prs.slide_height)
        pic.name = f"Template artwork {pg + 1}"
        pic._element.nvPicPr.cNvPr.set("descr", "Clash of Commits template artwork (decorative background)")

        groups, other = group_placeholders(spans)
        content = CONTENT[pg]
        consumed = set()

        # ---- table slide: 20 cell replacements
        if pg == 6:
            assert len(groups) == 20, len(groups)
            for gi, g in enumerate(groups):
                col = gi % 4
                s0 = spans[g[0]]
                yc = (s0["bbox"][1] + s0["bbox"][3]) / 2
                st = dict(s0, size=9)
                add_box(slide, f"Reference cell {gi // 4 + 1}-{col + 1}", TABLE_COLS["x"][col], yc, TABLE_COLS["w"][col],
                        [[(content[gi], st, 0)]], wrap=True, h=30)
                consumed.update(g)
        else:
            assert len(groups) == len(content), (pg, len(groups), len(content))
            for g, c in zip(groups, content):
                consumed.update(g)
                if c is KEEP:
                    c = dict(text=" ".join(spans[i]["t"].strip() for i in g), keep=True)
                if c is DROP:
                    continue
                s0 = spans[g[0]]
                bb = union(spans, g)
                st = dict(s0)
                if c.get("size"):
                    st["size"] = c["size"]
                spc = 0 if c.get("size") else spacing_for(s0)
                lines = c["text"].split("\n")
                paras = [[(ln, st, spc)] for ln in lines]
                if c.get("box") or c.get("center"):
                    cx = (bb[0] + bb[2]) / 2
                    w = c.get("w", 112)
                    yc = (bb[1] + bb[3]) / 2
                    add_box(slide, f"Text {pg + 1}-{len(slide.shapes)}", cx - w / 2, yc, w, paras, align=PP_ALIGN.CENTER, wrap=True)
                elif c.get("w") and (len(lines) > 1 or len(c["text"]) * st["size"] * 0.5 > c["w"]):
                    # wrapped body text: anchor top at the first template line
                    yc0 = (s0["bbox"][1] + s0["bbox"][3]) / 2
                    add_box(slide, f"Text {pg + 1}-{len(slide.shapes)}", s0["bbox"][0], yc0, c["w"], paras, wrap=True,
                            anchor=MSO_ANCHOR.TOP, top=yc0 - st["size"] * 0.61, h=st["size"] * 1.3 * (len(c["text"]) // max(int(c["w"] / (st["size"] * 0.48)), 1) + len(lines)))
                else:
                    yc = (s0["bbox"][1] + s0["bbox"][3]) / 2 + (8 if (pg == 0 and c["text"] == "Living Hacker Trap") else 0)
                    add_box(slide, f"Text {pg + 1}-{len(slide.shapes)}", s0["bbox"][0], yc, c.get("w", bb[2] - bb[0] + 12), paras)

        # ---- slide 4 specifics (box labels + caption), done on the "other" spans
        repl_static = {}
        if pg == 3:
            repl_static = {"User Input": "Attacker", "Output": "Block rule\n(text only)"}
        drop_prefix = ("\u2191", " REPLACE WITH") if pg == 3 else ()

        # ---- static spans: group by line, merge adjacent runs
        rest = [i for i in range(len(spans)) if i not in consumed]
        rest.sort(key=lambda i: (round(spans[i]["bbox"][1] / 2), spans[i]["bbox"][0]))
        lines, cur = [], []
        for i in rest:
            s = spans[i]
            if cur and abs(spans[cur[-1]]["bbox"][1] - s["bbox"][1]) < 2.5 and 0 <= s["bbox"][0] - spans[cur[-1]]["bbox"][2] < 14:
                cur.append(i)
            else:
                if cur:
                    lines.append(cur)
                cur = [i]
        if cur:
            lines.append(cur)

        for ln in lines:
            first = spans[ln[0]]
            txt = "".join(spans[i]["t"] for i in ln)
            if pg == 3 and txt.strip().startswith(("\u2191", "REPLACE")):
                bb = union(spans, ln)
                cap = dict(first, font="Calibri-Bold", size=10, color="5B3A1E")
                add_box(slide, "Diagram caption", 0, (bb[1] + bb[3]) / 2, 720,
                        [[("Attacker \u2192 decoys (no internet) \u2192 API \u2192 dashboard and block rule", cap, 60)]],
                        align=PP_ALIGN.CENTER)
                continue
            if pg == 3 and txt.strip() in repl_static:
                bb = union(spans, ln)
                paras = [[(t, first, 0)] for t in repl_static[txt.strip()].split("\n")]
                add_box(slide, f"Text 4-{len(slide.shapes)}", (bb[0] + bb[2]) / 2 - 56, (bb[1] + bb[3]) / 2, 112, paras,
                        align=PP_ALIGN.CENTER, wrap=True)
                continue
            if pg == 3 and txt.strip() == "\u2191":
                continue
            bb = union(spans, ln)
            runs = []
            for k, i in enumerate(ln):
                t = spans[i]["t"]
                if k and spans[i]["bbox"][0] - spans[ln[k - 1]]["bbox"][2] > 1.5 and not runs[-1][0].endswith(" ") and not t.startswith(" "):
                    t = " " + t
                spc_ = spacing_for(spans[i])
                fixed = {"P R O J E C T T I T L E": "PROJECT TITLE", "O N E - L I N E P I T C H": "ONE-LINE PITCH"}.get(t.strip())
                if fixed:
                    t = fixed
                runs.append((t, spans[i], spc_))
            add_box(slide, f"Text {pg + 1}-{len(slide.shapes)}", bb[0], (bb[1] + bb[3]) / 2, bb[2] - bb[0] + 14, [runs])

        # slide 4: the 2-line "Model/AWS" original and others have been consumed as groups; static 'User Input'/'Output' handled above

    prs.save(OUT)
    print("saved", OUT)


if __name__ == "__main__":
    build()
