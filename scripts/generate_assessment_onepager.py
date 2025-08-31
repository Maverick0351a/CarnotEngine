#!/usr/bin/env python3
"""Generate assessment one-pager Markdown + minimal PDF without external deps.

Substitutes placeholders in docs/ASSESSMENT_TEMPLATE.md using attestation + violations.
Creates both a filled markdown file and a lightweight PDF (basic text only).
If pandoc is available it will be used instead of the built‑in minimal PDF writer.
"""
import argparse, json, datetime, os, shutil, re, subprocess, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
TEMPLATE_PATH = os.path.join(ROOT, 'docs', 'ASSESSMENT_TEMPLATE.md')

PLACEHOLDERS = {
    'company_name': 'ExampleCo',
    'date': datetime.date.today().isoformat(),
    'year': str(datetime.date.today().year),
    'hndl_exposure_pct': '0',
    'total_observations': '0',
    'high_violations_count': '0'
}

TOKEN_RE = re.compile(r'{{\s*([a-zA-Z0-9_]+)\s*}}')

def load_attestation(path):
    if not path or not os.path.exists(path):
        return {}
    try:
        return json.load(open(path, encoding='utf-8'))
    except Exception:
        return {}

def load_violations(path):
    if not path or not os.path.exists(path):
        return []
    try:
        data = json.load(open(path, encoding='utf-8'))
        return data['result'][0]['expressions'][0]['value'] or []
    except Exception:
        return []

def fill_placeholders(template_text, mapping):
    def repl(m):
        key = m.group(1)
        return str(mapping.get(key, m.group(0)))
    return TOKEN_RE.sub(repl, template_text)

def have_pandoc():
    return shutil.which('pandoc') is not None

def write_minimal_pdf(text, out_path):
    # Extremely small PDF writer (single page, Helvetica font).
    lines = text.splitlines() or ['']
    # Prepare content stream: place each line with simple text operations.
    content_lines = []
    y = 800
    for ln in lines:
        safe = ln.replace('(', '\\(').replace(')', '\\)')
        content_lines.append(f'1 0 0 1 50 {y} Tm ({safe}) Tj')
        y -= 14
        if y < 50:
            break  # truncate if too long
    content_stream = "BT /F1 10 Tf " + " ".join(content_lines) + " ET"
    stream_bytes = content_stream.encode('utf-8')
    objects = []
    def add(obj):
        objects.append(obj)
        return len(objects)
    # Font object
    font_obj_num = add("<< /Type /Font /Subtype /Type1 /Name /F1 /BaseFont /Helvetica >>")
    # Contents object
    contents_obj_num = add(f"<< /Length {len(stream_bytes)} >>\nstream\n{content_stream}\nendstream")
    # Page object
    page_obj = f"<< /Type /Page /Parent 4 0 R /Resources << /Font << /F1 {font_obj_num} 0 R >> >> /MediaBox [0 0 595 842] /Contents {contents_obj_num} 0 R >>"
    page_obj_num = add(page_obj)
    # Pages object (id 4 fixed by ordering below)
    pages_obj_num = add(f"<< /Type /Pages /Kids [{page_obj_num} 0 R] /Count 1 >>")
    # Catalog object
    catalog_obj_num = add(f"<< /Type /Catalog /Pages {pages_obj_num} 0 R >>")
    # Build PDF
    offsets = []
    pdf = ["%PDF-1.4\n%\xE2\xE3\xCF\xD3\n"]
    for idx, obj in enumerate(objects, start=1):
        offsets.append(sum(len(x.encode('latin1', 'ignore')) for x in pdf))
        pdf.append(f"{idx} 0 obj\n{obj}\nendobj\n")
    xref_start = sum(len(x.encode('latin1', 'ignore')) for x in pdf)
    pdf.append(f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n")
    for off in offsets:
        pdf.append(f"{off:010d} 00000 n \n")
    pdf.append(f"trailer << /Size {len(objects)+1} /Root {catalog_obj_num} 0 R >>\nstartxref\n{xref_start}\n%%EOF")
    with open(out_path, 'wb') as f:
        f.write("".join(pdf).encode('latin1', 'ignore'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--company', required=True)
    ap.add_argument('--attestation')
    ap.add_argument('--violations')
    ap.add_argument('--out-dir', default=os.path.join(ROOT, 'docs', 'sales'))
    ap.add_argument('--basename', default='Assessment_OnePager')
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    mapping = PLACEHOLDERS.copy()
    mapping['company_name'] = args.company

    att = load_attestation(args.attestation)
    summary = att.get('summary', {})
    mapping['hndl_exposure_pct'] = summary.get('hndl_exposure_pct', 0)
    mapping['total_observations'] = summary.get('total_observations', 0)

    violations = load_violations(args.violations)
    mapping['high_violations_count'] = sum(1 for v in violations if v.get('severity') == 'high')

    template = open(TEMPLATE_PATH, encoding='utf-8').read()
    filled = fill_placeholders(template, mapping)

    md_path = os.path.join(args.out_dir, f"{args.basename}.md")
    open(md_path, 'w', encoding='utf-8').write(filled)

    pdf_path = os.path.join(args.out_dir, f"{args.basename}.pdf")
    if have_pandoc():
        try:
            subprocess.check_call(['pandoc', md_path, '-o', pdf_path])
            print('Generated PDF via pandoc:', pdf_path)
        except Exception as e:
            print('Pandoc failed, falling back to minimal PDF:', e, file=sys.stderr)
            write_minimal_pdf(filled, pdf_path)
    else:
        write_minimal_pdf(filled, pdf_path)
        print('Generated minimal PDF (no pandoc found):', pdf_path)

    print('Markdown written to', md_path)

if __name__ == '__main__':
    main()
