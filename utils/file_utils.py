import chardet
import markdown
from weasyprint import HTML, CSS
import os

def load_list(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return set(line.strip().lower() for line in f)

# Helper decode hex function
def decode_hex(password):
    decoded = []
    pwd = password
    if "$HEX" in password:
        multihex = list(filter(None, password.split("$")))
        for x in multihex:
            if "HEX[" in x:
                endhex = x.find("]")
                byte_data = bytes.fromhex(x[4:endhex])
                result = chardet.detect(byte_data)
                encoding = result['encoding'] or 'utf-8'
                try:
                    decoded.append(byte_data.decode(encoding))
                except:
                    decoded.append(x)
            else:
                decoded.append(x)
        if decoded:
            pwd = ''.join(decoded)
    return pwd



def generate_pdfs_from_markdown(markdown_folder, pdf_folder):
    """Convert all Markdown files in the output folder to PDFs in landscape orientation with adjusted styling, centered PNGs, and watermarks."""
    # Detect if there are any Markdown files in the output folder
    if not any(markdown_folder.glob('*.md')):
        print("No Markdown files found in the output folder.")
        return

    # Create the pdf_folder if it doesn’t exist
    os.makedirs(pdf_folder, exist_ok=True)

    for md_file in markdown_folder.glob('*.md'):
        pdf_file = pdf_folder / f"{md_file.stem}.pdf"

        # Convert Markdown to HTML
        with open(md_file, 'r', encoding='utf-8') as f:
            md_content = f.read()
        html_content = markdown.markdown(md_content, extensions=['tables'])  # Enable table rendering
        # Enhanced CSS for landscape, tight margins, proper tables, centered PNGs, and watermarks
        html_with_style = f"""
        <html>
        <head>
            <style>
                @page {{
                    size: landscape;
                    margin: 0.5in;
                    @top-center {{
                        content: "INTERNAL USE ONLY - CONFIDENTIAL";
                        font-family: Arial, sans-serif;
                        font-size: 10pt;
                        color: #777;
                    }}
                    @bottom-center {{
                        content: "INTERNAL USE ONLY - CONFIDENTIAL";
                        font-family: Arial, sans-serif;
                        font-size: 10pt;
                        color: #777;
                    }}
                }}
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 0.5in; }}
                h1 {{ color: #2c3e50; font-size: 24pt; margin-bottom: 10pt; }}
                h2 {{ color: #34495e; font-size: 18pt; margin-bottom: 8pt; }}
                table {{ border-collapse: collapse; width: 100%; font-size: 10pt; }}
                th, td {{ border: 1px solid #333; padding: 6px; text-align: left; word-wrap: break-word; max-width: 200px; }}
                th {{ background-color: #e0e0e0; font-weight: bold; }}
                td {{ vertical-align: top; }}
                img {{ max-width: 100%; height: auto; display: block; margin: 0 auto; }} /* Center PNGs */
            </style>
        </head>
        <body>{html_content}</body>
        </html>
        """
        # Generate PDF with landscape orientation
        HTML(string=html_with_style).write_pdf(pdf_file, stylesheets=[CSS(string='@page { size: landscape; }')])
        print(f"Generated PDF: {pdf_file}")