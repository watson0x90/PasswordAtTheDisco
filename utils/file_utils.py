# utils/file_utils.py
"""
File utility functions for the password audit tool.
Provides functions for loading and manipulating files.
"""

import os
import chardet
from pathlib import Path

# Optional imports for PDF generation (not required for HTML generation)
try:
    import markdown
    from weasyprint import HTML, CSS
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False

def load_list(file_path: str) -> set:
    """
    Load a file into a set of strings, line by line.
    
    Args:
        file_path (str): Path to the file
        
    Returns:
        set: Set of lines from the file
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        return set(line.strip().lower() for line in f)

def decode_hex(password: str) -> str:
    """
    Decode hexadecimal encoded passwords.
    
    Args:
        password (str): Potentially hex-encoded password
        
    Returns:
        str: Decoded password
    """
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

def generate_pdfs_from_markdown(markdown_folder: Path, pdf_folder: Path) -> None:
    """
    Convert all Markdown files in the output folder to PDFs.

    Args:
        markdown_folder (Path): Folder containing Markdown files
        pdf_folder (Path): Folder for output PDFs
    """
    if not PDF_SUPPORT:
        print("PDF generation not available (markdown and weasyprint modules not installed)")
        return

    # Detect if there are any Markdown files in the output folder
    if not any(markdown_folder.glob('*.md')):
        print("No Markdown files found in the output folder.")
        return

    # Create the pdf_folder if it doesn't exist
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

def ensure_directory(directory: str) -> None:
    """
    Ensure a directory exists, creating it if necessary.
    
    Args:
        directory (str): Directory path
    """
    os.makedirs(directory, exist_ok=True)

def safe_filename(filename: str) -> str:
    """
    Convert a string to a safe filename.
    
    Args:
        filename (str): Original filename
        
    Returns:
        str: Safe filename
    """
    # Remove or replace invalid filename characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Limit length to avoid path limitations
    max_length = 255
    if len(filename) > max_length:
        name, ext = os.path.splitext(filename)
        name = name[:max_length - len(ext)]
        filename = name + ext
    
    return filename

def get_file_size(file_path: str) -> int:
    """
    Get file size in bytes.
    
    Args:
        file_path (str): Path to the file
        
    Returns:
        int: File size in bytes
    """
    return os.path.getsize(file_path)

def list_files(directory: str, extension: str = None) -> list:
    """
    List files in a directory, optionally filtered by extension.
    
    Args:
        directory (str): Directory to list files from
        extension (str, optional): File extension filter
        
    Returns:
        list: List of file paths
    """
    file_list = []
    
    for root, _, files in os.walk(directory):
        for file in files:
            if extension is None or file.endswith(extension):
                file_list.append(os.path.join(root, file))
    
    return file_list

def read_file_chunks(file_path: str, chunk_size: int = 8192) -> bytes:
    """
    Generator to read a file in chunks.
    
    Args:
        file_path (str): Path to the file
        chunk_size (int, optional): Size of each chunk in bytes
        
    Yields:
        bytes: File chunk
    """
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk

def write_text_file(file_path: str, content: str, encoding: str = 'utf-8') -> None:
    """
    Write text content to a file.
    
    Args:
        file_path (str): Path to the file
        content (str): Content to write
        encoding (str, optional): File encoding
    """
    with open(file_path, 'w', encoding=encoding) as f:
        f.write(content)