# Document Link Extractor

Document Link Extractor is a Python tool that extracts all hyperlinks from a given PDF or Word (docx) document and copies them to the clipboard. This tool is designed to assist in quickly retrieving sources and hyperlinks from documents.

## Features

- Extract hyperlinks from PDF and Word (docx) documents.
- Copy all extracted links to the clipboard.
- Display all unique links in a user-friendly GUI.
- Support for GUI-based file selection.

## Requirements

- Python 3.x
- tkinter
- docx
- PyPDF2

## Installation

1. Clone this repository.
2. Navigate to the cloned repository.
3. Install the required Python packages using pip:

```bash
pip install -r requirements.txt
```

## Usage
Run the Python script from the command line:
```bash
python main.py
```
The GUI of the application will open. Click the button to select a file (PDF or Word document), and the tool will automatically extract all hyperlinks, display them in the text area, and copy them to the clipboard.