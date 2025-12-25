import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox
from docx import Document
from PyPDF2 import PdfReader
import PyPDF2


class DocLinkExtractor:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Document link extractor")

        # Creating Title Label
        tk.Label(self.window, text="Document link extractor", font=("Helvetica", 24)).pack()

        # Creating Description Label
        tk.Label(self.window,
                 text="Load a PDF or Doc file and this tool will retrieve all the hyperlinks and sources then copy them to clipboard.",
                 font=("Helvetica", 14)).pack()

        # Creating Button for file selection
        tk.Button(self.window, text="Select File", command=self._get_file).pack()

        # Create a frame for the text area and scrollbar
        self.text_frame = tk.Frame(self.window)
        self.text_frame.pack()

        self.text_area = tk.Text(self.text_frame, wrap='none')  # Disable text wrapping
        self.text_area.pack(side="left", fill="both", expand=True)

        # Create a scrollbar and pack it into the frame
        self.scrollbar = tk.Scrollbar(self.text_frame, command=self.text_area.yview)
        self.scrollbar.pack(side="right", fill="y")

        # Link the scrollbar and the text area
        self.text_area['yscrollcommand'] = self.scrollbar.set

        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )

    def run(self):
        self.window.mainloop()

    def _get_file(self):
        file_path = filedialog.askopenfilename(filetypes=[('PDF Files', '*.pdf'), ('Word Files', '*.docx')])
        if file_path:
            if file_path.endswith('.pdf'):
                self._extract_pdf_links(file_path)
            elif file_path.endswith('.docx'):
                self._extract_docx_links(file_path)
        else:
            messagebox.showerror("Error", "Unsupported file type. Please select a PDF or Word document.")

    def _extract_pdf_links(self, file_path):
        pdf_file = PyPDF2.PdfReader(file_path)
        links = []
        for page_num in range(len(pdf_file.pages)):
            page = pdf_file.pages[page_num]
            if '/Annots' in page:
                annotations = page['/Annots']
                for annotation in annotations:
                    a_entry = annotation.get_object().get('/A')
                    if isinstance(a_entry, PyPDF2.generic.DictionaryObject):
                        uri = a_entry.get('/URI')
                        if uri:
                            links.append(uri)
        self._display_links(links)

    def _extract_docx_links(self, file_path):
        doc = Document(file_path)
        links = []
        for rel in doc.part.rels.values():
            if "hyperlink" in rel.reltype:
                url = rel._target
                if url:
                    links.append(url)
        for para in doc.paragraphs:
            links.extend(re.findall(self.url_pattern, para.text))
        self._display_links(links)

    def _display_links(self, links):
        unique_links = list(set(links))
        for link in unique_links:
            self.text_area.insert(tk.END, link + '\n')
        self._copy_to_clipboard(unique_links)

    def _copy_to_clipboard(self, links):
        self.window.clipboard_clear()
        self.window.clipboard_append('\n'.join(links))
        messagebox.showinfo("Information", "Link extraction complete. Text copied to clipboard.")


if __name__ == "__main__":
    extractor = DocLinkExtractor()
    extractor.run()
