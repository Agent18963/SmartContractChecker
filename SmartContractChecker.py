# PROJECT BY STUDENTS FROM ST MARYS HIGHSCHOOL MUHAISNAH DONE BY HASAN, KENNETH AND OMAR

# Check GeminiAI.py for more library downloads
# Download all the necessary libraries
import re
import customtkinter as ctk
from tkinter import filedialog, messagebox
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from GeminiAI import Gemini_AI

# Initialize AI
model_name = "gemini-1.5-flash-8b-latest"
ai = Gemini_AI(model_name=model_name)


def create_response(ai_input):
    ai_input += "Explain all of these terms. without any bold texts or markdowns or rich text but make it numbered and spaced evenly"
    ai_response = ai.generate_response(ai_input)
    return ai_response.text


def load_contract_code(filename):
    try:
        with open(filename, 'r') as file:
            return file.read()
    except FileNotFoundError:
        messagebox.showerror("Error", f"File {filename} not found.")
        return None

def detect_etherlock(code):
    """Detects if contract has etherlock vulnerability (missing withdrawal function)."""
    return "withdraw" not in code

def detect_reentrancy(code):
    """Detects if contract is vulnerable to reentrancy."""
    reentrancy_patterns = [r"call\{value:\s*.*\}\s*\(\)", r"send\(", r"transfer\("]
    return any(re.search(pattern, code) for pattern in reentrancy_patterns)

def detect_assertion_failure(code):
    """Detects assertion failures that are unchecked or potentially unsafe."""
    return "assert(" in code

def detect_block_dependency(code):
    """Detects block dependency vulnerabilities like using block.timestamp or block.number."""
    block_patterns = [r"block\.timestamp", r"block\.number", r"block\.hash"]
    return any(re.search(pattern, code) for pattern in block_patterns)

def detect_integer_overflow_underflow(code):
    """Detects potential integer overflow or underflow vulnerabilities."""
    return any(op in code for op in ["+", "-", "*", "/"]) and "SafeMath" not in code

def analyze_contract(code):
    return {
        "etherlock": detect_etherlock(code),
        "reentrancy": detect_reentrancy(code),
        "assertion_failure": detect_assertion_failure(code),
        "block_dependency": detect_block_dependency(code),
        "integer_overflow_underflow": detect_integer_overflow_underflow(code)
    }


def generate_audit_report(vulnerabilities, filename):
    '''Generates an Audit report about the solidity code's vulnerabilities'''
    report = f"Audit Report for {filename}\n" + "-" * 40 + "\n"
    for vuln, detected in vulnerabilities.items():
        report += f"{vuln.replace('_', ' ').title()}: {'Detected' if detected else 'Not Detected'}\n"
    return report


def generate_pdf_report(report, filename):
    pdf_filename = filename.replace('.sol', '_audit_report.pdf')
    c = canvas.Canvas(pdf_filename, pagesize=letter)

    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 750, "Smart Contract Audit Report")

    c.setFont("Helvetica", 12)
    text = c.beginText(100, 720)

    for line in report.splitlines():
        text.textLine(line)

    c.drawText(text)
    c.showPage()
    c.save()
    messagebox.showinfo("PDF Report", f"PDF report generated: {pdf_filename}")


def select_file():
    filename = filedialog.askopenfilename(filetypes=[("Solidity Files", "*.sol")])
    if filename:
        contract_code = load_contract_code(filename)
        if contract_code:
            vulnerabilities = analyze_contract(contract_code)
            report = generate_audit_report(vulnerabilities, filename)
            audit_report_box.delete("1.0", ctk.END)
            audit_report_box.insert(ctk.END, report)
            ai_report = create_response(report)
            audit_report_box.insert(ctk.END, ai_report)


# GUI application
ctk.set_appearance_mode("dark")  # Optional: Set appearance mode to dark
ctk.set_default_color_theme("blue")  # Optional: Set default color theme

app = ctk.CTk()  # Use CTk for the main window
app.title("Simple Smart Contract Vulnerability Checker")
app.geometry("900x700")

# UI Components
label1 = ctk.CTkLabel(app, text="Smart Contract Vulnerability Checker", font=("Arial", 30))
label1.pack(pady=10)

# Create a styled button using CTk
select_file_button = ctk.CTkButton(app, text="Select Solidity File", command=select_file,
                                   fg_color="#007BFF", hover_color="#0056b3", width=130, height=40)
select_file_button.pack(pady=10)  # Use pack with pad y for vertical spacing

# Create a styled text box
audit_report_box = ctk.CTkTextbox(app, font=('Arial', 17), wrap=ctk.WORD, width=850, height=600)
audit_report_box.pack(pady=20)

app.mainloop()
