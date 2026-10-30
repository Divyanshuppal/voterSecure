VOTESECURE - CTBF-CS-07 HACKATHON DEMO

REQUIREMENTS
- Python 3.10+
- Windows / VS Code
- Internet is not required after Flask is installed.

SETUP (Windows PowerShell / VS Code terminal)
1. Open the VoteSecure folder.
2. Create a virtual environment:
   python -m venv venv
3. Activate it:
   .\venv\Scripts\Activate.ps1
   If using Command Prompt:
   venv\Scripts\activate
4. Install Flask:
   python -m pip install -r requirements.txt
5. Start the app:
   python app.py
6. Open:
   http://127.0.0.1:5000

DEMO STUDENT LOGIN
College ID: STU001
OTP: 123456
Other IDs: STU002 through STU010
Demo OTP for all: 123456

ADMIN LOGIN
Open http://127.0.0.1:5000/admin
Password: admin123

FEATURES
- Student demo login
- One vote per registered student
- Separate voter status and anonymous ballot tables
- One-time receipt token (only its SHA-256 hash is stored)
- Public receipt verification
- Public results
- Admin election open/close and candidate creation
- SHA-256 hash-linked audit log
- JSON APIs:
  /api/results
  /api/audit/verify

IMPORTANT LIMITATIONS
This is a local hackathon prototype, not a production election system.
OTP is fixed and displayed for demo purposes.
Admin password is a demo default.
The audit hash chain detects changes to records in the current database,
but a database administrator could rewrite the entire chain. It is not
a decentralized blockchain or proof of end-to-end election correctness.
The receipt confirms that a ballot record exists; it does not prove
that the vote was counted correctly in a coercion-resistant manner.
Use only mock voters and mock elections.
