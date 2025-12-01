ELEVATE: Intelligent Linux Privilege Escalation Auditor






📌 Abstract

During penetration testing or CTF challenges, we often run into a common issue — tools like LinPEAS dump a huge amount of system information, and most of it isn’t immediately useful. ELEVATE is a lightweight Python script I built to reduce this noise and highlight only the points that actually matter for privilege escalation.

Instead of listing everything, the script analyses the results and assigns a score to each finding based on impact and how easily it can be exploited, helping the user focus only on the most promising paths to root.

🚀 Key Features

Ranked Findings: Every result is scored on a scale of 1–10 based on risk and exploitability.

Minimal Noise: The script filters out the generic system info and highlights only real escalation vectors.

Practical Output: Each important finding includes simple, ready-to-use commands for attempting the escalation.

Modular Checks: Covers SUID binaries, file capabilities, sudo misconfigurations, kernel issues and more.

No External Dependencies: Uses only core Python libraries (os, subprocess) so it works on almost any Linux system.

🆚 How ELEVATE Differs From Traditional Tools
Metric	ELEVATE	Traditional Scripts (e.g., LinPEAS)
Approach	Focuses on prioritising findings	Collects everything without ranking
Output Size	Around 25–50 lines	Often 2000+ lines
Time to Spot a Vulnerability	Within seconds	Requires manual review
Accuracy	Consistently highlights high-probability vectors	No scoring mechanism
Ease of Use	Clear and guided output	Raw technical dump
🛠️ Installation & Usage

ELEVATE is a single Python file and does not require any setup. You can simply transfer it to the target machine using scp, wget, or curl.

# 1. Clone or download the script
git clone https://github.com/YOUR_USERNAME/Linux-PrivEsc-Elevate.git
cd Linux-PrivEsc-Elevate

# 2. Make the script executable
chmod +x elevate.py

# 3. Run the tool
python3 elevate.py
