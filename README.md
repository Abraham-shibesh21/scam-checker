# 🛡️ Scam Checker

**Upload a screenshot of a suspicious text, email, or message and get a plain-language answer: is it a scam, why, and what to do next.**

Built at **Hack for Humanity × Hacktoberfest 2026, Silver Spring** (AI Collective Maryland), using **Gemma 4**, Google DeepMind's open-weight model.

## The problem
Scam texts and emails ("Your bank account is locked", fake job offers, fake delivery fees, romance scams) hit everyone, but they hurt seniors and new immigrants the most. Many people don't know which red flags to look for, and English may not be their first language.

## What it does
1. Upload a screenshot or paste the message.
2. **Gemma 4** reads the image and text the way a fraud analyst would.
3. You get:
   - A clear verdict: 🚨 **SCAM**, ⚠️ **SUSPICIOUS**, ✅ **LIKELY SAFE**, or ❔ **NOT ENOUGH INFORMATION**
   - A level of concern: **Low**, **Medium**, or **High** (low concern is not a guarantee of safety)
   - **Why:** step-by-step reasoning that points to the exact words, links, or sender
   - Warning signs, each with an explanation of why scammers do it, plus signs it looks normal
   - Simple next steps (never "click the link")
4. **"I already clicked or paid":** pick what happened (replied, clicked, installed, entered a password, shared info, or sent money) and get prioritized recovery steps, tailored to the type of scam in your screenshot.
5. Answers in **English, Amharic, Spanish, or French**.

## Safety by design
- A missing or broken AI answer is **never** shown as "Likely safe."
- Screenshots and pasted messages are treated as untrusted evidence, never as instructions to the AI.
- Links quoted from scams are broken (`hxxp://bad[.]co`) so they can't be clicked by accident.
- Recovery steps come from a reviewed list, not invented by the AI, and never promise that money will come back.
- Nothing is saved. Note: what you check is sent to Google's Gemini API. On the free tier, Google may use it to improve its products, so avoid sharing screenshots with personal details like account numbers.

## Built with
- **Gemma 4** (`gemma-4-26b-a4b-it`), Google DeepMind's open-weight multimodal model, via the Gemini API
- **Streamlit** for the web app
- **Pillow** for image handling

## Run it locally
```bash
git clone https://github.com/<your-username>/scam-checker.git
cd scam-checker
python -m venv venv
source venv/Scripts/activate      # Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
export GEMINI_API_KEY="your-key"  # or paste it in the app sidebar
streamlit run app.py
```
Get a free API key at [aistudio.google.com](https://aistudio.google.com).

## What's next
A phone app: take a screenshot, tap **Share → Scam Checker**, and get the answer, with no inbox access needed.

## Disclaimer
This tool gives guidance, not a guarantee. When in doubt, contact your bank or the company directly using a number you trust. Report scams at [ReportFraud.ftc.gov](https://reportfraud.ftc.gov).

## License
MIT. See [LICENSE](LICENSE).
