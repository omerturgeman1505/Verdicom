# threat-Mobileye-dashboard

## Run locally

1. Create and activate a virtual environment:
   - PowerShell: `.\.venv\Scripts\Activate.ps1`
2. Install dependencies:
   - `pip install -r requirements.txt`
3. Create `.env` from `.env.example` and set your API keys.
4. Run:
   - `flask --app app.py --debug run`

## Deploy to Render

This repository includes `render.yaml` for one-click deployment.

1. Push this project to GitHub.
2. In Render, create a new Blueprint service from your repository.
3. Set environment variables in Render:
   - `VT_API_KEY`
   - `ABUSEIPDB_API_KEY`
   - `RAPIDAPI_KEY`
4. Deploy.

Render uses:
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --bind 0.0.0.0:$PORT`