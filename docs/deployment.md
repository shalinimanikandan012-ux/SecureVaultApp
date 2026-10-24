# Production Deployment & Hosting Architecture

## 1. Hosting Target Architecture

```text
[ Users (HTTPS) ] 
       │
       ▼
[ Frontend: Vercel / Cloudflare Pages / Static CDN ]
  - Vite Production React Build (SPA)
  - Strict Content-Security-Policy
       │
       ▼ (REST API / CORS)
[ Backend: Render / Railway / Google Cloud Run ]
  - Gunicorn WSGI HTTP Server (Python 3.11+)
  - Argon2id & Cryptography Libraries
       │
       ▼
[ Database: Managed PostgreSQL (Supabase / Neon / AWS RDS) ]
  - SSL Enforced (require sslmode=require)
  - Automated backups & schema migrations
```

---

## 2. Backend Deployment on Render

1. Create a new **Web Service** on [Render](https://render.com).
2. Connect your Git repository.
3. Configure settings:
   - **Environment**: `Python 3`
   - **Root Directory**: `backend`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn wsgi:app`
4. Set Environment Variables:
   - `FLASK_ENV`: `production`
   - `SECRET_KEY`: `<Generate random 64-char hex string>`
   - `DATABASE_URL`: `postgresql://<user>:<password>@<host>:5432/<dbname>?sslmode=require`
   - `FRONTEND_ORIGIN`: `https://your-app.vercel.app`

---

## 3. Frontend Deployment on Vercel

1. Create a new project on [Vercel](https://vercel.com).
2. Set Root Directory to `frontend`.
3. Framework Preset: `Vite`.
4. Build Command: `npm run build`.
5. Output Directory: `dist`.
6. Set Environment Variables:
   - `VITE_API_URL`: `https://your-backend.onrender.com`
