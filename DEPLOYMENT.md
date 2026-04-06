# Deployment Guide

## 🚀 Quick Deployment

This project is ready for deployment on free tiers of **Render** (Backend) and **Vercel** (Frontend).

---

## Backend Deployment (Render)

### Prerequisites
- Render account: https://render.com/
- GitHub repository connected

### Step 1: Deploy on Render
1. Go to https://dashboard.render.com/
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub repository (`vikashni28/rx-mortem`)
4. Configure:
   - **Name:** `rx-mortem-api`
   - **Environment:** Python 3.11
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python -m uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
   - **Plan:** Free (auto-sleeps after 15 min inactivity)

### Step 2: Get Your API URL
After deployment succeeds, you'll get a URL like:
```
https://rx-mortem-api.onrender.com
```

### Step 3: Enable Auto-Deploy
- Go to **Settings** → Check "Auto-Deploy"
- Now every push to `main` branch auto-deploys

---

## Frontend Deployment (Vercel)

### Prerequisites
- Vercel account: https://vercel.com/
- GitHub account connected

### Step 1: Deploy on Vercel
1. Go to https://vercel.com/dashboard
2. Click **"Add New..."** → **"Project"**
3. Import your GitHub repository (`vikashni28/rx-mortem`)
4. Configure:
   - **Framework:** Other
   - **Build Command:** Leave empty (static frontend)
   - **Output Directory:** `frontend`
   - **Root Directory:** `.` (project root)

### Step 2: Set Environment Variables
Click **Settings** → **Environment Variables**
```
REACT_APP_API_URL = https://rx-mortem-api.onrender.com
```

### Step 3: Deploy!
Click **Deploy** and wait ~1-2 minutes. You'll get a URL like:
```
https://rx-mortem.vercel.app
```

---

## 🔗 Connect Frontend to Backend

The frontend HTML file is configured to work with environment variables.

**Update in `frontend/rx-mortem.html`:**
Find the API endpoint configuration and update it:
```javascript
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
```

Alternatively, hardcode it temporarily:
```javascript
const API_URL = 'https://rx-mortem-api.onrender.com';
```

---

## ✅ Testing After Deployment

### Test Backend
```bash
curl https://rx-mortem-api.onrender.com/health
# Response: {"api": "ok", "model_loaded": true}
```

### Test Frontend
Visit: https://rx-mortem.vercel.app

### Test File Upload
Using curl:
```bash
curl -X POST https://rx-mortem-api.onrender.com/analyze \
  -F "file=@/path/to/binary.exe"
```

---

## 📊 Model Information

- **Training Samples:** 1,040,000 (from JSONL)
- **Test Samples:** 240,000
- **Accuracy:** 87.55%
- **ROC-AUC:** 0.9707
- **Model Size:** ~50MB (includes `rf_model.pkl` + `scaler.pkl`)

---

## 🔄 Continuous Deployment

### Auto-Deploy on Push
Both Render and Vercel support auto-deploy when you push to the main branch:

```bash
git add .
git commit -m "Update feature"
git push origin main
# ✅ Automatic deployment starts!
```

### Rollback
All deployments are versioned, you can rollback in:
- **Render:** Settings → Deployments → Select version
- **Vercel:** Deployments tab → Select version

---

## 🆓 Free Tier Limitations

### Render Free Tier
- Auto-sleeps after 15 min inactivity (cold starts)
- Limited to 750 dyno-hours/month
- No custom domains without upgrade

### Vercel Free Tier
- 100GB bandwidth/month
- Unlimited deployments
- Serverless deployments

### Workaround for Cold Starts
Add a simple health check to keep backend warm:
```javascript
// In frontend or external service
setInterval(() => {
  fetch('https://rx-mortem-api.onrender.com/health');
}, 600000); // Every 10 minutes
```

---

## 🔐 Security Notes

1. **Environment Variables:** Don't commit secrets to git
2. **API Rate Limiting:** Add rate limiting for production (middleware)
3. **CORS:** Update CORS policy in backend if needed
4. **Model Files:** Keep `rf_model.pkl` in git (necessary for inference)

---

## 📝 Additional Commands

### Monitor Backend Logs (Render)
```
Render Dashboard → rx-mortem-api → Logs
```

### Monitor Frontend (Vercel)
```
Vercel Dashboard → rx-mortem → Analytics
```

### Force Redeploy
```bash
# Render: Click "Deploy" in dashboard
# Vercel: Click "Redeploy" for specific deployment
```

---

## ❓ Troubleshooting

### Backend shows "Application failed to start"
- Check logs: `Render Dashboard → Logs`
- Verify `requirements.txt` has all dependencies
- Ensure no syntax errors in `backend/main.py`

### Frontend can't connect to backend
- Check CORS is enabled in `backend/main.py`
- Verify API URL is correct
- Check network tab in browser dev tools

### Model files not found
- Ensure `ml/model/rf_model.pkl` is committed to git
- Check file paths in `config/settings.py`

---

**Status:** ✅ Ready for production
**Repository:** https://github.com/vikashni28/rx-mortem
