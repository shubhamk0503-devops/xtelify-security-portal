# Deployment & Large Dataset Optimization Guide

This portal is a full-stack DevSecOps vulnerability management platform built with **React 19, Tailwind CSS, TypeScript, Express, and Vite**.

---

## 1. Fast Deploy Options

### Option A: AI Studio Direct Cloud Run (Active)
Your application is built and actively running on Google Cloud Run:
- **Dev URL:** `https://ais-dev-vbinswjbibvkis5lgftm3o-733621303036.asia-southeast1.run.app`
- **Shared / Preview URL:** `https://ais-pre-vbinswjbibvkis5lgftm3o-733621303036.asia-southeast1.run.app`

---

### Option B: Docker Container (Any Cloud / On-Prem)
A production multi-stage `Dockerfile` is included in the root directory.

#### 1. Build the Docker Image
```bash
docker build -t devsecops-portal:latest .
```

#### 2. Run Locally or on a Server
```bash
docker run -d \
  -p 3000:3000 \
  -e PORT=3000 \
  -e NODE_ENV=production \
  --name security-portal \
  devsecops-portal:latest
```
Access at `http://localhost:3000`.

---

### Option C: Deploying to Google Cloud Run (CLI)
```bash
# 1. Build and submit to Artifact Registry or Container Registry
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/devsecops-portal:latest

# 2. Deploy service
gcloud run deploy devsecops-portal \
  --image gcr.io/YOUR_PROJECT_ID/devsecops-portal:latest \
  --platform managed \
  --region asia-southeast1 \
  --allow-unauthenticated \
  --port 3000 \
  --memory 2Gi \
  --cpu 2
```

---

### Option D: Kubernetes / EKS / GKE Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: devsecops-portal
  labels:
    app: devsecops-portal
spec:
  replicas: 2
  selector:
    matchLabels:
      app: devsecops-portal
  template:
    metadata:
      labels:
        app: devsecops-portal
    spec:
      containers:
      - name: devsecops-portal
        image: your-registry/devsecops-portal:latest
        ports:
        - containerPort: 3000
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        env:
        - name: NODE_ENV
          value: "production"
        - name: PORT
          value: "3000"
---
apiVersion: v1
kind: Service
metadata:
  name: devsecops-portal-service
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 3000
  selector:
    app: devsecops-portal
```

---

## 2. Optimizations Implemented for Large Datasets (50,000 to 500,000+ Rows)

### 1. High-Performance Single-Pass Filter Engine
- **Old Approach:** Cloned the entire dataset `[...allIssues]` on every HTTP request and performed 8 consecutive `.filter()` passes, creating 8 intermediary arrays and causing high garbage collection spikes.
- **Optimized Engine (`server.ts`):** Implemented an early-exit single-pass loop with indexed `Set` lookups for batches and sub-types. Evaluates criteria in a single scan with `O(N)` complexity and zero redundant array allocations.

### 2. HTTP Streaming for Massive CSV Exports (`/api/export-massive?format=csv`)
- Instead of serializing a 100MB+ JSON object in RAM, the `/api/export-massive` endpoint streams CSV rows directly to `res.write()` in real-time, preventing Node.js out-of-memory crashes on enterprise-grade dataset downloads.

### 3. Ingestion Capacity & Multi-Sheet Detection
- Upload limit raised to **100MB** (`multer` and `express.json({ limit: "100mb" })`).
- SheetJS parser scans all workbook sheets and automatically detects raw vulnerability records versus pivot tables/summary sheets.

### 4. Presentation Mode for Management Meetings
- One-click toggle in the top navigation (`Presentation Mode` or press `Esc`).
- Hides operational clutter (filter sidebars, overdue alerts, deep search modals, column reorder pickers).
- Focuses strictly on core KPIs: Composite Posture Grade, Attack Vector Distribution, SLA Ageing, and POD Accountability.

---

## 3. Recommended Next-Step Scaling for 1M+ Records

When moving beyond 500,000 rows into multi-million record enterprise scans:
1. **Persistent Relational DB:** Offload in-memory array storage to PostgreSQL or Cloud SQL using Drizzle/Prisma ORM with B-Tree indexes on `Severity`, `Status`, `UploadBatch`, and `DueDate`.
2. **Server-Side Cursor Pagination:** Use keyset pagination (`WHERE id > last_seen_id LIMIT 100`) instead of offset-based pagination.
3. **Redis Cache Layer:** Cache `/api/executive-briefing` and `/api/db/summary` aggregate counts with a 5-minute TTL or upload-triggered cache invalidation.
