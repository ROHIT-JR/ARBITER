# ARBITER dashboard

A small React + TypeScript (Vite) front end for the ARBITER API. It lets you:

- run a session under any scenario and backend,
- see the layered verdict and attribution posterior,
- watch the sequential log-evidence trajectory,
- resubmit a transcript verbatim (to demonstrate classical replay),
- inspect and verify the audit ledger, and
- compare against the information-theoretic limits.

It uses no UI or chart libraries. The chart is plain SVG, and colours follow the system light/dark theme.

## Run

Start the API from the repository root:

```bash
uvicorn --factory arbiter.api.app:create_app --port 8000
```

Then start the dashboard:

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

The dev and preview servers proxy `/api/*` to `http://127.0.0.1:8000`. Set `ARBITER_API` to point at another backend. For a production bundle, run `npm run build` (the output goes to `dist/`), and use `npm run preview` to serve it locally with the same proxy.

## Layout

```
src/
  api.ts                  typed client + response types
  App.tsx                 page layout and state
  components/
    SessionForm.tsx       scenario / θ / rounds / backend / seed
    VerdictPanel.tsx      decision, posterior bars, per-layer results
    EvidenceChart.tsx     sequential e-process trajectory (SVG)
    LedgerPanel.tsx       recent entries + chain verification
    BoundsTable.tsx       quantum vs achieved Chernoff exponents
  styles.css              theme tokens (light + dark)
```
