# Deploying the proxy with GitHub Pages + Render

## 1. Put these files in one GitHub repository

Keep `web-proxy.html`, `Proxy.js`, `Fullproxy.js`, `blocklist.txt`, `package.json`, and `render.yaml` in the repository root.

## 2. Deploy the Node.js backend on Render

1. Create a Render account and choose **New > Blueprint** (or create a Web Service from this repository).
2. Select this repository. Render detects `render.yaml`.
3. Set these environment variables in the Render service:
   - `FRONTEND_ORIGIN`: the exact GitHub Pages origin, e.g. `https://YOURNAME.github.io` (no repository path and no trailing slash).
   - `PROXY_USER`: choose a username.
   - `PROXY_PASS`: choose a long, unique password.
4. Deploy and copy the backend URL, e.g. `https://my-web-proxy-backend.onrender.com`.

Do not publish your backend credentials in GitHub. The app's HTTP Basic Authentication protects the backend; use a unique password and do not share the backend URL/password publicly. A free hosting plan may sleep when idle, so the first request can be slow.

## 3. Publish the frontend on GitHub Pages

GitHub Pages serves a file named `index.html` from the selected publishing source. Make a copy of `web-proxy.html` named `index.html` in the repository root (or rename it to `index.html`). Enable Pages in **Settings > Pages** and publish from your chosen branch/root.

## 4. Connect the frontend to the backend

Open your GitHub Pages URL. Expand **Settings** in the proxy UI, paste the Render URL into **Backend URL**, and leave Relay set to **Your Node.js backend (/fetch)**. Enter a site and choose Full proxy or Snapshot.

## Notes and limitations

- The frontend and backend are on different origins. `FRONTEND_ORIGIN` must exactly match the GitHub Pages origin for Snapshot mode's browser fetches to pass CORS.
- Full proxy mode uses the backend in an iframe. Some games and sites may still fail because they depend on anti-bot checks, WebRTC, strict origin checks, DRM, service workers, or browser features that a rewriting proxy cannot transparently reproduce.
- This is a web-page proxy, not a system-wide browser proxy. It does not configure your computer's network proxy settings.
- Keep the backend private to people you trust. A public proxy can be abused, incur hosting costs, or be used to attack other services. The backend blocks private/local IP ranges by default; do not enable `ALLOW_PRIVATE=1` on a public deployment.
