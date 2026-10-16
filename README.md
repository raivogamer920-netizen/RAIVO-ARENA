# ArenaX

One Node server that serves the app (`index.html`) and its API (`/api/...`). No npm packages to install.

## Put it on GitHub
1. Create a new repository on github.com.
2. Upload these files to the top level: `server.js`, `package.json`, `index.html`, `.gitignore`, `README.md`.

## Run it on Render (gives you a web link)
1. render.com > New > Web Service > connect your GitHub repo.
2. Build command: `npm install`   Start command: `npm start`
3. Environment variables:
   - `ADMIN_PASSWORD` : your admin password (required, pick a long one)
   - `JWT_SECRET` : any long random text (required, keeps logins valid after restarts)
   - `ADMIN_USERNAME` : optional, default `admin`
   - `DATA_FILE` : `/var/data/db.json` (only if you add a Disk mounted at `/var/data`)
4. Open the Render link. Log in with the admin username and password.

## Important: saving data
Everything is saved in one file. Render's free plan wipes files on every restart or redeploy, so players and coins would be lost.
Before real use, add a Render Disk (paid) mounted at `/var/data` and set `DATA_FILE=/var/data/db.json`, or move to a database.

## Run on your computer
```
ADMIN_PASSWORD=yourpass node server.js
```
Open http://localhost:3000

## Hosting the page somewhere else
Add `<script>window.ARENAX_API="https://your-server-link"</script>` at the top of `index.html`, and set the env var `ALLOWED_ORIGIN` on the server to the page's address.
