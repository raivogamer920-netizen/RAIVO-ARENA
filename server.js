
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "db.json");

if (!ADMIN_PASSWORD || !JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Set ADMIN_PASSWORD and JWT_SECRET (at least 32 characters).");
  process.exit(1);
}

const emptyDB = () => ({
  users: [],
  matches: [],
  modes: [],
  requests: []
});

let db = emptyDB();
let saveQueue = Promise.resolve();

async function loadDB() {
  try {
    db = JSON.parse(await fs.promises.readFile(DATA_FILE, "utf8"));
    for (const key of ["users", "matches", "modes", "requests"]) {
      if (!Array.isArray(db[key])) db[key] = [];
    }
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
    await saveDB();
  }
}

function saveDB() {
  const snapshot = JSON.stringify(db, null, 2);
  saveQueue = saveQueue.then(async () => {
    const temp = DATA_FILE + ".tmp";
    await fs.promises.mkdir(path.dirname(path.resolve(DATA_FILE)), {
      recursive: true
    });
    await fs.promises.writeFile(temp, snapshot, { mode: 0o600 });
    await fs.promises.rename(temp, DATA_FILE);
  });
  return saveQueue;
}

const send = (res, status, data) => {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  res.end(JSON.stringify(data));
};

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 100000) {
        reject(new Error("Request too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });
    req.on("error", reject);
  });
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function verifyPassword(password, stored) {
  const actual = hashPassword(password, stored.salt).hash;
  const a = Buffer.from(actual, "hex");
  const b = Buffer.from(stored.hash, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function makeToken(user) {
  const payload = Buffer.from(JSON.stringify({
    id: user.id,
    role: user.role,
    exp: Date.now() + 12 * 60 * 60 * 1000
  })).toString("base64url");

  const signature = crypto.createHmac("sha256", JWT_SECRET)
    .update(payload).digest("base64url");

  return payload + "." + signature;
}

function getAuth(req) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const expected = crypto.createHmac("sha256", JWT_SECRET)
    .update(parts[0]).digest();
  let supplied;
  try {
    supplied = Buffer.from(parts[1], "base64url");
  } catch {
    return null;
  }

  if (expected.length !== supplied.length ||
      !crypto.timingSafeEqual(expected, supplied)) return null;

  try {
    const payload = JSON.parse(
      Buffer.from(parts[0], "base64url").toString()
    );
    if (payload.exp < Date.now()) return null;

    if (payload.role === "admin" && payload.id === "admin") {
      return { id: "admin", role: "admin", username: ADMIN_USERNAME };
    }

    const user = db.users.find(u => u.id === payload.id);
    return user ? { id: user.id, role: "user", username: user.username } : null;
  } catch {
    return null;
  }
}

const cleanUser = u => ({
  id: u.id,
  username: u.username,
  coins: u.coins,
  createdAt: u.createdAt
});

function validName(s) {
  return typeof s === "string" &&
    /^[a-zA-Z0-9_-]{3,24}$/.test(s);
}

function publicMatch(m) {
  return {
    id: m.id,
    name: m.name,
    mode: m.mode,
    map: m.map,
    date: m.date,
    entryFee: m.entryFee,
    prize: m.prize,
    image: m.image,
    status: m.status
  };
}

async function handle(req, res) {
  const url = new URL(req.url, "http://localhost");
  const route = url.pathname;
  const method = req.method;
  const ip = req.socket.remoteAddress || "unknown";

  if (method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "600"
    });
    return res.end();
  }

  let body = {};
  if (!["GET", "HEAD"].includes(method)) {
    try {
      body = await readBody(req);
    } catch (e) {
      return send(res, 400, { error: e.message });
    }
  }

  // Login and registration are handled separately from protected routes.
  if (method === "POST" && route === "/api/register") {
    const { username, password } = body;

    if (!validName(username) || typeof password !== "string" ||
        password.length < 8 || password.length > 128) {
      return send(res, 400, {
        error: "Username must be 3-24 letters, digits, _ or -. Password must be 8-128 characters."
      });
    }

    if (username.toLowerCase() === ADMIN_USERNAME.toLowerCase() ||
        db.users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
      return send(res, 409, { error: "Username is unavailable" });
    }

    const pw = hashPassword(password);
    const user = {
      id: crypto.randomUUID(),
      username,
      password: pw,
      coins: 0,
      createdAt: new Date().toISOString()
    };

    db.users.push(user);
    await saveDB();
    return send(res, 201, {
      token: makeToken({ id: user.id, role: "user" }),
      user: cleanUser(user)
    });
  }

  if (method === "POST" && route === "/api/login") {
    const { username, password } = body;

    if (typeof username !== "string" || typeof password !== "string") {
      return send(res, 400, { error: "Enter username and password" });
    }

    // Only server environment variables can authenticate an admin.
    if (username === ADMIN_USERNAME &&
        crypto.timingSafeEqual(
          Buffer.from(crypto.createHash("sha256").update(password).digest()),
          Buffer.from(crypto.createHash("sha256").update(ADMIN_PASSWORD).digest())
        )) {
      return send(res, 200, {
        token: makeToken({ id: "admin", role: "admin" }),
        user: { id: "admin", username: ADMIN_USERNAME, role: "admin" }
      });
    }

    const user = db.users.find(
      u => u.username.toLowerCase() === username.toLowerCase()
    );

    if (!user || !verifyPassword(password, user.password)) {
      return send(res, 401, { error: "Invalid username or password" });
    }

    return send(res, 200, {
      token: makeToken({ id: user.id, role: "user" }),
      user: cleanUser(user)
    });
  }

  const auth = getAuth(req);

  if (route === "/api/health" && method === "GET") {
    return send(res, 200, { ok: true });
  }

  if (!auth) return send(res, 401, { error: "Please log in" });

  if (route === "/api/me" && method === "GET") {
    if (auth.role === "admin") {
      return send(res, 200, { user: { ...auth, role: "admin" } });
    }
    const user = db.users.find(u => u.id === auth.id);
    return send(res, 200, { user: cleanUser(user) });
  }

  if (route === "/api/matches" && method === "GET") {
    return send(res, 200, { matches: db.matches.map(publicMatch) });
  }

  if (route === "/api/modes" && method === "GET") {
    return send(res, 200, { modes: db.modes });
  }

  // All management endpoints require a real admin token.
  if (auth.role !== "admin") {
    if (method === "POST" && route === "/api/requests") {
      const { type, amount } = body;

      if (!["deposit", "withdraw"].includes(type) ||
          !Number.isSafeInteger(amount) || amount < 1 || amount > 1000000) {
        return send(res, 400, { error: "Invalid request" });
      }

      if (type === "withdraw") {
        const user = db.users.find(u => u.id === auth.id);
        if (user.coins < amount) {
          return send(res, 400, { error: "Insufficient coins" });
        }
      }

      const request = {
        id: crypto.randomUUID(),
        userId: auth.id,
        type,
        amount,
        status: "pending",
        createdAt: new Date().toISOString()
      };
      db.requests.push(request);
      await saveDB();
      return send(res, 201, { request });
    }

    if (method === "POST" && route === "/api/matches/join") {
      const user = db.users.find(u => u.id === auth.id);
      const match = db.matches.find(m => m.id === body.matchId);

      if (!match || match.status !== "open") {
        return send(res, 404, { error: "Match unavailable" });
      }
      if (!Number.isSafeInteger(match.entryFee) || match.entryFee < 0) {
        return send(res, 400, { error: "Invalid entry fee" });
      }
      if (user.coins < match.entryFee) {
        return send(res, 400, { error: "Insufficient coins" });
      }
      if (!Array.isArray(match.players)) match.players = [];
      if (match.players.includes(user.id)) {
        return send(res, 409, { error: "Already joined" });
      }

      user.coins -= match.entryFee;
      match.players.push(user.id);
      await saveDB();
      return send(res, 200, { message: "Joined match", coins: user.coins });
    }

    return send(res, 403, { error: "Admin access required" });
  }

  if (method === "GET" && route === "/api/admin/users") {
    return send(res, 200, { users: db.users.map(cleanUser) });
  }

  if (method === "GET" && route === "/api/admin/requests") {
    return send(res, 200, { requests: db.requests });
  }

  if (method === "POST" && route === "/api/admin/wallet") {
    const { userId, amount, reason } = body;
    const user = db.users.find(u => u.id === userId);

    if (!user || !Number.isSafeInteger(amount) || amount === 0 ||
        Math.abs(amount) > 1000000) {
      return send(res, 400, { error: "Invalid user or coin amount" });
    }
    if (user.coins + amount < 0) {
      return send(res, 400, { error: "Wallet cannot become negative" });
    }

    user.coins += amount;
    await saveDB();
    return send(res, 200, {
      message: "Wallet updated",
      user: cleanUser(user),
      reason: typeof reason === "string" ? reason.slice(0, 200) : ""
    });
  }

  if (method === "POST" && route === "/api/admin/requests/resolve") {
    const request = db.requests.find(r => r.id === body.requestId);
    if (!request || request.status !== "pending") {
      return send(res, 404, { error: "Pending request not found" });
    }

    if (!["approve", "reject"].includes(body.action)) {
      return send(res, 400, { error: "Invalid action" });
    }

    const user = db.users.find(u => u.id === request.userId);
    if (!user) return send(res, 404, { error: "User not found" });

    if (body.action === "approve") {
      if (request.type === "deposit") {
        user.coins += request.amount;
      } else {
        if (user.coins < request.amount) {
          return send(res, 400, { error: "User no longer has enough coins" });
        }
        user.coins -= request.amount;
      }
    }

    request.status = body.action === "approve" ? "approved" : "rejected";
    request.resolvedAt = new Date().toISOString();
    await saveDB();
    return send(res, 200, { request, user: cleanUser(user) });
  }

  if (method === "POST" && route === "/api/admin/matches") {
    const { name, mode, map, date, entryFee, prize, image } = body;
    if (typeof name !== "string" || !name.trim() || name.length > 100 ||
        !Number.isSafeInteger(entryFee) || entryFee < 0 ||
        !Number.isSafeInteger(prize) || prize < 0) {
      return send(res, 400, { error: "Enter valid match details" });
    }

    const match = {
      id: crypto.randomUUID(),
      name: name.trim(),
      mode: typeof mode === "string" ? mode.slice(0, 60) : "",
      map: typeof map === "string" ? map.slice(0, 60) : "",
      date: typeof date === "string" ? date.slice(0, 40) : "",
      entryFee,
      prize,
      image: typeof image === "string" && /^https:\/\/\S+$/i.test(image)
        ? image.slice(0, 1000) : "",
      status: "open",
      players: []
    };

    db.matches.push(match);
    await saveDB();
    return send(res, 201, { match: publicMatch(match) });
  }

  if (method === "DELETE" && route.startsWith("/api/admin/matches/")) {
    const id = route.slice("/api/admin/matches/".length);
    const before = db.matches.length;
    db.matches = db.matches.filter(m => m.id !== id);
    if (before === db.matches.length) {
      return send(res, 404, { error: "Match not found" });
    }
    await saveDB();
    return send(res, 200, { message: "Match deleted" });
  }

  if (method === "POST" && route === "/api/admin/modes") {
    const { name, image } = body;
    if (typeof name !== "string" || !name.trim() || name.length > 60) {
      return send(res, 400, { error: "Enter a valid mode name" });
    }
    const mode = {
      id: crypto.randomUUID(),
      name: name.trim(),
      image: typeof image === "string" && /^https:\/\/\S+$/i.test(image)
        ? image.slice(0, 1000) : ""
    };
    db.modes.push(mode);
    await saveDB();
    return send(res, 201, { mode });
  }

  if (method === "DELETE" && route.startsWith("/api/admin/modes/")) {
    const id = route.slice("/api/admin/modes/".length);
    const before = db.modes.length;
    db.modes = db.modes.filter(m => m.id !== id);
    if (before === db.modes.length) {
      return send(res, 404, { error: "Mode not found" });
    }
    await saveDB();
    return send(res, 200, { message: "Mode deleted" });
  }

  return send(res, 404, { error: "API route not found" });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://localhost");

    if (url.pathname.startsWith("/api/")) {
      return await handle(req, res);
    }

    const requested = decodeURIComponent(url.pathname);
    const relative = requested === "/" ? "index.html" : requested.slice(1);
    const file = path.resolve(__dirname, relative);

    if (file !== path.join(__dirname, "index.html") &&
        !file.startsWith(path.resolve(__dirname) + path.sep)) {
      return send(res, 403, { error: "Forbidden" });
    }

    const stat = await fs.promises.stat(file);
    if (!stat.isFile()) throw new Error("Not a file");

    const types = {
      ".html": "text/html; charset=utf-8",
      ".css": "text/css; charset=utf-8",
      ".js": "text/javascript; charset=utf-8",
      ".json": "application/json; charset=utf-8",
      ".png": "image/png",
      ".jpg": "image/jpeg",
      ".jpeg": "image/jpeg",
      ".svg": "image/svg+xml",
      ".webp": "image/webp"
    };

    res.writeHead(200, {
      "Content-Type": types[path.extname(file)] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff"
    });
    fs.createReadStream(file).pipe(res);
  } catch (e) {
    if (!res.headersSent) send(res, 404, { error: "File or route not found" });
    else res.destroy();
  }
});

loadDB().then(() => {
  server.listen(PORT, "0.0.0.0", () => {
    console.log(`RAIVO-ARENA listening on port ${PORT}`);
  });
}).catch(err => {
  console.error("Failed to load database:", err);
  process.exit(1);
});
