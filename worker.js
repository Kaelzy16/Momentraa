/*
  MOMENTRA API — CLOUDFLARE WORKER
  Architecture:
  Event → Cup → SMP vs SMP → Foto
  Photo storage: GitHub
  Database: Cloudflare D1
  Payment: InstanPay
  Storage: NO R2
*/

const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Key",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: JSON_HEADERS
  });
}

function error(message, status = 400, extra = {}) {
  return json({
    success: false,
    error: message,
    ...extra
  }, status);
}

function ok(data = {}) {
  return json({
    success: true,
    ...data
  });
}

function now() {
  return new Date().toISOString();
}

function id(prefix = "") {
  return prefix + crypto.randomUUID();
}

function bearer(request) {
  const value = request.headers.get("Authorization") || "";
  if (!value.startsWith("Bearer ")) return null;
  return value.slice(7).trim();
}

async function sha256(text) {
  const data = new TextEncoder().encode(text);

  const hash = await crypto.subtle.digest(
    "SHA-256",
    data
  );

  return [...new Uint8Array(hash)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function base64urlEncode(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlDecode(value) {
  value = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  while (value.length % 4) {
    value += "=";
  }

  const binary = atob(value);

  return Uint8Array.from(
    binary,
    c => c.charCodeAt(0)
  );
}

async function hmacSign(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message)
  );

  return base64urlEncode(
    new Uint8Array(signature)
  );
}

async function createToken(env, user) {
  const payload = {
    id: user.id,
    email: user.email,
    role: user.role,
    exp: Date.now() + 1000 * 60 * 60 * 24 * 7
  };

  const encoded = base64urlEncode(
    new TextEncoder().encode(
      JSON.stringify(payload)
    )
  );

  const signature = await hmacSign(
    env.SESSION_SECRET || "momentra-session-secret",
    encoded
  );

  return encoded + "." + signature;
}

async function verifyToken(env, token) {
  if (!token) return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [encoded, signature] = parts;

  const expected = await hmacSign(
    env.SESSION_SECRET || "momentra-session-secret",
    encoded
  );

  if (signature !== expected) {
    return null;
  }

  try {
    const payload = JSON.parse(
      new TextDecoder().decode(
        base64urlDecode(encoded)
      )
    );

    if (!payload.exp || payload.exp < Date.now()) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

async function authUser(request, env) {
  const token = bearer(request);

  if (!token) return null;

  return await verifyToken(env, token);
}

async function requireAuth(request, env) {
  const user = await authUser(request, env);

  if (!user) {
    return {
      error: error("Unauthorized", 401)
    };
  }

  return {
    user
  };
}

async function requireAdmin(request, env) {
  const auth = await requireAuth(request, env);

  if (auth.error) {
    return auth;
  }

  if (auth.user.role !== "admin") {
    return {
      error: error("Admin access required", 403)
    };
  }

  return auth;
}

/* =========================================================
   DATABASE
========================================================= */

async function ensureSchema(env) {
  const db = env.DB;

  await db.batch([
    db.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL
      )
    `),

    db.prepare(`
      CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        location TEXT,
        description TEXT,
        created_at TEXT NOT NULL
      )
    `),

    db.prepare(`
      CREATE TABLE IF NOT EXISTS cups (
        id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        created_at TEXT NOT NULL
      )
    `),

    db.prepare(`
      CREATE TABLE IF NOT EXISTS matches (
        id TEXT PRIMARY KEY,
        cup_id TEXT NOT NULL,
        match_name TEXT,
        team_a TEXT,
        team_b TEXT,
        match_date TEXT,
        created_at TEXT NOT NULL
      )
    `),

    db.prepare(`
      CREATE TABLE IF NOT EXISTS photos (
        id TEXT PRIMARY KEY,
        match_id TEXT NOT NULL,
        title TEXT,
        photographer TEXT,
        price INTEGER NOT NULL DEFAULT 25000,
        r2_key TEXT,
        file_name TEXT,
        content_type TEXT,
        file_size INTEGER,
        image_url TEXT,
        original_path TEXT,
        preview_path TEXT,
        created_at TEXT NOT NULL
      )
    `),

    db.prepare(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
      )
    `),

    db.prepare(`
      CREATE TABLE IF NOT EXISTS transactions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        ref_id TEXT,
        txn_id TEXT,
        amount INTEGER NOT NULL DEFAULT 0,
        unique_amount INTEGER,
        fee INTEGER DEFAULT 0,
        net_amount INTEGER DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        payment_url TEXT,
        qris_string TEXT,
        expired_at TEXT,
        paid_at TEXT,
        created_at TEXT NOT NULL
      )
    `),

    db.prepare(`
      CREATE TABLE IF NOT EXISTS transaction_items (
        id TEXT PRIMARY KEY,
        transaction_id TEXT NOT NULL,
        photo_id TEXT NOT NULL,
        price INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
      )
    `),

    db.prepare(`
      CREATE TABLE IF NOT EXISTS payment_config (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        api_key TEXT,
        base_url TEXT,
        updated_at TEXT NOT NULL
      )
    `)
  ]);

  /*
    Compatibility columns for existing installations.
  */
  const columns = [
    ["photos", "image_url", "TEXT"],
    ["photos", "original_path", "TEXT"],
    ["photos", "preview_path", "TEXT"],
    ["photos", "r2_key", "TEXT"],
    ["transactions", "ref_id", "TEXT"],
    ["transactions", "txn_id", "TEXT"],
    ["transactions", "unique_amount", "INTEGER"],
    ["transactions", "fee", "INTEGER DEFAULT 0"],
    ["transactions", "net_amount", "INTEGER DEFAULT 0"],
    ["transactions", "payment_url", "TEXT"],
    ["transactions", "qris_string", "TEXT"],
    ["transactions", "expired_at", "TEXT"],
    ["transactions", "paid_at", "TEXT"]
  ];

  for (const [table, column, type] of columns) {
    try {
      await db.prepare(
        `ALTER TABLE ${table} ADD COLUMN ${column} ${type}`
      ).run();
    } catch {
      // Column already exists.
    }
  }
}

/* =========================================================
   AUTH — REGISTER
========================================================= */

async function register(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return error("Invalid JSON");
  }

  const name = String(body.name || "").trim();
  const email = String(body.email || "")
    .trim()
    .toLowerCase();

  const password = String(body.password || "");

  if (!name) {
    return error("Nama wajib diisi");
  }

  if (!email) {
    return error("Email wajib diisi");
  }

  if (!password || password.length < 6) {
    return error(
      "Password minimal 6 karakter"
    );
  }

  const existing = await env.DB
    .prepare(`
      SELECT id
      FROM users
      WHERE email = ?
      LIMIT 1
    `)
    .bind(email)
    .first();

  if (existing) {
    return error(
      "Email sudah terdaftar",
      409
    );
  }

  const userId = Date.now();
  const passwordHash = await sha256(password);

  await env.DB
    .prepare(`
      INSERT INTO users
      (
        id,
        name,
        email,
        password_hash,
        role,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `)
    .bind(
      userId,
      name,
      email,
      passwordHash,
      "user",
      now()
    )
    .run();

  return json({
    success: true,
    message: "Registrasi berhasil",
    user: {
      id: userId,
      name,
      email,
      role: "user"
    }
  }, 201);
}

/* =========================================================
   AUTH — LOGIN
========================================================= */

async function login(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return error("Invalid JSON");
  }

  const email = String(body.email || "")
    .trim()
    .toLowerCase();

  const password = String(body.password || "");

  if (!email || !password) {
    return error(
      "Email dan password wajib diisi"
    );
  }

  const user = await env.DB
    .prepare(`
      SELECT
        id,
        name,
        email,
        password_hash,
        role,
        created_at
      FROM users
      WHERE email = ?
      LIMIT 1
    `)
    .bind(email)
    .first();

  if (!user) {
    return error(
      "Email atau password salah",
      401
    );
  }

  const passwordHash =
    await sha256(password);

  if (passwordHash !== user.password_hash) {
    return error(
      "Email atau password salah",
      401
    );
  }

  const token =
    await createToken(env, user);

  return json({
    success: true,
    token,
    access_token: token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      created_at: user.created_at
    }
  });
}

/* =========================================================
   AUTH — ME
========================================================= */

async function me(request, env) {
  const auth = await requireAuth(
    request,
    env
  );

  if (auth.error) {
    return auth.error;
  }

  const user = await env.DB
    .prepare(`
      SELECT
        id,
        name,
        email,
        role,
        created_at
      FROM users
      WHERE id = ?
      LIMIT 1
    `)
    .bind(auth.user.id)
    .first();

  if (!user) {
    return error(
      "User tidak ditemukan",
      404
    );
  }

  return ok({
    user
  });
}

/* =========================================================
   LOGOUT
========================================================= */

async function logout() {
  return ok({
    message: "Logout berhasil"
  });
}

/* =========================================================
   ADMIN — USERS
========================================================= */

async function adminUsers(request, env) {
  const auth = await requireAdmin(request, env);

  if (auth.error) {
    return auth.error;
  }

  const result = await env.DB
    .prepare(`
      SELECT
        id,
        name,
        email,
        role,
        created_at
      FROM users
      ORDER BY created_at DESC
    `)
    .all();

  return ok({
    users: result.results || []
  });
}

/* =========================================================
   ADMIN — DASHBOARD
========================================================= */

async function adminDashboard(request, env) {
  const auth = await requireAdmin(request, env);

  if (auth.error) {
    return auth.error;
  }

  const [
    users,
    events,
    cups,
    matches,
    photos,
    transactions
  ] = await Promise.all([
    env.DB.prepare(
      `SELECT COUNT(*) AS total FROM users`
    ).first(),

    env.DB.prepare(
      `SELECT COUNT(*) AS total FROM events`
    ).first(),

    env.DB.prepare(
      `SELECT COUNT(*) AS total FROM cups`
    ).first(),

    env.DB.prepare(
      `SELECT COUNT(*) AS total FROM matches`
    ).first(),

    env.DB.prepare(
      `SELECT COUNT(*) AS total FROM photos`
    ).first(),

    env.DB.prepare(
      `SELECT COUNT(*) AS total FROM transactions`
    ).first()
  ]);

  return ok({
    stats: {
      users: Number(users?.total || 0),
      events: Number(events?.total || 0),
      cups: Number(cups?.total || 0),
      matches: Number(matches?.total || 0),
      photos: Number(photos?.total || 0),
      transactions: Number(
        transactions?.total || 0
      )
    }
  });
}

/* =========================================================
   EVENTS
========================================================= */

async function adminEvents(request, env) {
  const auth = await requireAdmin(
    request,
    env
  );

  if (auth.error) {
    return auth.error;
  }

  if (request.method === "GET") {
    const result = await env.DB
      .prepare(`
        SELECT
          id,
          name,
          location,
          description,
          created_at
        FROM events
        ORDER BY created_at DESC
      `)
      .all();

    return ok({
      events: result.results || []
    });
  }

  if (request.method === "POST") {
    let body;

    try {
      body = await request.json();
    } catch {
      return error("Invalid JSON");
    }

    const name = String(
      body.name || ""
    ).trim();

    const location = String(
      body.location || ""
    ).trim();

    const description = String(
      body.description || ""
    ).trim();

    if (!name) {
      return error(
        "Nama event wajib diisi"
      );
    }

    const eventId = id("evt_");

    await env.DB
      .prepare(`
        INSERT INTO events
        (
          id,
          name,
          location,
          description,
          created_at
        )
        VALUES (?, ?, ?, ?, ?)
      `)
      .bind(
        eventId,
        name,
        location,
        description,
        now()
      )
      .run();

    return json({
      success: true,
      message: "Event berhasil dibuat",
      event: {
        id: eventId,
        name,
        location,
        description
      }
    }, 201);
  }

  if (request.method === "DELETE") {
    const url = new URL(request.url);
    const eventId =
      url.searchParams.get("id");

    if (!eventId) {
      return error(
        "Event ID wajib diisi"
      );
    }

    await env.DB
      .prepare(`
        DELETE FROM events
        WHERE id = ?
      `)
      .bind(eventId)
      .run();

    return ok({
      message: "Event berhasil dihapus"
    });
  }

  return error(
    "Method not allowed",
    405
  );
}

/* =========================================================
   CUPS
========================================================= */

async function adminCups(request, env) {
  const auth = await requireAdmin(
    request,
    env
  );

  if (auth.error) {
    return auth.error;
  }

  if (request.method === "GET") {
    const result = await env.DB
      .prepare(`
        SELECT
          c.id,
          c.event_id,
          c.name,
          c.description,
          c.created_at,
          e.name AS event_name
        FROM cups c
        LEFT JOIN events e
          ON e.id = c.event_id
        ORDER BY c.created_at DESC
      `)
      .all();

    return ok({
      cups: result.results || []
    });
  }

  if (request.method === "POST") {
    let body;

    try {
      body = await request.json();
    } catch {
      return error("Invalid JSON");
    }

    const eventId = String(
      body.event_id ||
      body.eventId ||
      ""
    ).trim();

    const name = String(
      body.name || ""
    ).trim();

    const description = String(
      body.description || ""
    ).trim();

    if (!eventId) {
      return error(
        "Event wajib dipilih"
      );
    }

    if (!name) {
      return error(
        "Nama cup wajib diisi"
      );
    }

    const event = await env.DB
      .prepare(`
        SELECT id
        FROM events
        WHERE id = ?
        LIMIT 1
      `)
      .bind(eventId)
      .first();

    if (!event) {
      return error(
        "Event tidak ditemukan",
        404
      );
    }

    const cupId = id("cup_");

    await env.DB
      .prepare(`
        INSERT INTO cups
        (
          id,
          event_id,
          name,
          description,
          created_at
        )
        VALUES (?, ?, ?, ?, ?)
      `)
      .bind(
        cupId,
        eventId,
        name,
        description,
        now()
      )
      .run();

    return json({
      success: true,
      message: "Cup berhasil dibuat",
      cup: {
        id: cupId,
        event_id: eventId,
        name,
        description
      }
    }, 201);
  }

  if (request.method === "DELETE") {
    const url = new URL(request.url);
    const cupId =
      url.searchParams.get("id");

    if (!cupId) {
      return error(
        "Cup ID wajib diisi"
      );
    }

    await env.DB
      .prepare(`
        DELETE FROM cups
        WHERE id = ?
      `)
      .bind(cupId)
      .run();

    return ok({
      message: "Cup berhasil dihapus"
    });
  }

  return error(
    "Method not allowed",
    405
  );
}

/* =========================================================
   MATCH / SMP VS SMP
========================================================= */

async function adminMatches(request, env) {
  const auth = await requireAdmin(
    request,
    env
  );

  if (auth.error) {
    return auth.error;
  }

  if (request.method === "GET") {
    const result = await env.DB
      .prepare(`
        SELECT
          m.id,
          m.cup_id,
          m.match_name,
          m.team_a,
          m.team_b,
          m.match_date,
          m.created_at,
          c.name AS cup_name,
          e.name AS event_name
        FROM matches m
        LEFT JOIN cups c
          ON c.id = m.cup_id
        LEFT JOIN events e
          ON e.id = c.event_id
        ORDER BY m.match_date DESC,
                 m.created_at DESC
      `)
      .all();

    return ok({
      matches: result.results || []
    });
  }

  if (request.method === "POST") {
    let body;

    try {
      body = await request.json();
    } catch {
      return error("Invalid JSON");
    }

    const cupId = String(
      body.cup_id ||
      body.cupId ||
      ""
    ).trim();

    const matchName = String(
      body.matchName ||
      body.match_name ||
      body.name ||
      ""
    ).trim();

    const teamA = String(
      body.teamA ||
      body.team_a ||
      ""
    ).trim();

    const teamB = String(
      body.teamB ||
      body.team_b ||
      ""
    ).trim();

    const matchDate = String(
      body.matchDate ||
      body.match_date ||
      ""
    ).trim();

    if (!cupId) {
      return error(
        "Cup wajib dipilih"
      );
    }

    if (!teamA) {
      return error(
        "SMP A wajib diisi"
      );
    }

    if (!teamB) {
      return error(
        "SMP B wajib diisi"
      );
    }

    const cup = await env.DB
      .prepare(`
        SELECT id
        FROM cups
        WHERE id = ?
        LIMIT 1
      `)
      .bind(cupId)
      .first();

    if (!cup) {
      return error(
        "Cup tidak ditemukan",
        404
      );
    }

    const matchId = id("match_");

    await env.DB
      .prepare(`
        INSERT INTO matches
        (
          id,
          cup_id,
          match_name,
          team_a,
          team_b,
          match_date,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        matchId,
        cupId,
        matchName ||
          `${teamA} vs ${teamB}`,
        teamA,
        teamB,
        matchDate || null,
        now()
      )
      .run();

    return json({
      success: true,
      message:
        "SMP vs SMP berhasil dibuat",
      match: {
        id: matchId,
        cup_id: cupId,
        match_name:
          matchName ||
          `${teamA} vs ${teamB}`,
        team_a: teamA,
        team_b: teamB,
        match_date: matchDate || null
      }
    }, 201);
  }

  if (request.method === "DELETE") {
    const url = new URL(request.url);

    const matchId =
      url.searchParams.get("id");

    if (!matchId) {
      return error(
        "Match ID wajib diisi"
      );
    }

    await env.DB
      .prepare(`
        DELETE FROM matches
        WHERE id = ?
      `)
      .bind(matchId)
      .run();

    return ok({
      message:
        "SMP vs SMP berhasil dihapus"
    });
  }

  return error(
    "Method not allowed",
    405
  );
}

/* =========================================================
   ADMIN — PHOTOS METADATA
   File sudah diupload ke GitHub oleh admin.html.
========================================================= */

async function adminPhotos(request, env) {
  const auth = await requireAdmin(
    request,
    env
  );

  if (auth.error) {
    return auth.error;
  }

  if (request.method === "GET") {
    const result = await env.DB
      .prepare(`
        SELECT
          p.*,
          m.match_name,
          m.team_a,
          m.team_b,
          c.name AS cup_name,
          e.name AS event_name
        FROM photos p
        LEFT JOIN matches m
          ON m.id = p.match_id
        LEFT JOIN cups c
          ON c.id = m.cup_id
        LEFT JOIN events e
          ON e.id = c.event_id
        ORDER BY p.created_at DESC
      `)
      .all();

    return ok({
      photos: result.results || []
    });
  }

  if (request.method === "POST") {
    let body;

    try {
      body = await request.json();
    } catch {
      return error("Invalid JSON");
    }

    const matchId = String(
      body.match_id ||
      body.matchId ||
      ""
    ).trim();

    const title = String(
      body.title || ""
    ).trim();

    const photographer = String(
      body.photographer || ""
    ).trim();

    const price = Number(
      body.price || 25000
    );

    const imageUrl = String(
      body.image_url ||
      body.imageUrl ||
      ""
    ).trim();

    const originalPath = String(
      body.original_path ||
      body.originalPath ||
      ""
    ).trim();

    const previewPath = String(
      body.preview_path ||
      body.previewPath ||
      ""
    ).trim();

    const fileName = String(
      body.file_name ||
      body.fileName ||
      ""
    ).trim();

    const contentType = String(
      body.content_type ||
      body.contentType ||
      "image/jpeg"
    ).trim();

    const fileSize = Number(
      body.file_size ||
      body.fileSize ||
      0
    );

    if (!matchId) {
      return error(
        "Match wajib dipilih"
      );
    }

    if (!originalPath) {
      return error(
        "Original path wajib diisi"
      );
    }

    if (!previewPath) {
      return error(
        "Preview path wajib diisi"
      );
    }

    if (!Number.isFinite(price) ||
        price < 0) {
      return error(
        "Harga tidak valid"
      );
    }

    const match = await env.DB
      .prepare(`
        SELECT id
        FROM matches
        WHERE id = ?
        LIMIT 1
      `)
      .bind(matchId)
      .first();

    if (!match) {
      return error(
        "Match tidak ditemukan",
        404
      );
    }

    const photoId = id("photo_");

    await env.DB
      .prepare(`
        INSERT INTO photos
        (
          id,
          match_id,
          title,
          photographer,
          price,
          r2_key,
          file_name,
          content_type,
          file_size,
          image_url,
          original_path,
          preview_path,
          created_at
        )
        VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        photoId,
        matchId,
        title,
        photographer,
        Math.round(price),
        originalPath,
        fileName,
        contentType,
        fileSize,
        imageUrl,
        originalPath,
        previewPath,
        now()
      )
      .run();

    return json({
      success: true,
      message:
        "Foto berhasil ditambahkan",
      photo: {
        id: photoId,
        match_id: matchId,
        title,
        photographer,
        price: Math.round(price),
        image_url: imageUrl,
        original_path: originalPath,
        preview_path: previewPath
      }
    }, 201);
  }

  if (request.method === "DELETE") {
    const url = new URL(request.url);

    const photoId =
      url.searchParams.get("id");

    if (!photoId) {
      return error(
        "Photo ID wajib diisi"
      );
    }

    await env.DB
      .prepare(`
        DELETE FROM photos
        WHERE id = ?
      `)
      .bind(photoId)
      .run();

    await env.DB
      .prepare(`
        DELETE FROM transaction_items
        WHERE photo_id = ?
      `)
      .bind(photoId)
      .run();

    return ok({
      message:
        "Foto berhasil dihapus"
    });
  }

  return error(
    "Method not allowed",
    405
  );
}

/* =========================================================
   PUBLIC CATALOG — EVENTS
========================================================= */

async function publicEvents(env) {
  const result = await env.DB
    .prepare(`
      SELECT
        e.id,
        e.name,
        e.location,
        e.description,
        e.created_at,
        COUNT(DISTINCT c.id) AS cup_count
      FROM events e
      LEFT JOIN cups c
        ON c.event_id = e.id
      GROUP BY
        e.id,
        e.name,
        e.location,
        e.description,
        e.created_at
      ORDER BY e.created_at DESC
    `)
    .all();

  return ok({
    events: result.results || []
  });
}

/* =========================================================
   PUBLIC CATALOG — CUPS
========================================================= */

async function publicCups(env, request) {
  const url = new URL(request.url);

  const eventId =
    url.searchParams.get("event_id") ||
    url.searchParams.get("eventId");

  if (eventId) {
    const result = await env.DB
      .prepare(`
        SELECT
          c.id,
          c.event_id,
          c.name,
          c.description,
          c.created_at,
          e.name AS event_name,
          COUNT(DISTINCT m.id) AS match_count
        FROM cups c
        LEFT JOIN events e
          ON e.id = c.event_id
        LEFT JOIN matches m
          ON m.cup_id = c.id
        WHERE c.event_id = ?
        GROUP BY
          c.id,
          c.event_id,
          c.name,
          c.description,
          c.created_at,
          e.name
        ORDER BY c.created_at DESC
      `)
      .bind(eventId)
      .all();

    return ok({
      cups: result.results || []
    });
  }

  const result = await env.DB
    .prepare(`
      SELECT
        c.id,
        c.event_id,
        c.name,
        c.description,
        c.created_at,
        e.name AS event_name,
        COUNT(DISTINCT m.id) AS match_count
      FROM cups c
      LEFT JOIN events e
        ON e.id = c.event_id
      LEFT JOIN matches m
        ON m.cup_id = c.id
      GROUP BY
        c.id,
        c.event_id,
        c.name,
        c.description,
        c.created_at,
        e.name
      ORDER BY c.created_at DESC
    `)
    .all();

  return ok({
    cups: result.results || []
  });
}

/* =========================================================
   PUBLIC CATALOG — MATCHES / SMP VS SMP
========================================================= */

async function publicMatches(env, request) {
  const url = new URL(request.url);

  const cupId =
    url.searchParams.get("cup_id") ||
    url.searchParams.get("cupId");

  if (cupId) {
    const result = await env.DB
      .prepare(`
        SELECT
          m.id,
          m.cup_id,
          m.match_name,
          m.team_a,
          m.team_b,
          m.match_date,
          m.created_at,
          c.name AS cup_name,
          e.name AS event_name,
          COUNT(p.id) AS photo_count
        FROM matches m
        LEFT JOIN cups c
          ON c.id = m.cup_id
        LEFT JOIN events e
          ON e.id = c.event_id
        LEFT JOIN photos p
          ON p.match_id = m.id
        WHERE m.cup_id = ?
        GROUP BY
          m.id,
          m.cup_id,
          m.match_name,
          m.team_a,
          m.team_b,
          m.match_date,
          m.created_at,
          c.name,
          e.name
        ORDER BY
          m.match_date DESC,
          m.created_at DESC
      `)
      .bind(cupId)
      .all();

    return ok({
      matches: result.results || []
    });
  }

  const result = await env.DB
    .prepare(`
      SELECT
        m.id,
        m.cup_id,
        m.match_name,
        m.team_a,
        m.team_b,
        m.match_date,
        m.created_at,
        c.name AS cup_name,
        e.name AS event_name,
        COUNT(p.id) AS photo_count
      FROM matches m
      LEFT JOIN cups c
        ON c.id = m.cup_id
      LEFT JOIN events e
        ON e.id = c.event_id
      LEFT JOIN photos p
        ON p.match_id = m.id
      GROUP BY
        m.id,
        m.cup_id,
        m.match_name,
        m.team_a,
        m.team_b,
        m.match_date,
        m.created_at,
        c.name,
        e.name
      ORDER BY
        m.match_date DESC,
        m.created_at DESC
    `)
    .all();

  return ok({
    matches: result.results || []
  });
}

/* =========================================================
   PUBLIC CATALOG — PHOTOS
========================================================= */

async function publicPhotos(env, request) {
  const url = new URL(request.url);

  const matchId =
    url.searchParams.get("match_id") ||
    url.searchParams.get("matchId");

  if (matchId) {
    const result = await env.DB
      .prepare(`
        SELECT
          p.id,
          p.match_id,
          p.title,
          p.photographer,
          p.price,
          p.file_name,
          p.content_type,
          p.file_size,
          p.image_url,
          p.preview_path,
          p.created_at,
          m.match_name,
          m.team_a,
          m.team_b,
          c.name AS cup_name,
          e.name AS event_name
        FROM photos p
        LEFT JOIN matches m
          ON m.id = p.match_id
        LEFT JOIN cups c
          ON c.id = m.cup_id
        LEFT JOIN events e
          ON e.id = c.event_id
        WHERE p.match_id = ?
        ORDER BY p.created_at DESC
      `)
      .bind(matchId)
      .all();

    return ok({
      photos: result.results || []
    });
  }

  const result = await env.DB
    .prepare(`
      SELECT
        p.id,
        p.match_id,
        p.title,
        p.photographer,
        p.price,
        p.file_name,
        p.content_type,
        p.file_size,
        p.image_url,
        p.preview_path,
        p.created_at,
        m.match_name,
        m.team_a,
        m.team_b,
        c.name AS cup_name,
        e.name AS event_name
      FROM photos p
      LEFT JOIN matches m
        ON m.id = p.match_id
      LEFT JOIN cups c
        ON c.id = m.cup_id
      LEFT JOIN events e
        ON e.id = c.event_id
      ORDER BY p.created_at DESC
    `)
    .all();

  return ok({
    photos: result.results || []
  });
}

/* =========================================================
   PUBLIC — SINGLE EVENT
========================================================= */

async function publicEvent(env, request) {
  const url = new URL(request.url);

  const eventId =
    url.searchParams.get("id");

  if (!eventId) {
    return error(
      "Event ID wajib diisi"
    );
  }

  const event = await env.DB
    .prepare(`
      SELECT
        id,
        name,
        location,
        description,
        created_at
      FROM events
      WHERE id = ?
      LIMIT 1
    `)
    .bind(eventId)
    .first();

  if (!event) {
    return error(
      "Event tidak ditemukan",
      404
    );
  }

  const cups = await env.DB
    .prepare(`
      SELECT
        id,
        event_id,
        name,
        description,
        created_at
      FROM cups
      WHERE event_id = ?
      ORDER BY created_at DESC
    `)
    .bind(eventId)
    .all();

  return ok({
    event,
    cups: cups.results || []
  });
}

/* =========================================================
   PUBLIC — SINGLE MATCH
========================================================= */

async function publicMatch(env, request) {
  const url = new URL(request.url);

  const matchId =
    url.searchParams.get("id");

  if (!matchId) {
    return error(
      "Match ID wajib diisi"
    );
  }

  const match = await env.DB
    .prepare(`
      SELECT
        m.id,
        m.cup_id,
        m.match_name,
        m.team_a,
        m.team_b,
        m.match_date,
        m.created_at,
        c.name AS cup_name,
        e.name AS event_name
      FROM matches m
      LEFT JOIN cups c
        ON c.id = m.cup_id
      LEFT JOIN events e
        ON e.id = c.event_id
      WHERE m.id = ?
      LIMIT 1
    `)
    .bind(matchId)
    .first();

  if (!match) {
    return error(
      "SMP vs SMP tidak ditemukan",
      404
    );
  }

  const photos = await env.DB
    .prepare(`
      SELECT
        id,
        match_id,
        title,
        photographer,
        price,
        file_name,
        content_type,
        file_size,
        image_url,
        preview_path,
        created_at
      FROM photos
      WHERE match_id = ?
      ORDER BY created_at DESC
    `)
    .bind(matchId)
    .all();

  return ok({
    match,
    photos: photos.results || []
  });
}

/* =========================================================
   SEARCH
========================================================= */

async function searchCatalog(env, request) {
  const url = new URL(request.url);

  const q = String(
    url.searchParams.get("q") || ""
  ).trim();

  if (!q) {
    return ok({
      events: [],
      cups: [],
      matches: [],
      photos: []
    });
  }

  const search = `%${q}%`;

  const [
    events,
    cups,
    matches,
    photos
  ] = await Promise.all([
    env.DB
      .prepare(`
        SELECT
          id,
          name,
          location,
          description,
          created_at
        FROM events
        WHERE
          name LIKE ?
          OR location LIKE ?
          OR description LIKE ?
        ORDER BY created_at DESC
        LIMIT 50
      `)
      .bind(search, search, search)
      .all(),

    env.DB
      .prepare(`
        SELECT
          c.id,
          c.event_id,
          c.name,
          c.description,
          c.created_at,
          e.name AS event_name
        FROM cups c
        LEFT JOIN events e
          ON e.id = c.event_id
        WHERE
          c.name LIKE ?
          OR c.description LIKE ?
          OR e.name LIKE ?
        ORDER BY c.created_at DESC
        LIMIT 50
      `)
      .bind(search, search, search)
      .all(),

    env.DB
      .prepare(`
        SELECT
          m.id,
          m.cup_id,
          m.match_name,
          m.team_a,
          m.team_b,
          m.match_date,
          c.name AS cup_name,
          e.name AS event_name
        FROM matches m
        LEFT JOIN cups c
          ON c.id = m.cup_id
        LEFT JOIN events e
          ON e.id = c.event_id
        WHERE
          m.match_name LIKE ?
          OR m.team_a LIKE ?
          OR m.team_b LIKE ?
          OR c.name LIKE ?
          OR e.name LIKE ?
        ORDER BY m.match_date DESC
        LIMIT 50
      `)
      .bind(
        search,
        search,
        search,
        search,
        search
      )
      .all(),

    env.DB
      .prepare(`
        SELECT
          p.id,
          p.match_id,
          p.title,
          p.photographer,
          p.price,
          p.image_url,
          p.preview_path,
          m.match_name,
          m.team_a,
          m.team_b,
          c.name AS cup_name,
          e.name AS event_name
        FROM photos p
        LEFT JOIN matches m
          ON m.id = p.match_id
        LEFT JOIN cups c
          ON c.id = m.cup_id
        LEFT JOIN events e
          ON e.id = c.event_id
        WHERE
          p.title LIKE ?
          OR p.photographer LIKE ?
          OR m.match_name LIKE ?
          OR m.team_a LIKE ?
          OR m.team_b LIKE ?
          OR c.name LIKE ?
          OR e.name LIKE ?
        ORDER BY p.created_at DESC
        LIMIT 100
      `)
      .bind(
        search,
        search,
        search,
        search,
        search,
        search,
        search
      )
      .all()
  ]);

  return ok({
    events: events.results || [],
    cups: cups.results || [],
    matches: matches.results || [],
    photos: photos.results || []
  });
}

/* =========================================================
   USER — PROFILE
========================================================= */

async function userProfile(request, env) {
  const auth = await requireAuth(
    request,
    env
  );

  if (auth.error) {
    return auth.error;
  }

  const user = await env.DB
    .prepare(`
      SELECT
        id,
        name,
        email,
        role,
        created_at
      FROM users
      WHERE id = ?
      LIMIT 1
    `)
    .bind(auth.user.id)
    .first();

  if (!user) {
    return error(
      "User tidak ditemukan",
      404
    );
  }

  return ok({
    user
  });
}

/* =========================================================
   USER — PURCHASED PHOTOS
========================================================= */

async function purchasedPhotos(
  request,
  env
) {
  const auth = await requireAuth(
    request,
    env
  );

  if (auth.error) {
    return auth.error;
  }

  const result = await env.DB
    .prepare(`
      SELECT
        p.id,
        p.title,
        p.photographer,
        p.price,
        p.file_name,
        p.content_type,
        p.file_size,
        p.image_url,
        p.preview_path,
        p.original_path,
        p.created_at,

        t.id AS transaction_id,
        t.txn_id,
        t.status,
        t.paid_at,

        m.match_name,
        m.team_a,
        m.team_b,

        c.name AS cup_name,

        e.name AS event_name

      FROM transaction_items ti

      INNER JOIN transactions t
        ON t.id = ti.transaction_id

      INNER JOIN photos p
        ON p.id = ti.photo_id

      LEFT JOIN matches m
        ON m.id = p.match_id

      LEFT JOIN cups c
        ON c.id = m.cup_id

      LEFT JOIN events e
        ON e.id = c.event_id

      WHERE
        t.user_id = ?
        AND LOWER(t.status) IN (
          'paid',
          'success',
          'settlement',
          'completed'
        )

      ORDER BY
        t.paid_at DESC,
        t.created_at DESC
    `)
    .bind(auth.user.id)
    .all();

  return ok({
    photos: result.results || []
  });
}

/* =========================================================
   USER — TRANSACTIONS
========================================================= */

async function userTransactions(
  request,
  env
) {
  const auth = await requireAuth(
    request,
    env
  );

  if (auth.error) {
    return auth.error;
  }

  const result = await env.DB
    .prepare(`
      SELECT
        id,
        ref_id,
        txn_id,
        amount,
        unique_amount,
        fee,
        net_amount,
        status,
        payment_url,
        qris_string,
        expired_at,
        paid_at,
        created_at
      FROM transactions
      WHERE user_id = ?
      ORDER BY created_at DESC
    `)
    .bind(auth.user.id)
    .all();

  return ok({
    transactions: result.results || []
  });
}

/* =========================================================
   PAYMENT CONFIG
========================================================= */

async function getPaymentConfig(env) {
  const row = await env.DB
    .prepare(`
      SELECT
        api_key,
        base_url,
        updated_at
      FROM payment_config
      WHERE id = 1
      LIMIT 1
    `)
    .first();

  return {
    apiKey:
      row?.api_key ||
      env.INSTANPAY_API_KEY ||
      "",

    baseUrl:
      row?.base_url ||
      env.INSTANPAY_BASE_URL ||
      "https://pay.instanlive.id/api/v1"
  };
}

/* =========================================================
   ADMIN — PAYMENT CONFIG
========================================================= */

async function adminPaymentConfig(
  request,
  env
) {
  const auth = await requireAdmin(
    request,
    env
  );

  if (auth.error) {
    return auth.error;
  }

  if (request.method === "GET") {
    const config =
      await getPaymentConfig(env);

    return ok({
      configured: Boolean(
        config.apiKey
      ),
      base_url: config.baseUrl
    });
  }

  if (request.method === "POST" ||
      request.method === "PUT") {
    let body;

    try {
      body = await request.json();
    } catch {
      return error("Invalid JSON");
    }

    const apiKey = String(
      body.api_key ||
      body.apiKey ||
      ""
    ).trim();

    const baseUrl = String(
      body.base_url ||
      body.baseUrl ||
      "https://pay.instanlive.id/api/v1"
    ).trim();

    if (!apiKey) {
      return error(
        "InstanPay API Key wajib diisi"
      );
    }

    if (!baseUrl) {
      return error(
        "InstanPay Base URL wajib diisi"
      );
    }

    await env.DB
      .prepare(`
        INSERT INTO payment_config
        (
          id,
          api_key,
          base_url,
          updated_at
        )
        VALUES (1, ?, ?, ?)

        ON CONFLICT(id)
        DO UPDATE SET
          api_key = excluded.api_key,
          base_url = excluded.base_url,
          updated_at = excluded.updated_at
      `)
      .bind(
        apiKey,
        baseUrl.replace(/\/+$/, ""),
        now()
      )
      .run();

    return ok({
      message:
        "Payment configuration berhasil disimpan",
      base_url:
        baseUrl.replace(/\/+$/, "")
    });
  }

  return error(
    "Method not allowed",
    405
  );
}

/* =========================================================
   PAYMENT HELPER
========================================================= */

async function instanPayRequest(
  env,
  path,
  options = {}
) {
  const config =
    await getPaymentConfig(env);

  if (!config.apiKey) {
    throw new Error(
      "InstanPay API Key belum dikonfigurasi"
    );
  }

  const base =
    config.baseUrl.replace(/\/+$/, "");

  const url =
    base + "/" + path.replace(/^\/+/, "");

  const headers = {
    "Content-Type":
      "application/json",
    "X-Api-Key":
      config.apiKey
  };

  const response =
    await fetch(url, {
      method:
        options.method || "GET",
      headers,
      body:
        options.body
          ? JSON.stringify(options.body)
          : undefined
    });

  const text =
    await response.text();

  let data;

  try {
    data = JSON.parse(text);
  } catch {
    data = {
      raw: text
    };
  }

  if (!response.ok) {
    throw new Error(
      data?.message ||
      data?.error ||
      `InstanPay HTTP ${response.status}`
    );
  }

  return data;
}

/* =========================================================
   PAYMENT — CREATE
========================================================= */

async function createPayment(
  request,
  env
) {
  const auth = await requireAuth(
    request,
    env
  );

  if (auth.error) {
    return auth.error;
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return error("Invalid JSON");
  }

  let photoIds =
    body.photo_ids ||
    body.photoIds ||
    [];

  if (!Array.isArray(photoIds)) {
    photoIds = [photoIds];
  }

  photoIds = [
    ...new Set(
      photoIds
        .map(x => String(x).trim())
        .filter(Boolean)
    )
  ];

  if (!photoIds.length) {
    return error(
      "Minimal satu foto harus dipilih"
    );
  }

  const placeholders =
    photoIds.map(() => "?").join(",");

  const photos = await env.DB
    .prepare(`
      SELECT
        id,
        title,
        price,
        match_id
      FROM photos
      WHERE id IN (${placeholders})
    `)
    .bind(...photoIds)
    .all();

  const rows =
    photos.results || [];

  if (rows.length !== photoIds.length) {
    return error(
      "Ada foto yang tidak ditemukan",
      404
    );
  }

  /*
    Jangan membuat transaksi baru untuk
    foto yang sudah berhasil dibeli user.
  */

  const purchased =
    await env.DB
      .prepare(`
        SELECT DISTINCT
          ti.photo_id
        FROM transaction_items ti
        INNER JOIN transactions t
          ON t.id = ti.transaction_id
        WHERE
          t.user_id = ?
          AND ti.photo_id IN (${placeholders})
          AND LOWER(t.status) IN (
            'paid',
            'success',
            'settlement',
            'completed'
          )
      `)
      .bind(
        auth.user.id,
        ...photoIds
      )
      .all();

  const purchasedIds =
    new Set(
      (purchased.results || [])
        .map(x => x.photo_id)
    );

  const unpaidRows =
    rows.filter(
      photo =>
        !purchasedIds.has(photo.id)
    );

  if (!unpaidRows.length) {
    return error(
      "Semua foto sudah dibeli",
      409
    );
  }

  const amount =
    unpaidRows.reduce(
      (sum, photo) =>
        sum + Number(photo.price || 0),
      0
    );

  if (!Number.isFinite(amount) ||
      amount <= 0) {
    return error(
      "Total pembayaran tidak valid"
    );
  }

  const transactionId =
    id("trx_");

  const refId =
    `MOMENTRA-${Date.now()}-${transactionId.slice(-8)}`;

  const redirectUrl =
    String(
      body.redirect_url ||
      body.redirectUrl ||
      ""
    ).trim();

  let payment;

  try {
    payment =
      await instanPayRequest(
        env,
        "/transaction/create",
        {
          method: "POST",
          body: {
            ref_id: refId,
            amount,
            description:
              `Pembelian ${unpaidRows.length} foto Momentra`,
            ...(redirectUrl
              ? {
                  redirect_url:
                    redirectUrl
                }
              : {})
          }
        }
      );
  } catch (err) {
    return error(
      err.message ||
      "Gagal membuat pembayaran",
      502
    );
  }

  /*
    InstanPay biasanya menaruh data
    transaksi di property "data".
  */

  const data =
    payment?.data ||
    payment?.result ||
    payment;

  const txnId =
    data?.txn_id ||
    data?.transaction_id ||
    null;

  const uniqueAmount =
    Number(
      data?.unique_amount ??
      data?.amount ??
      amount
    );

  const fee =
    Number(
      data?.fee || 0
    );

  const netAmount =
    Number(
      data?.net_amount ||
      Math.max(
        0,
        uniqueAmount - fee
      )
    );

  const paymentUrl =
    data?.payment_url ||
    data?.checkout_url ||
    null;

  const qrisString =
    data?.qris_string ||
    data?.qris ||
    null;

  const status =
    String(
      data?.status ||
      "pending"
    ).toLowerCase();

  const expiredAt =
    data?.expired_at ||
    data?.expires_at ||
    null;

  await env.DB
    .prepare(`
      INSERT INTO transactions
      (
        id,
        user_id,
        ref_id,
        txn_id,
        amount,
        unique_amount,
        fee,
        net_amount,
        status,
        payment_url,
        qris_string,
        expired_at,
        created_at
      )
      VALUES
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .bind(
      transactionId,
      auth.user.id,
      refId,
      txnId,
      amount,
      uniqueAmount,
      fee,
      netAmount,
      status,
      paymentUrl,
      qrisString,
      expiredAt,
      now()
    )
    .run();

  for (const photo of unpaidRows) {
    await env.DB
      .prepare(`
        INSERT INTO transaction_items
        (
          id,
          transaction_id,
          photo_id,
          price,
          created_at
        )
        VALUES (?, ?, ?, ?, ?)
      `)
      .bind(
        id("item_"),
        transactionId,
        photo.id,
        Number(photo.price || 0),
        now()
      )
      .run();
  }

  return json({
    success: true,
    transaction: {
      id: transactionId,
      ref_id: refId,
      txn_id: txnId,
      amount,
      unique_amount: uniqueAmount,
      fee,
      net_amount: netAmount,
      status,
      payment_url: paymentUrl,
      qris_string: qrisString,
      expired_in_minutes:
        data?.expired_in_minutes ||
        data?.expire_in_minutes ||
        null,
      expired_at: expiredAt,
      photo_ids:
        unpaidRows.map(
          photo => photo.id
        )
    }
  }, 201);
}

/* =========================================================
   PAYMENT — STATUS
========================================================= */

async function paymentStatus(
  request,
  env
) {
  const auth = await requireAuth(
    request,
    env
  );

  if (auth.error) {
    return auth.error;
  }

  const url =
    new URL(request.url);

  const txnId =
    url.pathname.split("/").pop();

  if (!txnId) {
    return error(
      "Transaction ID wajib diisi"
    );
  }

  const transaction =
    await env.DB
      .prepare(`
        SELECT
          *
        FROM transactions
        WHERE
          txn_id = ?
          AND user_id = ?
        LIMIT 1
      `)
      .bind(
        txnId,
        auth.user.id
      )
      .first();

  if (!transaction) {
    return error(
      "Transaksi tidak ditemukan",
      404
    );
  }

  let remote;

  try {
    remote =
      await instanPayRequest(
        env,
        `/transaction/status/${encodeURIComponent(txnId)}`
      );
  } catch (err) {
    return error(
      err.message ||
      "Gagal mengambil status pembayaran",
      502
    );
  }

  const data =
    remote?.data ||
    remote?.result ||
    remote;

  const newStatus =
    String(
      data?.status ||
      transaction.status ||
      "pending"
    ).toLowerCase();

  let paidAt =
    transaction.paid_at;

  if (
    [
      "paid",
      "success",
      "settlement",
      "completed"
    ].includes(newStatus) &&
    !paidAt
  ) {
    paidAt = now();
  }

  await env.DB
    .prepare(`
      UPDATE transactions
      SET
        status = ?,
        paid_at = ?
      WHERE id = ?
    `)
    .bind(
      newStatus,
      paidAt || null,
      transaction.id
    )
    .run();

  return ok({
    transaction: {
      id: transaction.id,
      ref_id: transaction.ref_id,
      txn_id: transaction.txn_id,
      status: newStatus,
      amount: transaction.amount,
      unique_amount:
        transaction.unique_amount,
      paid_at: paidAt || null
    }
  });
}

/* =========================================================
   PAYMENT — WEBHOOK
========================================================= */

async function paymentWebhook(
  request,
  env
) {
  let body;

  try {
    body = await request.json();
  } catch {
    return error(
      "Invalid JSON"
    );
  }

  const data =
    body?.data ||
    body?.result ||
    body;

  const txnId =
    data?.txn_id ||
    data?.transaction_id ||
    body?.txn_id ||
    body?.transaction_id;

  const refId =
    data?.ref_id ||
    body?.ref_id ||
    null;

  const status =
    String(
      data?.status ||
      body?.status ||
      "pending"
    ).toLowerCase();

  if (!txnId && !refId) {
    return error(
      "Transaction identifier tidak ditemukan"
    );
  }

  let transaction;

  if (txnId) {
    transaction =
      await env.DB
        .prepare(`
          SELECT *
          FROM transactions
          WHERE txn_id = ?
          LIMIT 1
        `)
        .bind(txnId)
        .first();
  }

  if (!transaction && refId) {
    transaction =
      await env.DB
        .prepare(`
          SELECT *
          FROM transactions
          WHERE ref_id = ?
          LIMIT 1
        `)
        .bind(refId)
        .first();
  }

  if (!transaction) {
    return error(
      "Transaksi tidak ditemukan",
      404
    );
  }

  let paidAt =
    transaction.paid_at;

  if (
    [
      "paid",
      "success",
      "settlement",
      "completed"
    ].includes(status) &&
    !paidAt
  ) {
    paidAt = now();
  }

  await env.DB
    .prepare(`
      UPDATE transactions
      SET
        status = ?,
        paid_at = ?
      WHERE id = ?
    `)
    .bind(
      status,
      paidAt || null,
      transaction.id
    )
    .run();

  return ok({
    message:
      "Webhook diterima",
    transaction_id:
      transaction.id,
    status
  });
}

/* =========================================================
   ADMIN — TRANSACTIONS
========================================================= */

async function adminTransactions(
  request,
  env
) {
  const auth = await requireAdmin(
    request,
    env
  );

  if (auth.error) {
    return auth.error;
  }

  const result = await env.DB
    .prepare(`
      SELECT
        t.*,
        u.name AS user_name,
        u.email AS user_email,

        (
          SELECT COUNT(*)
          FROM transaction_items ti
          WHERE
            ti.transaction_id = t.id
        ) AS photo_count

      FROM transactions t

      LEFT JOIN users u
        ON u.id = t.user_id

      ORDER BY
        t.created_at DESC
    `)
    .all();

  return ok({
    transactions:
      result.results || []
  });
}

/* =========================================================
   ADMIN — PAYMENT TEST
========================================================= */

async function adminPaymentTest(
  request,
  env
) {
  const auth = await requireAdmin(
    request,
    env
  );

  if (auth.error) {
    return auth.error;
  }

  try {
    const config =
      await getPaymentConfig(env);

    if (!config.apiKey) {
      return error(
        "InstanPay API Key belum dikonfigurasi"
      );
    }

    const response =
      await fetch(
        config.baseUrl.replace(/\/+$/, ""),
        {
          method: "GET",
          headers: {
            "X-Api-Key":
              config.apiKey
          }
        }
      );

    return ok({
      configured: true,
      status: response.status,
      message:
        response.ok
          ? "Koneksi InstanPay berhasil"
          : "InstanPay merespons dengan status " +
            response.status
    });
  } catch (err) {
    return error(
      err.message ||
      "Gagal menghubungi InstanPay",
      502
    );
  }
}

/* =========================================================
   GITHUB CONFIG
========================================================= */

function githubConfig(env) {
  return {
    token:
      env.GITHUB_TOKEN || "",

    owner:
      env.GITHUB_OWNER ||
      "Kaelzy16",

    repo:
      env.GITHUB_REPO ||
      "Momentraa",

    branch:
      env.GITHUB_BRANCH ||
      "main",

    folder:
      env.GITHUB_PHOTO_FOLDER ||
      "photos"
  };
}

/* =========================================================
   GITHUB — GET FILE
========================================================= */

async function githubGetFile(
  env,
  path
) {
  const config =
    githubConfig(env);

  if (!config.token) {
    throw new Error(
      "GITHUB_TOKEN belum dikonfigurasi"
    );
  }

  const cleanPath =
    String(path || "")
      .replace(/^\/+/, "");

  const apiUrl =
    "https://api.github.com/repos/" +
    encodeURIComponent(config.owner) +
    "/" +
    encodeURIComponent(config.repo) +
    "/contents/" +
    cleanPath +
    "?ref=" +
    encodeURIComponent(config.branch);

  const response =
    await fetch(apiUrl, {
      headers: {
        "Authorization":
          `Bearer ${config.token}`,

        "Accept":
          "application/vnd.github+json",

        "X-GitHub-Api-Version":
          "2022-11-28",

        "User-Agent":
          "Momentra-Worker"
      }
    });

  if (!response.ok) {
    const text =
      await response.text();

    throw new Error(
      `GitHub HTTP ${response.status}: ${text}`
    );
  }

  return await response.json();
}

/* =========================================================
   GITHUB — RAW URL
========================================================= */

function githubRawUrl(
  env,
  path
) {
  const config =
    githubConfig(env);

  const cleanPath =
    String(path || "")
      .replace(/^\/+/, "");

  return (
    "https://raw.githubusercontent.com/" +
    encodeURIComponent(config.owner) +
    "/" +
    encodeURIComponent(config.repo) +
    "/" +
    encodeURIComponent(config.branch) +
    "/" +
    cleanPath
  );
}

/* =========================================================
   PHOTO DOWNLOAD
   Hanya user yang sudah membayar.
========================================================= */

async function downloadPhoto(
  request,
  env
) {
  const auth =
    await requireAuth(
      request,
      env
    );

  if (auth.error) {
    return auth.error;
  }

  const url =
    new URL(request.url);

  const photoId =
    url.searchParams.get("id") ||
    url.pathname.split("/").pop();

  if (!photoId) {
    return error(
      "Photo ID wajib diisi"
    );
  }

  /*
    Pastikan foto memang pernah dibeli
    oleh user yang sedang login dan
    transaksi sudah sukses.
  */

  const item =
    await env.DB
      .prepare(`
        SELECT
          p.id,
          p.file_name,
          p.content_type,
          p.original_path,

          t.id AS transaction_id,
          t.txn_id,
          t.status,
          t.paid_at

        FROM transaction_items ti

        INNER JOIN transactions t
          ON t.id = ti.transaction_id

        INNER JOIN photos p
          ON p.id = ti.photo_id

        WHERE
          ti.photo_id = ?
          AND t.user_id = ?
          AND LOWER(t.status) IN (
            'paid',
            'success',
            'settlement',
            'completed'
          )

        ORDER BY
          t.paid_at DESC,
          t.created_at DESC

        LIMIT 1
      `)
      .bind(
        photoId,
        auth.user.id
      )
      .first();

  if (!item) {
    return error(
      "Foto belum dibeli atau pembayaran belum berhasil",
      403
    );
  }

  if (!item.original_path) {
    return error(
      "File original tidak tersedia",
      404
    );
  }

  /*
    Ambil file original melalui
    GitHub API supaya token GitHub
    tidak pernah dikirim ke browser.
  */

  let githubFile;

  try {
    githubFile =
      await githubGetFile(
        env,
        item.original_path
      );
  } catch (err) {
    return error(
      err.message ||
      "Gagal mengambil file original",
      502
    );
  }

  if (!githubFile.content) {
    return error(
      "Konten file tidak ditemukan di GitHub",
      404
    );
  }

  try {
    const base64 =
      githubFile.content
        .replace(/\s/g, "");

    const binary =
      atob(base64);

    const bytes =
      new Uint8Array(
        binary.length
      );

    for (
      let i = 0;
      i < binary.length;
      i++
    ) {
      bytes[i] =
        binary.charCodeAt(i);
    }

    const contentType =
      item.content_type ||
      "application/octet-stream";

    const fileName =
      item.file_name ||
      `momentra-${photoId}.jpg`;

    return new Response(
      bytes,
      {
        status: 200,

        headers: {
          "Content-Type":
            contentType,

          "Content-Disposition":
            `attachment; filename="${fileName.replace(/"/g, "")}"`,

          "Cache-Control":
            "private, no-store",

          "Access-Control-Allow-Origin":
            "*",

          "Access-Control-Allow-Headers":
            "Content-Type, Authorization"
        }
      }
    );
  } catch {
    return error(
      "Gagal memproses file original",
      500
    );
  }
}

/* =========================================================
   PHOTO — PUBLIC PREVIEW
========================================================= */

async function photoPreview(
  env,
  request
) {
  const url =
    new URL(request.url);

  const photoId =
    url.searchParams.get("id");

  if (!photoId) {
    return error(
      "Photo ID wajib diisi"
    );
  }

  const photo =
    await env.DB
      .prepare(`
        SELECT
          id,
          preview_path,
          image_url,
          title,
          content_type
        FROM photos
        WHERE id = ?
        LIMIT 1
      `)
      .bind(photoId)
      .first();

  if (!photo) {
    return error(
      "Foto tidak ditemukan",
      404
    );
  }

  /*
    image_url menjadi prioritas.
    Jika kosong, gunakan preview_path.
  */

  const previewUrl =
    photo.image_url ||
    (
      photo.preview_path
        ? githubRawUrl(
            env,
            photo.preview_path
          )
        : null
    );

  if (!previewUrl) {
    return error(
      "Preview foto tidak tersedia",
      404
    );
  }

  return ok({
    photo: {
      id: photo.id,
      title: photo.title,
      image_url: previewUrl,
      preview_url: previewUrl
    }
  });
}

/* =========================================================
   ADMIN — GITHUB CONFIG CHECK
========================================================= */

async function adminGithubConfig(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (auth.error) {
    return auth.error;
  }

  const config =
    githubConfig(env);

  return ok({
    configured:
      Boolean(config.token),

    owner:
      config.owner,

    repo:
      config.repo,

    branch:
      config.branch,

    folder:
      config.folder
  });
}

/* =========================================================
   ADMIN — CREATE PHOTO FROM
   GITHUB UPLOAD RESULT
========================================================= */

async function adminGithubPhoto(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (auth.error) {
    return auth.error;
  }

  let body;

  try {
    body =
      await request.json();
  } catch {
    return error(
      "Invalid JSON"
    );
  }

  const path =
    String(
      body.path ||
      ""
    ).trim();

  const type =
    String(
      body.type ||
      "preview"
    ).trim();

  if (!path) {
    return error(
      "GitHub path wajib diisi"
    );
  }

  const config =
    githubConfig(env);

  /*
    Pastikan path tetap berada
    di folder photos.
  */

  const expectedFolder =
    config.folder
      .replace(/^\/+|\/+$/g, "");

  const cleanPath =
    path.replace(/^\/+/, "");

  if (
    !cleanPath.startsWith(
      expectedFolder + "/"
    )
  ) {
    return error(
      "Path GitHub tidak berada di folder photos",
      403
    );
  }

  return ok({
    path: cleanPath,
    type,
    url:
      githubRawUrl(
        env,
        cleanPath
      )
  });
}

/* =========================================================
   ADMIN — DELETE USER
========================================================= */

async function adminDeleteUser(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (auth.error) {
    return auth.error;
  }

  const url =
    new URL(request.url);

  const userId =
    url.searchParams.get("id");

  if (!userId) {
    return error(
      "User ID wajib diisi"
    );
  }

  if (
    String(userId) ===
    String(auth.user.id)
  ) {
    return error(
      "Admin yang sedang login tidak dapat dihapus"
    );
  }

  await env.DB
    .prepare(`
      DELETE FROM users
      WHERE id = ?
    `)
    .bind(userId)
    .run();

  return ok({
    message:
      "User berhasil dihapus"
  });
}

/* =========================================================
   ADMIN — DELETE TRANSACTION
========================================================= */

async function adminDeleteTransaction(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (auth.error) {
    return auth.error;
  }

  const url =
    new URL(request.url);

  const transactionId =
    url.searchParams.get("id");

  if (!transactionId) {
    return error(
      "Transaction ID wajib diisi"
    );
  }

  await env.DB
    .prepare(`
      DELETE FROM transaction_items
      WHERE transaction_id = ?
    `)
    .bind(transactionId)
    .run();

  await env.DB
    .prepare(`
      DELETE FROM transactions
      WHERE id = ?
    `)
    .bind(transactionId)
    .run();

  return ok({
    message:
      "Transaksi berhasil dihapus"
  });
}

/* =========================================================
   ADMIN — ENSURE FIRST ADMIN
========================================================= */

async function ensureAdmin(env) {
  /*
    Jika belum ada user admin dan
    ADMIN_EMAIL + ADMIN_PASSWORD tersedia,
    Worker akan membuat admin pertama.

    Gunakan environment variable:
      ADMIN_EMAIL
      ADMIN_PASSWORD

    Setelah admin dibuat, password tidak
    disimpan plaintext.
  */

  const admin =
    await env.DB
      .prepare(`
        SELECT id
        FROM users
        WHERE role = 'admin'
        LIMIT 1
      `)
      .first();

  if (admin) {
    return;
  }

  if (
    !env.ADMIN_EMAIL ||
    !env.ADMIN_PASSWORD
  ) {
    return;
  }

  const email =
    String(
      env.ADMIN_EMAIL
    )
      .trim()
      .toLowerCase();

  const existing =
    await env.DB
      .prepare(`
        SELECT id
        FROM users
        WHERE email = ?
        LIMIT 1
      `)
      .bind(email)
      .first();

  if (existing) {
    await env.DB
      .prepare(`
        UPDATE users
        SET role = 'admin'
        WHERE id = ?
      `)
      .bind(existing.id)
      .run();

    return;
  }

  const passwordHash =
    await sha256(
      String(
        env.ADMIN_PASSWORD
      )
    );

  await env.DB
    .prepare(`
      INSERT INTO users
      (
        id,
        name,
        email,
        password_hash,
        role,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `)
    .bind(
      id("usr_"),
      "Momentra Admin",
      email,
      passwordHash,
      "admin",
      now()
    )
    .run();
}

/* =========================================================
   ADMIN KEY LOGIN
========================================================= */

async function adminKeyLogin(
  request,
  env
) {
  if (!env.ADMIN_KEY) {
    return error(
      "ADMIN_KEY belum dikonfigurasi",
      500
    );
  }

  const provided =
    request.headers.get(
      "X-Admin-Key"
    );

  if (!provided) {
    let body = {};

    try {
      body =
        await request.json();
    } catch {}

    if (
      body.admin_key ||
      body.adminKey
    ) {
      if (
        String(
          body.admin_key ||
          body.adminKey
        ) ===
        String(env.ADMIN_KEY)
      ) {
        const admin =
          await env.DB
            .prepare(`
              SELECT
                id,
                name,
                email,
                role
              FROM users
              WHERE role = 'admin'
              ORDER BY created_at ASC
              LIMIT 1
            `)
            .first();

        if (!admin) {
          return error(
            "Admin user belum tersedia",
            404
          );
        }

        const token =
          await createToken(
            env,
            admin
          );

        return ok({
          token,
          user: admin
        });
      }
    }

    return error(
      "Admin key wajib diisi",
      401
    );
  }

  if (
    String(provided) !==
    String(env.ADMIN_KEY)
  ) {
    return error(
      "Admin key salah",
      401
    );
  }

  const admin =
    await env.DB
      .prepare(`
        SELECT
          id,
          name,
          email,
          role
        FROM users
        WHERE role = 'admin'
        ORDER BY created_at ASC
        LIMIT 1
      `)
      .first();

  if (!admin) {
    return error(
      "Admin user belum tersedia",
      404
    );
  }

  const token =
    await createToken(
      env,
      admin
    );

  return ok({
    token,
    user: admin
  });
}

/* =========================================================
   ROUTER
========================================================= */

async function router(
  request,
  env
) {
  const url =
    new URL(request.url);

  const path =
    url.pathname.replace(
      /\/+$/,
      ""
    ) || "/";

  const method =
    request.method.toUpperCase();

  /* -------------------------
     AUTH
  ------------------------- */

  if (
    path === "/api/auth/register" &&
    method === "POST"
  ) {
    return register(
      request,
      env
    );
  }

  if (
    path === "/api/auth/login" &&
    method === "POST"
  ) {
    return login(
      request,
      env
    );
  }

  if (
    path === "/api/auth/admin-login" &&
    method === "POST"
  ) {
    return adminKeyLogin(
      request,
      env
    );
  }

  if (
    path === "/api/auth/me" &&
    method === "GET"
  ) {
    return me(
      request,
      env
    );
  }

  if (
    path === "/api/auth/logout"
  ) {
    return logout();
  }

  /* -------------------------
     PUBLIC CATALOG
  ------------------------- */

  if (
    path === "/api/events" &&
    method === "GET"
  ) {
    return publicEvents(env);
  }

  if (
    path === "/api/event" &&
    method === "GET"
  ) {
    return publicEvent(
      env,
      request
    );
  }

  if (
    path === "/api/cups" &&
    method === "GET"
  ) {
    return publicCups(
      env,
      request
    );
  }

  if (
    path === "/api/matches" &&
    method === "GET"
  ) {
    return publicMatches(
      env,
      request
    );
  }

  if (
    path === "/api/match" &&
    method === "GET"
  ) {
    return publicMatch(
      env,
      request
    );
  }

  if (
    path === "/api/photos" &&
    method === "GET"
  ) {
    return publicPhotos(
      env,
      request
    );
  }

  if (
    path === "/api/photo/preview" &&
    method === "GET"
  ) {
    return photoPreview(
      env,
      request
    );
  }

  if (
    path === "/api/search" &&
    method === "GET"
  ) {
    return searchCatalog(
      env,
      request
    );
  }

  /* -------------------------
     USER
  ------------------------- */

  if (
    path === "/api/user/profile" &&
    method === "GET"
  ) {
    return userProfile(
      request,
      env
    );
  }

  if (
    path === "/api/user/transactions" &&
    method === "GET"
  ) {
    return userTransactions(
      request,
      env
    );
  }

  if (
    path === "/api/user/purchased-photos" &&
    method === "GET"
  ) {
    return purchasedPhotos(
      request,
      env
    );
  }

  if (
    path === "/api/purchased-photos" &&
    method === "GET"
  ) {
    return purchasedPhotos(
      request,
      env
    );
  }

  /* -------------------------
     PAYMENT
  ------------------------- */

  if (
    path === "/api/payment/create" &&
    method === "POST"
  ) {
    return createPayment(
      request,
      env
    );
  }

  if (
    path.startsWith(
      "/api/payment/status/"
    ) &&
    method === "GET"
  ) {
    return paymentStatus(
      request,
      env
    );
  }

  if (
    path === "/api/payment/webhook" &&
    method === "POST"
  ) {
    return paymentWebhook(
      request,
      env
    );
  }

  /* -------------------------
     DOWNLOAD
  ------------------------- */

  if (
    path === "/api/photos/download" &&
    method === "GET"
  ) {
    return downloadPhoto(
      request,
      env
    );
  }

  if (
    path.startsWith(
      "/api/photos/"
    ) &&
    path.endsWith(
      "/download"
    ) &&
    method === "GET"
  ) {
    return downloadPhoto(
      request,
      env
    );
  }

  /* -------------------------
     ADMIN DASHBOARD
  ------------------------- */

  if (
    path === "/api/admin/dashboard" &&
    method === "GET"
  ) {
    return adminDashboard(
      request,
      env
    );
  }

  if (
    path === "/api/admin/users" &&
    method === "GET"
  ) {
    return adminUsers(
      request,
      env
    );
  }

  if (
    path === "/api/admin/users" &&
    method === "DELETE"
  ) {
    return adminDeleteUser(
      request,
      env
    );
  }

  if (
    path === "/api/admin/transactions" &&
    method === "GET"
  ) {
    return adminTransactions(
      request,
      env
    );
  }

  if (
    path === "/api/admin/transactions" &&
    method === "DELETE"
  ) {
    return adminDeleteTransaction(
      request,
      env
    );
  }

  /* -------------------------
     ADMIN EVENT
  ------------------------- */

  if (
    path === "/api/admin/events"
  ) {
    return adminEvents(
      request,
      env
    );
  }

  /* -------------------------
     ADMIN CUP
  ------------------------- */

  if (
    path === "/api/admin/cups"
  ) {
    return adminCups(
      request,
      env
    );
  }

  /* -------------------------
     ADMIN MATCH
  ------------------------- */

  if (
    path === "/api/admin/matches"
  ) {
    return adminMatches(
      request,
      env
    );
  }

  /* -------------------------
     ADMIN PHOTO
  ------------------------- */

  if (
    path === "/api/admin/photos"
  ) {
    return adminPhotos(
      request,
      env
    );
  }

  /* -------------------------
     ADMIN PAYMENT
  ------------------------- */

  if (
    path ===
      "/api/admin/payment-config"
  ) {
    return adminPaymentConfig(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/payment/test" &&
    method === "POST"
  ) {
    return adminPaymentTest(
      request,
      env
    );
  }

  /* -------------------------
     ADMIN GITHUB
  ------------------------- */

  if (
    path ===
      "/api/admin/github-config" &&
    method === "GET"
  ) {
    return adminGithubConfig(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/github-photo" &&
    method === "POST"
  ) {
    return adminGithubPhoto(
      request,
      env
    );
  }

  /* -------------------------
     HEALTH CHECK
  ------------------------- */

  if (
    path === "/" ||
    path === "/api" ||
    path === "/api/health"
  ) {
    return ok({
      service: "Momentra API",
      status: "online",
      storage: "GitHub",
      database: "Cloudflare D1",
      payment: "InstanPay",
      r2: false,
      time: now()
    });
  }

  return error(
    "Endpoint tidak ditemukan",
    404
  );
}

/* =========================================================
   CLOUDFLARE WORKER ENTRY
========================================================= */

export default {
  async fetch(
    request,
    env,
    ctx
  ) {
    if (
      request.method ===
      "OPTIONS"
    ) {
      return new Response(
        null,
        {
          status: 204,
          headers: JSON_HEADERS
        }
      );
    }

    try {
      await ensureSchema(env);

      /*
        Membuat admin pertama jika
        ADMIN_EMAIL dan ADMIN_PASSWORD
        tersedia di Worker secrets.
      */
      await ensureAdmin(env);

      return await router(
        request,
        env
      );
    } catch (err) {
      console.error(
        "MOMENTRA WORKER ERROR:",
        err
      );

      return json({
        success: false,
        error:
          err?.message ||
          "Internal Server Error"
      }, 500);
    }
  }
};