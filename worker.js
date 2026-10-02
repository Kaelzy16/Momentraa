const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Api-Key",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Content-Type": "application/json; charset=utf-8"
};

const INSTANPAY_DEFAULT_BASE_URL =
  "https://pay.instanlive.id/api/v1";

const MAX_PHOTO_SIZE = 15 * 1024 * 1024;

// =====================================================
// RESPONSE
// =====================================================

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: CORS_HEADERS
  });
}

function options() {
  return new Response(null, {
    status: 204,
    headers: CORS_HEADERS
  });
}

// =====================================================
// HELPERS
// =====================================================

function cleanText(value) {
  return String(value ?? "").trim();
}

function getBearer(request) {
  const header = request.headers.get("Authorization") || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice(7).trim() || null;
}

function randomId(prefix = "") {
  return prefix + crypto.randomUUID();
}

function safeFileName(name) {
  return String(name || "photo")
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .slice(0, 120);
}

function bytesToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }

  return bytes;
}

// =====================================================
// PASSWORD
// =====================================================

function generateSalt() {
  return bytesToHex(
    crypto.getRandomValues(new Uint8Array(16))
  );
}

async function hashPassword(password, saltHex) {
  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: hexToBytes(saltHex),
      iterations: 100000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return bytesToHex(bits);
}

async function createPasswordHash(password) {
  const salt = generateSalt();
  const hash = await hashPassword(password, salt);

  return `${salt}:${hash}`;
}

async function verifyPassword(password, stored) {
  const parts = String(stored || "").split(":");

  if (parts.length !== 2) {
    return false;
  }

  const [salt, expected] = parts;

  const actual = await hashPassword(password, salt);

  if (actual.length !== expected.length) {
    return false;
  }

  let diff = 0;

  for (let i = 0; i < actual.length; i++) {
    diff |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  }

  return diff === 0;
}

// =====================================================
// DATABASE INIT
// =====================================================

async function initDatabase(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TEXT NOT NULL
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      location TEXT,
      description TEXT,
      created_at TEXT NOT NULL
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS cups (
      id TEXT PRIMARY KEY,
      event_id TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      created_at TEXT NOT NULL
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS matches (
      id TEXT PRIMARY KEY,
      cup_id TEXT NOT NULL,
      match_name TEXT,
      team_a TEXT NOT NULL,
      team_b TEXT NOT NULL,
      match_date TEXT,
      created_at TEXT NOT NULL
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS photos (
      id TEXT PRIMARY KEY,
      match_id TEXT NOT NULL,
      title TEXT,
      photographer TEXT,
      price INTEGER NOT NULL DEFAULT 25000,
      r2_key TEXT NOT NULL,
      file_name TEXT,
      content_type TEXT,
      file_size INTEGER,
      created_at TEXT NOT NULL
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      ref_id TEXT UNIQUE NOT NULL,
      instanpay_txn_id INTEGER,
      amount INTEGER NOT NULL,
      unique_amount INTEGER,
      fee INTEGER DEFAULT 0,
      net_amount INTEGER DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'pending',
      payment_url TEXT,
      qris_string TEXT,
      description TEXT,
      paid_at TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS transaction_items (
      id TEXT PRIMARY KEY,
      transaction_id TEXT NOT NULL,
      photo_id TEXT NOT NULL,
      price INTEGER NOT NULL,
      created_at TEXT NOT NULL
    )
  `).run();
}

// =====================================================
// AUTH
// =====================================================

async function getUserFromRequest(request, env) {
  const token = getBearer(request);

  if (!token) return null;

  const row = await env.DB.prepare(`
    SELECT
      users.id,
      users.name,
      users.email,
      users.role,
      users.created_at
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token = ?
      AND sessions.expires_at > ?
    LIMIT 1
  `)
    .bind(token, new Date().toISOString())
    .first();

  return row || null;
}

async function requireAuth(request, env) {
  const user = await getUserFromRequest(request, env);

  if (!user) {
    return {
      error: json(
        {
          success: false,
          message: "Unauthorized."
        },
        401
      )
    };
  }

  return { user };
}

async function requireAdmin(request, env) {
  const auth = await requireAuth(request, env);

  if (auth.error) {
    return auth;
  }

  if (auth.user.role !== "admin") {
    return {
      error: json(
        {
          success: false,
          message: "Admin access required."
        },
        403
      )
    };
  }

  return auth;
}

// =====================================================
// REGISTER
// =====================================================

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function registerUser(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        message: "JSON tidak valid."
      },
      400
    );
  }

  const name = cleanText(body.name);
  const email = cleanText(body.email).toLowerCase();
  const password = String(body.password || "");

  if (!name) {
    return json(
      {
        success: false,
        message: "Nama wajib diisi."
      },
      400
    );
  }

  if (name.length < 2) {
    return json(
      {
        success: false,
        message: "Nama terlalu pendek."
      },
      400
    );
  }

  if (!isValidEmail(email)) {
    return json(
      {
        success: false,
        message: "Format email tidak valid."
      },
      400
    );
  }

  if (password.length < 8) {
    return json(
      {
        success: false,
        message: "Password minimal 8 karakter."
      },
      400
    );
  }

  const existing = await env.DB.prepare(`
    SELECT id
    FROM users
    WHERE email = ?
    LIMIT 1
  `)
    .bind(email)
    .first();

  if (existing) {
    return json(
      {
        success: false,
        message: "Email sudah terdaftar."
      },
      409
    );
  }

  const id = randomId("user_");
  const createdAt = new Date().toISOString();
  const passwordHash = await createPasswordHash(password);

  await env.DB.prepare(`
    INSERT INTO users (
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
      id,
      name,
      email,
      passwordHash,
      "user",
      createdAt
    )
    .run();

  return json(
    {
      success: true,
      message: "Akun berhasil dibuat.",
      user: {
        id,
        name,
        email,
        role: "user",
        created_at: createdAt
      }
    },
    201
  );
}

// =====================================================
// LOGIN
// =====================================================

async function loginUser(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        message: "JSON tidak valid."
      },
      400
    );
  }

  const email = cleanText(body.email).toLowerCase();
  const password = String(body.password || "");

  const user = await env.DB.prepare(`
    SELECT *
    FROM users
    WHERE email = ?
    LIMIT 1
  `)
    .bind(email)
    .first();

  if (!user) {
    return json(
      {
        success: false,
        message: "Email atau password salah."
      },
      401
    );
  }

  const valid = await verifyPassword(
    password,
    user.password_hash
  );

  if (!valid) {
    return json(
      {
        success: false,
        message: "Email atau password salah."
      },
      401
    );
  }

  const token = crypto.randomUUID();
  const createdAt = new Date();
  const expiresAt = new Date(
    createdAt.getTime() + 7 * 24 * 60 * 60 * 1000
  );

  await env.DB.prepare(`
    INSERT INTO sessions (
      token,
      user_id,
      created_at,
      expires_at
    )
    VALUES (?, ?, ?, ?)
  `)
    .bind(
      token,
      user.id,
      createdAt.toISOString(),
      expiresAt.toISOString()
    )
    .run();

  return json({
    success: true,
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      created_at: user.created_at
    }
  });
}

// =====================================================
// LOGOUT
// =====================================================

async function logoutUser(request, env) {
  const token = getBearer(request);

  if (token) {
    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE token = ?
    `)
      .bind(token)
      .run();
  }

  return json({
    success: true,
    message: "Logout berhasil."
  });
}

// =====================================================
// ADMIN USERS
// =====================================================

async function getAdminUsers(env) {
  const result = await env.DB.prepare(`
    SELECT
      id,
      name,
      email,
      role,
      created_at
    FROM users
    ORDER BY created_at DESC
  `).all();

  return json({
    success: true,
    users: result.results || []
  });
}

// =====================================================
// EVENTS
// =====================================================

async function createEvent(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        message: "JSON tidak valid."
      },
      400
    );
  }

  const name = cleanText(body.name);

  if (!name) {
    return json(
      {
        success: false,
        message: "Nama olahraga/event wajib diisi."
      },
      422
    );
  }

  const id = randomId("event_");
  const createdAt = new Date().toISOString();

  await env.DB.prepare(`
    INSERT INTO events (
      id,
      name,
      location,
      description,
      created_at
    )
    VALUES (?, ?, ?, ?, ?)
  `)
    .bind(
      id,
      name,
      cleanText(body.location),
      cleanText(body.description),
      createdAt
    )
    .run();

  return json({
    success: true,
    event: {
      id,
      name,
      location: cleanText(body.location),
      description: cleanText(body.description),
      created_at: createdAt
    }
  }, 201);
}

async function getEvents(env) {
  const result = await env.DB.prepare(`
    SELECT *
    FROM events
    ORDER BY created_at DESC
  `).all();

  return json({
    success: true,
    events: result.results || []
  });
}

// =====================================================
// CUPS
// =====================================================

async function createCup(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        message: "JSON tidak valid."
      },
      400
    );
  }

  const eventId = cleanText(body.event_id);
  const name = cleanText(body.name);

  if (!eventId || !name) {
    return json(
      {
        success: false,
        message: "event_id dan nama cup wajib diisi."
      },
      422
    );
  }

  const event = await env.DB.prepare(`
    SELECT id
    FROM events
    WHERE id = ?
    LIMIT 1
  `)
    .bind(eventId)
    .first();

  if (!event) {
    return json(
      {
        success: false,
        message: "Event tidak ditemukan."
      },
      404
    );
  }

  const id = randomId("cup_");
  const createdAt = new Date().toISOString();

  await env.DB.prepare(`
    INSERT INTO cups (
      id,
      event_id,
      name,
      description,
      created_at
    )
    VALUES (?, ?, ?, ?, ?)
  `)
    .bind(
      id,
      eventId,
      name,
      cleanText(body.description),
      createdAt
    )
    .run();

  return json({
    success: true,
    cup: {
      id,
      event_id: eventId,
      name,
      description: cleanText(body.description),
      created_at: createdAt
    }
  }, 201);
}

async function getCups(env, eventId = null) {
  let result;

  if (eventId) {
    result = await env.DB.prepare(`
      SELECT
        cups.*,
        events.name AS event_name
      FROM cups
      JOIN events ON events.id = cups.event_id
      WHERE cups.event_id = ?
      ORDER BY cups.created_at DESC
    `)
      .bind(eventId)
      .all();
  } else {
    result = await env.DB.prepare(`
      SELECT
        cups.*,
        events.name AS event_name
      FROM cups
      JOIN events ON events.id = cups.event_id
      ORDER BY cups.created_at DESC
    `).all();
  }

  return json({
    success: true,
    cups: result.results || []
  });
}

// =====================================================
// MATCH / SEKOLAH VS SEKOLAH
// =====================================================

async function createMatch(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        message: "JSON tidak valid."
      },
      400
    );
  }

  const cupId = cleanText(body.cup_id);
  const teamA = cleanText(body.teamA || body.team_a);
  const teamB = cleanText(body.teamB || body.team_b);

  if (!cupId || !teamA || !teamB) {
    return json(
      {
        success: false,
        message: "Cup, sekolah A, dan sekolah B wajib diisi."
      },
      422
    );
  }

  const cup = await env.DB.prepare(`
    SELECT id
    FROM cups
    WHERE id = ?
    LIMIT 1
  `)
    .bind(cupId)
    .first();

  if (!cup) {
    return json(
      {
        success: false,
        message: "Cup tidak ditemukan."
      },
      404
    );
  }

  const id = randomId("match_");
  const createdAt = new Date().toISOString();

  await env.DB.prepare(`
    INSERT INTO matches (
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
      id,
      cupId,
      cleanText(body.matchName || body.match_name),
      teamA,
      teamB,
      cleanText(body.matchDate || body.match_date),
      createdAt
    )
    .run();

  return json({
    success: true,
    match: {
      id,
      cup_id: cupId,
      match_name: cleanText(body.matchName || body.match_name),
      team_a: teamA,
      team_b: teamB,
      match_date: cleanText(body.matchDate || body.match_date),
      created_at: createdAt
    }
  }, 201);
}

async function getMatches(env, cupId = null) {
  let result;

  if (cupId) {
    result = await env.DB.prepare(`
      SELECT
        matches.*,
        cups.name AS cup_name,
        events.name AS event_name
      FROM matches
      JOIN cups ON cups.id = matches.cup_id
      JOIN events ON events.id = cups.event_id
      WHERE matches.cup_id = ?
      ORDER BY matches.match_date DESC, matches.created_at DESC
    `)
      .bind(cupId)
      .all();
  } else {
    result = await env.DB.prepare(`
      SELECT
        matches.*,
        cups.name AS cup_name,
        events.name AS event_name
      FROM matches
      JOIN cups ON cups.id = matches.cup_id
      JOIN events ON events.id = cups.event_id
      ORDER BY matches.match_date DESC, matches.created_at DESC
    `).all();
  }

  return json({
    success: true,
    matches: result.results || []
  });
}

// =====================================================
// PHOTO UPLOAD
// =====================================================

async function uploadPhotos(request, env) {
  if (!env.PHOTOS) {
    return json(
      {
        success: false,
        message: "R2 binding PHOTOS belum dikonfigurasi."
      },
      500
    );
  }

  const form = await request.formData();

  const matchId = cleanText(form.get("match_id"));
  const title = cleanText(form.get("title"));
  const photographer = cleanText(form.get("photographer"));

  const price = Number(form.get("price") || 25000);
  const file = form.get("file");

  if (!matchId || !file || typeof file === "string") {
    return json(
      {
        success: false,
        message: "Match dan file foto wajib diisi."
      },
      422
    );
  }

  if (!file.type.startsWith("image/")) {
    return json(
      {
        success: false,
        message: "File harus berupa gambar."
      },
      422
    );
  }

  if (file.size > MAX_PHOTO_SIZE) {
    return json(
      {
        success: false,
        message: "Ukuran foto maksimal 15 MB."
      },
      422
    );
  }

  const match = await env.DB.prepare(`
    SELECT id
    FROM matches
    WHERE id = ?
    LIMIT 1
  `)
    .bind(matchId)
    .first();

  if (!match) {
    return json(
      {
        success: false,
        message: "Match tidak ditemukan."
      },
      404
    );
  }

  const id = randomId("photo_");
  const fileName = safeFileName(file.name);
  const r2Key =
    `photos/${matchId}/${id}-${fileName}`;

  await env.PHOTOS.put(
    r2Key,
    file.stream(),
    {
      httpMetadata: {
        contentType: file.type
      }
    }
  );

  const createdAt = new Date().toISOString();

  await env.DB.prepare(`
    INSERT INTO photos (
      id,
      match_id,
      title,
      photographer,
      price,
      r2_key,
      file_name,
      content_type,
      file_size,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `)
    .bind(
      id,
      matchId,
      title,
      photographer,
      price,
      r2Key,
      fileName,
      file.type,
      file.size,
      createdAt
    )
    .run();

  return json({
    success: true,
    message: "Foto berhasil diupload.",
    photo: {
      id,
      match_id: matchId,
      title,
      photographer,
      price,
      created_at: createdAt
    }
  }, 201);
}

// =====================================================
// PHOTO FILE
// =====================================================

async function getPhotoFile(photoId, env) {
  if (!env.PHOTOS) {
    return new Response("R2 not configured.", {
      status: 500
    });
  }

  const photo = await env.DB.prepare(`
    SELECT *
    FROM photos
    WHERE id = ?
    LIMIT 1
  `)
    .bind(photoId)
    .first();

  if (!photo) {
    return new Response("Photo not found.", {
      status: 404
    });
  }

  const object = await env.PHOTOS.get(photo.r2_key);

  if (!object) {
    return new Response("File not found.", {
      status: 404
    });
  }

  const headers = new Headers();

  object.writeHttpMetadata(headers);
  headers.set(
    "Cache-Control",
    "public, max-age=31536000"
  );

  return new Response(object.body, {
    headers
  });
}

// =====================================================
// PUBLIC PHOTO LIST
// =====================================================

async function getPhotos(env, matchId = null) {
  let result;

  if (matchId) {
    result = await env.DB.prepare(`
      SELECT
        photos.id,
        photos.match_id,
        photos.title,
        photos.photographer,
        photos.price,
        photos.content_type,
        photos.file_size,
        photos.created_at,
        matches.team_a,
        matches.team_b,
        cups.name AS cup_name,
        events.name AS event_name
      FROM photos
      JOIN matches ON matches.id = photos.match_id
      JOIN cups ON cups.id = matches.cup_id
      JOIN events ON events.id = cups.event_id
      WHERE photos.match_id = ?
      ORDER BY photos.created_at DESC
    `)
      .bind(matchId)
      .all();
  } else {
    result = await env.DB.prepare(`
      SELECT
        photos.id,
        photos.match_id,
        photos.title,
        photos.photographer,
        photos.price,
        photos.content_type,
        photos.file_size,
        photos.created_at,
        matches.team_a,
        matches.team_b,
        cups.name AS cup_name,
        events.name AS event_name
      FROM photos
      JOIN matches ON matches.id = photos.match_id
      JOIN cups ON cups.id = matches.cup_id
      JOIN events ON events.id = cups.event_id
      ORDER BY photos.created_at DESC
    `).all();
  }

  const photos = (result.results || []).map(photo => ({
    ...photo,
    file_url:
      `/api/photos/${encodeURIComponent(photo.id)}/file`
  }));

  return json({
    success: true,
    photos
  });
}

// =====================================================
// DELETE PHOTO
// =====================================================

async function deletePhoto(photoId, env) {
  const photo = await env.DB.prepare(`
    SELECT *
    FROM photos
    WHERE id = ?
    LIMIT 1
  `)
    .bind(photoId)
    .first();

  if (!photo) {
    return json(
      {
        success: false,
        message: "Foto tidak ditemukan."
      },
      404
    );
  }

  if (env.PHOTOS) {
    await env.PHOTOS.delete(photo.r2_key);
  }

  await env.DB.prepare(`
    DELETE FROM transaction_items
    WHERE photo_id = ?
  `)
    .bind(photoId)
    .run();

  await env.DB.prepare(`
    DELETE FROM photos
    WHERE id = ?
  `)
    .bind(photoId)
    .run();

  return json({
    success: true,
    message: "Foto berhasil dihapus."
  });
}

// =====================================================
// INSTANPAY
// =====================================================

function getInstanPayBaseUrl(env) {
  return cleanText(
    env.INSTANPAY_BASE_URL ||
    INSTANPAY_DEFAULT_BASE_URL
  ).replace(/\/+$/, "");
}

function getInstanPayKey(env) {
  return cleanText(env.INSTANPAY_API_KEY);
}

async function instanPayRequest(
  env,
  path,
  options = {}
) {
  const apiKey = getInstanPayKey(env);

  if (!apiKey) {
    throw new Error(
      "INSTANPAY_API_KEY belum dikonfigurasi."
    );
  }

  const baseUrl = getInstanPayBaseUrl(env);

  const headers = new Headers(
    options.headers || {}
  );

  headers.set("X-Api-Key", apiKey);
  headers.set("Content-Type", "application/json");

  const response = await fetch(
    `${baseUrl}${path}`,
    {
      ...options,
      headers
    }
  );

  let data;

  try {
    data = await response.json();
  } catch {
    data = {
      ok: false,
      error: "invalid_json_response"
    };
  }

  return {
    response,
    data
  };
}

// =====================================================
// CREATE PAYMENT
// =====================================================

async function createPayment(request, env) {
  const auth = await requireAuth(request, env);

  if (auth.error) return auth.error;

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        message: "JSON tidak valid."
      },
      400
    );
  }

  const photoIds = Array.isArray(body.photo_ids)
    ? body.photo_ids
    : [];

  if (!photoIds.length) {
    return json(
      {
        success: false,
        message: "Minimal satu foto harus dipilih."
      },
      422
    );
  }

  const placeholders =
    photoIds.map(() => "?").join(",");

  const result = await env.DB.prepare(`
    SELECT
      id,
      title,
      price
    FROM photos
    WHERE id IN (${placeholders})
  `)
    .bind(...photoIds)
    .all();

  const photos = result.results || [];

  if (photos.length !== photoIds.length) {
    return json(
      {
        success: false,
        message: "Ada foto yang tidak ditemukan."
      },
      404
    );
  }

  const amount = photos.reduce(
    (sum, photo) =>
      sum + Number(photo.price || 0),
    0
  );

  if (amount < 100) {
    return json(
      {
        success: false,
        message: "Total pembayaran tidak valid."
      },
      422
    );
  }

  const transactionId = randomId("trx_");

  const refId =
    `MOM-${Date.now()}-${transactionId.slice(-8)}`;

  const description =
    `Pembelian ${photos.length} foto Momentra`;

  const redirectUrl =
    cleanText(body.redirect_url) ||
    "";

  const instanBody = {
    ref_id: refId,
    amount,
    description
  };

  if (redirectUrl) {
    instanBody.redirect_url = redirectUrl;
  }

  const { response, data } =
    await instanPayRequest(
      env,
      "/transaction/create",
      {
        method: "POST",
        body: JSON.stringify(instanBody)
      }
    );

  if (!response.ok || !data.ok) {
    return json(
      {
        success: false,
        message:
          data?.error ||
          data?.message ||
          "Gagal membuat pembayaran.",
        instanpay: data
      },
      response.status || 502
    );
  }

  const payment = data.data;

  const now = new Date().toISOString();

  await env.DB.prepare(`
    INSERT INTO transactions (
      id,
      user_id,
      ref_id,
      instanpay_txn_id,
      amount,
      unique_amount,
      fee,
      net_amount,
      status,
      payment_url,
      qris_string,
      description,
      paid_at,
      created_at,
      updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `)
    .bind(
      transactionId,
      auth.user.id,
      refId,
      Number(payment.txn_id),
      amount,
      Number(payment.unique_amount || amount),
      Number(payment.fee || 0),
      Number(payment.net_amount || 0),
      cleanText(payment.status) || "pending",
      cleanText(payment.payment_url),
      cleanText(payment.qris_string),
      description,
      null,
      now,
      now
    )
    .run();

  for (const photo of photos) {
    await env.DB.prepare(`
      INSERT INTO transaction_items (
        id,
        transaction_id,
        photo_id,
        price,
        created_at
      )
      VALUES (?, ?, ?, ?, ?)
    `)
      .bind(
        randomId("item_"),
        transactionId,
        photo.id,
        Number(photo.price || 0),
        now
      )
      .run();
  }

  return json({
    success: true,
    transaction: {
      id: transactionId,
      ref_id: refId,
      txn_id: payment.txn_id,
      amount: payment.amount,
      unique_amount: payment.unique_amount,
      fee: payment.fee,
      net_amount: payment.net_amount,
      status: payment.status,
      payment_url: payment.payment_url,
      qris_string: payment.qris_string,
      expired_in_minutes:
        payment.expired_in_minutes,
      simulate_url:
        payment.simulate_url || null
    }
  });
}

// =====================================================
// PAYMENT STATUS
// =====================================================

async function getPaymentStatus(
  txnId,
  request,
  env
) {
  const auth = await requireAuth(request, env);

  if (auth.error) return auth.error;

  const transaction = await env.DB.prepare(`
    SELECT *
    FROM transactions
    WHERE instanpay_txn_id = ?
      AND user_id = ?
    LIMIT 1
  `)
    .bind(Number(txnId), auth.user.id)
    .first();

  if (!transaction) {
    return json(
      {
        success: false,
        message: "Transaksi tidak ditemukan."
      },
      404
    );
  }

  const { response, data } =
    await instanPayRequest(
      env,
      `/transaction/status/${encodeURIComponent(txnId)}`,
      {
        method: "GET"
      }
    );

  if (!response.ok || !data.ok) {
    return json(
      {
        success: false,
        message:
          data?.error ||
          data?.message ||
          "Gagal mengecek status.",
        instanpay: data
      },
      response.status || 502
    );
  }

  const payment = data.data;

  await updateTransactionStatus(
    transaction,
    payment,
    env
  );

  return json({
    success: true,
    transaction: {
      id: transaction.id,
      ref_id: transaction.ref_id,
      txn_id: payment.txn_id,
      status: payment.status,
      amount: payment.amount,
      unique_amount: payment.unique_amount,
      paid_at: payment.paid_at || null
    }
  });
}

// =====================================================
// UPDATE TRANSACTION
// =====================================================

async function updateTransactionStatus(
  transaction,
  payment,
  env
) {
  const status = cleanText(payment.status);

  if (!status) return;

  const paidAt =
    payment.paid_at ||
    (status === "paid"
      ? new Date().toISOString()
      : null);

  const updatedAt =
    new Date().toISOString();

  await env.DB.prepare(`
    UPDATE transactions
    SET
      status = ?,
      unique_amount = ?,
      fee = ?,
      net_amount = ?,
      paid_at = ?,
      updated_at = ?
    WHERE id = ?
  `)
    .bind(
      status,
      Number(
        payment.unique_amount ??
        transaction.unique_amount ??
        0
      ),
      Number(
        payment.fee ??
        transaction.fee ??
        0
      ),
      Number(
        payment.net_amount ??
        transaction.net_amount ??
        0
      ),
      paidAt,
      updatedAt,
      transaction.id
    )
    .run();
}

// =====================================================
// WEBHOOK SIGNATURE
// =====================================================

async function hmacSha256(
  key,
  message
) {
  const cryptoKey =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(key),
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,
      ["sign"]
    );

  const signature =
    await crypto.subtle.sign(
      "HMAC",
      cryptoKey,
      new TextEncoder().encode(message)
    );

  return bytesToHex(signature);
}

function sortObjectKeys(data) {
  const sorted = {};

  for (
    const key of Object.keys(data).sort()
  ) {
    sorted[key] = data[key];
  }

  return sorted;
}

async function verifyInstanPayWebhook(
  body,
  apiKey
) {
  const signature = body.signature;

  if (!signature) {
    return false;
  }

  const data = {
    ...body
  };

  delete data.signature;

  const sorted =
    sortObjectKeys(data);

  const payload = JSON.stringify(
    sorted
  );

  const calculated =
    await hmacSha256(
      apiKey,
      payload
    );

  if (
    calculated.length !==
    String(signature).length
  ) {
    return false;
  }

  let diff = 0;

  for (
    let i = 0;
    i < calculated.length;
    i++
  ) {
    diff |=
      calculated.charCodeAt(i) ^
      String(signature).charCodeAt(i);
  }

  return diff === 0;
}

// =====================================================
// WEBHOOK
// =====================================================

async function paymentWebhook(
  request,
  env
) {
  const apiKey =
    getInstanPayKey(env);

  if (!apiKey) {
    return json(
      {
        success: false,
        message:
          "INSTANPAY_API_KEY belum dikonfigurasi."
      },
      500
    );
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        message: "JSON tidak valid."
      },
      400
    );
  }

  const valid =
    await verifyInstanPayWebhook(
      body,
      apiKey
    );

  if (!valid) {
    return json(
      {
        success: false,
        message: "Invalid signature."
      },
      401
    );
  }

  const refId =
    cleanText(body.ref_id);

  const txnId =
    Number(body.txn_id);

  const transaction =
    await env.DB.prepare(`
      SELECT *
      FROM transactions
      WHERE ref_id = ?
         OR instanpay_txn_id = ?
      LIMIT 1
    `)
      .bind(refId, txnId)
      .first();

  if (!transaction) {
    return json(
      {
        success: true,
        message:
          "Webhook valid tetapi transaksi Momentra tidak ditemukan."
      }
    );
  }

  await updateTransactionStatus(
    transaction,
    body,
    env
  );

  return json({
    success: true,
    message: "Webhook diterima."
  });
}

// =====================================================
// ADMIN TRANSACTIONS
// =====================================================

async function getAdminTransactions(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (auth.error) return auth.error;

  const url =
    new URL(request.url);

  const status =
    cleanText(url.searchParams.get("status"));

  const search =
    cleanText(url.searchParams.get("search"));

  let query = `
    SELECT
      transactions.*,
      users.name AS user_name,
      users.email AS user_email,
      (
        SELECT COUNT(*)
        FROM transaction_items
        WHERE transaction_items.transaction_id =
          transactions.id
      ) AS photo_count
    FROM transactions
    JOIN users ON users.id = transactions.user_id
    WHERE 1 = 1
  `;

  const binds = [];

  if (status) {
    query += `
      AND transactions.status = ?
    `;

    binds.push(status);
  }

  if (search) {
    query += `
      AND (
        transactions.ref_id LIKE ?
        OR users.name LIKE ?
        OR users.email LIKE ?
      )
    `;

    const q = `%${search}%`;

    binds.push(q, q, q);
  }

  query += `
    ORDER BY transactions.created_at DESC
    LIMIT 200
  `;

  const result =
    await env.DB.prepare(query)
      .bind(...binds)
      .all();

  return json({
    success: true,
    transactions:
      result.results || []
  });
}

// =====================================================
// USER TRANSACTIONS
// =====================================================

async function getUserTransactions(
  request,
  env
) {
  const auth =
    await requireAuth(
      request,
      env
    );

  if (auth.error) return auth.error;

  const result =
    await env.DB.prepare(`
      SELECT
        transactions.*,
        (
          SELECT COUNT(*)
          FROM transaction_items
          WHERE transaction_items.transaction_id =
            transactions.id
        ) AS photo_count
      FROM transactions
      WHERE user_id = ?
      ORDER BY created_at DESC
    `)
      .bind(auth.user.id)
      .all();

  return json({
    success: true,
    transactions:
      result.results || []
  });
}

// =====================================================
// USER PURCHASED PHOTOS
// =====================================================

async function getPurchasedPhotos(
  request,
  env
) {
  const auth =
    await requireAuth(
      request,
      env
    );

  if (auth.error) return auth.error;

  const result =
    await env.DB.prepare(`
      SELECT
        photos.id,
        photos.title,
        photos.photographer,
        photos.price,
        photos.match_id,
        transactions.id AS transaction_id,
        transactions.paid_at
      FROM transaction_items
      JOIN transactions
        ON transactions.id =
           transaction_items.transaction_id
      JOIN photos
        ON photos.id =
           transaction_items.photo_id
      WHERE transactions.user_id = ?
        AND transactions.status = 'paid'
      ORDER BY transactions.paid_at DESC
    `)
      .bind(auth.user.id)
      .all();

  return json({
    success: true,
    photos: result.results || []
  });
}

// =====================================================
// PAYMENT TEST CONNECTION
// =====================================================

async function testPaymentConnection(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (auth.error) return auth.error;

  const apiKey =
    getInstanPayKey(env);

  if (!apiKey) {
    return json(
      {
        success: false,
        connected: false,
        message:
          "INSTANPAY_API_KEY belum dikonfigurasi."
      },
      500
    );
  }

  try {
    const {
      response,
      data
    } = await instanPayRequest(
      env,
      "/balance",
      {
        method: "GET"
      }
    );

    return json({
      success: response.ok && data.ok,
      connected:
        response.ok && data.ok,
      mode:
        data?.data?.mode || null,
      currency:
        data?.data?.currency || null,
      message:
        response.ok && data.ok
          ? "Koneksi InstanPay berhasil."
          : (
            data?.error ||
            data?.message ||
            "Koneksi gagal."
          )
    });
  } catch (error) {
    return json(
      {
        success: false,
        connected: false,
        message: error.message
      },
      500
    );
  }
}

// =====================================================
// PAYMENT CONFIG
// =====================================================

async function getPaymentConfig(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (auth.error) return auth.error;

  const apiKey =
    getInstanPayKey(env);

  let mode = null;

  if (apiKey.startsWith("sk_live_")) {
    mode = "live";
  } else if (
    apiKey.startsWith("sk_test_")
  ) {
    mode = "sandbox";
  }

  return json({
    success: true,
    config: {
      base_url:
        getInstanPayBaseUrl(env),
      configured:
        Boolean(apiKey),
      mode
    }
  });
}

// =====================================================
// SANDBOX SIMULATION
// =====================================================

async function simulateSandboxPayment(
  txnId,
  request,
  env
) {
  const auth =
    await requireAuth(
      request,
      env
    );

  if (auth.error) return auth.error;

  const apiKey =
    getInstanPayKey(env);

  if (
    !apiKey.startsWith("sk_test_")
  ) {
    return json(
      {
        success: false,
        message:
          "Sandbox simulation hanya dapat digunakan dengan sk_test_."
      },
      403
    );
  }

  const transaction =
    await env.DB.prepare(`
      SELECT *
      FROM transactions
      WHERE instanpay_txn_id = ?
        AND user_id = ?
      LIMIT 1
    `)
      .bind(
        Number(txnId),
        auth.user.id
      )
      .first();

  if (!transaction) {
    return json(
      {
        success: false,
        message: "Transaksi tidak ditemukan."
      },
      404
    );
  }

  const {
    response,
    data
  } = await instanPayRequest(
    env,
    `/sandbox/pay/${encodeURIComponent(txnId)}`,
    {
      method: "POST"
    }
  );

  if (!response.ok || !data.ok) {
    return json(
      {
        success: false,
        message:
          data?.error ||
          data?.message ||
          "Sandbox payment gagal.",
        instanpay: data
      },
      response.status || 502
    );
  }

  const statusResult =
    await instanPayRequest(
      env,
      `/transaction/status/${encodeURIComponent(txnId)}`,
      {
        method: "GET"
      }
    );

  if (
    statusResult.response.ok &&
    statusResult.data.ok
  ) {
    await updateTransactionStatus(
      transaction,
      statusResult.data.data,
      env
    );
  }

  return json({
    success: true,
    message:
      "Sandbox payment berhasil disimulasikan.",
    instanpay: data.data
  });
}

// =====================================================
// DASHBOARD
// =====================================================

async function getAdminDashboard(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (auth.error) return auth.error;

  const users =
    await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM users
      WHERE role = 'user'
    `).first();

  const photos =
    await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM photos
    `).first();

  const transactions =
    await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM transactions
    `).first();

  const paid =
    await env.DB.prepare(`
      SELECT
        COUNT(*) AS total,
        COALESCE(
          SUM(amount),
          0
        ) AS revenue
      FROM transactions
      WHERE status = 'paid'
    `).first();

  const pending =
    await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM transactions
      WHERE status = 'pending'
    `).first();

  return json({
    success: true,
    stats: {
      users: Number(users?.total || 0),
      photos: Number(photos?.total || 0),
      transactions:
        Number(transactions?.total || 0),
      paid:
        Number(paid?.total || 0),
      revenue:
        Number(paid?.revenue || 0),
      pending:
        Number(pending?.total || 0)
    }
  });
}

// =====================================================
// CATALOG
// =====================================================

async function getCatalog(env) {
  const events =
    await env.DB.prepare(`
      SELECT *
      FROM events
      ORDER BY created_at DESC
    `).all();

  const cups =
    await env.DB.prepare(`
      SELECT *
      FROM cups
      ORDER BY created_at DESC
    `).all();

  const matches =
    await env.DB.prepare(`
      SELECT *
      FROM matches
      ORDER BY match_date DESC, created_at DESC
    `).all();

  const photos =
    await env.DB.prepare(`
      SELECT
        id,
        match_id,
        title,
        photographer,
        price,
        content_type,
        file_size,
        created_at
      FROM photos
      ORDER BY created_at DESC
    `).all();

  return json({
    success: true,
    events:
      events.results || [],
    cups:
      cups.results || [],
    matches:
      matches.results || [],
    photos:
      photos.results || []
  });
}

// =====================================================
// HEALTH
// =====================================================

function health() {
  return json({
    success: true,
    service: "momentra-api",
    status: "online",
    payment: "InstanPay"
  });
}

// =====================================================
// MAIN ROUTER
// =====================================================

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return options();
    }

    try {
      await initDatabase(env);

      const url =
        new URL(request.url);

      const path =
        url.pathname;

      const method =
        request.method;

      // -------------------------------
      // HEALTH
      // -------------------------------

      if (
        path === "/" &&
        method === "GET"
      ) {
        return health();
      }

      // -------------------------------
      // AUTH
      // -------------------------------

      if (
        path === "/api/auth/register" &&
        method === "POST"
      ) {
        return await registerUser(
          request,
          env
        );
      }

      if (
        path === "/api/auth/login" &&
        method === "POST"
      ) {
        return await loginUser(
          request,
          env
        );
      }

      if (
        path === "/api/auth/logout" &&
        method === "POST"
      ) {
        return await logoutUser(
          request,
          env
        );
      }

      if (
        path === "/api/auth/me" &&
        method === "GET"
      ) {
        const auth =
          await requireAuth(
            request,
            env
          );

        if (auth.error)
          return auth.error;

        return json({
          success: true,
          user: auth.user
        });
      }

      // -------------------------------
      // PUBLIC CATALOG
      // -------------------------------

      if (
        path === "/api/catalog" &&
        method === "GET"
      ) {
        return await getCatalog(env);
      }

      if (
        path === "/api/events" &&
        method === "GET"
      ) {
        return await getEvents(env);
      }

      if (
        path === "/api/cups" &&
        method === "GET"
      ) {
        return await getCups(
          env,
          url.searchParams.get("event_id")
        );
      }

      if (
        path === "/api/matches" &&
        method === "GET"
      ) {
        return await getMatches(
          env,
          url.searchParams.get("cup_id")
        );
      }

      if (
        path === "/api/photos" &&
        method === "GET"
      ) {
        return await getPhotos(
          env,
          url.searchParams.get("match_id")
        );
      }

      // -------------------------------
      // PHOTO FILE
      // -------------------------------

      const photoFileMatch =
        path.match(
          /^\/api\/photos\/([^/]+)\/file$/
        );

      if (
        photoFileMatch &&
        method === "GET"
      ) {
        return await getPhotoFile(
          decodeURIComponent(
            photoFileMatch[1]
          ),
          env
        );
      }

      // -------------------------------
      // ADMIN USERS
      // -------------------------------

      if (
        path === "/api/admin/users" &&
        method === "GET"
      ) {
        const auth =
          await requireAdmin(
            request,
            env
          );

        if (auth.error)
          return auth.error;

        return await getAdminUsers(env);
      }

      // -------------------------------
      // ADMIN DASHBOARD
      // -------------------------------

      if (
        path === "/api/admin/dashboard" &&
        method === "GET"
      ) {
        return await getAdminDashboard(
          request,
          env
        );
      }

      // -------------------------------
      // ADMIN EVENTS
      // -------------------------------

      if (
        path === "/api/admin/events" &&
        method === "POST"
      ) {
        const auth =
          await requireAdmin(
            request,
            env
          );

        if (auth.error)
          return auth.error;

        return await createEvent(
          request,
          env
        );
      }

      // -------------------------------
      // ADMIN CUPS
      // -------------------------------

      if (
        path === "/api/admin/cups" &&
        method === "POST"
      ) {
        const auth =
          await requireAdmin(
            request,
            env
          );

        if (auth.error)
          return auth.error;

        return await createCup(
          request,
          env
        );
      }

      // -------------------------------
      // ADMIN MATCHES
      // -------------------------------

      if (
        path === "/api/admin/matches" &&
        method === "POST"
      ) {
        const auth =
          await requireAdmin(
            request,
            env
          );

        if (auth.error)
          return auth.error;

        return await createMatch(
          request,
          env
        );
      }

      // -------------------------------
      // ADMIN PHOTO UPLOAD
      // -------------------------------

      if (
        path === "/api/admin/photos" &&
        method === "POST"
      ) {
        const auth =
          await requireAdmin(
            request,
            env
          );

        if (auth.error)
          return auth.error;

        return await uploadPhotos(
          request,
          env
        );
      }

      // -------------------------------
      // ADMIN PHOTO DELETE
      // -------------------------------

      const deletePhotoMatch =
        path.match(
          /^\/api\/admin\/photos\/([^/]+)$/
        );

      if (
        deletePhotoMatch &&
        method === "DELETE"
      ) {
        const auth =
          await requireAdmin(
            request,
            env
          );

        if (auth.error)
          return auth.error;

        return await deletePhoto(
          decodeURIComponent(
            deletePhotoMatch[1]
          ),
          env
        );
      }

      // -------------------------------
      // USER CREATE PAYMENT
      // -------------------------------

      if (
        path === "/api/payment/create" &&
        method === "POST"
      ) {
        return await createPayment(
          request,
          env
        );
      }

      // -------------------------------
      // PAYMENT STATUS
      // -------------------------------

      const paymentStatusMatch =
        path.match(
          /^\/api\/payment\/status\/([^/]+)$/
        );

      if (
        paymentStatusMatch &&
        method === "GET"
      ) {
        return await getPaymentStatus(
          decodeURIComponent(
            paymentStatusMatch[1]
          ),
          request,
          env
        );
      }

      // -------------------------------
      // PAYMENT WEBHOOK
      // -------------------------------

      if (
        path === "/api/payment/webhook" &&
        method === "POST"
      ) {
        return await paymentWebhook(
          request,
          env
        );
      }

      // -------------------------------
      // SANDBOX SIMULATION
      // -------------------------------

      const sandboxMatch =
        path.match(
          /^\/api\/payment\/sandbox\/([^/]+)$/
        );

      if (
        sandboxMatch &&
        method === "POST"
      ) {
        return await simulateSandboxPayment(
          decodeURIComponent(
            sandboxMatch[1]
          ),
          request,
          env
        );
      }

      // -------------------------------
      // USER TRANSACTIONS
      // -------------------------------

      if (
        path === "/api/transactions" &&
        method === "GET"
      ) {
        return await getUserTransactions(
          request,
          env
        );
      }

      // -------------------------------
      // PURCHASED PHOTOS
      // -------------------------------

      if (
        path === "/api/purchased-photos" &&
        method === "GET"
      ) {
        return await getPurchasedPhotos(
          request,
          env
        );
      }

      // -------------------------------
      // ADMIN TRANSACTIONS
      // -------------------------------

      if (
        path === "/api/admin/transactions" &&
        method === "GET"
      ) {
        return await getAdminTransactions(
          request,
          env
        );
      }

      // -------------------------------
      // PAYMENT CONFIG
      // -------------------------------

      if (
        path === "/api/admin/payment-config" &&
        method === "GET"
      ) {
        return await getPaymentConfig(
          request,
          env
        );
      }

      if (
        path === "/api/admin/payment/test" &&
        method === "POST"
      ) {
        return await testPaymentConnection(
          request,
          env
        );
      }

      // -------------------------------
      // NOT FOUND
      // -------------------------------

      return json(
        {
          success: false,
          message: "Endpoint tidak ditemukan."
        },
        404
      );

    } catch (error) {
      console.error(
        "Momentra Worker Error:",
        error
      );

      return json(
        {
          success: false,
          message:
            "Terjadi kesalahan pada server.",
          error:
            error?.message || "Unknown error"
        },
        500
      );
    }
  }
};