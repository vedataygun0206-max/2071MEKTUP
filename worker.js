const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,PUT,OPTIONS",
  "access-control-allow-headers": "Content-Type, Authorization",
};

const PBKDF2_ITERATIONS = 100000;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: JSON_HEADERS,
  });
}

function error(message, status = 400) {
  return json({
    ok: false,
    error: message,
  }, status);
}

function uuid() {
  return crypto.randomUUID();
}

function base64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";

  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

async function derivePassword(password, salt) {
  const encoder = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );

  return new Uint8Array(bits);
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derivePassword(password, salt);

  return `${base64url(salt)}.${base64url(hash)}`;
}
function generatePassword(length = 16) {
  const chars =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";

  const bytes = crypto.getRandomValues(
    new Uint8Array(length)
  );

  let password = "";

  for (let i = 0; i < length; i++) {
    password += chars[bytes[i] % chars.length];
  }

  return password;
}

function generateRecoveryKey() {
  const chars =
    "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  const bytes = crypto.getRandomValues(
    new Uint8Array(20)
  );

  let key = "";

  for (let i = 0; i < bytes.length; i++) {
    if (i > 0 && i % 4 === 0) {
      key += "-";
    }

    key += chars[bytes[i] % chars.length];
  }

  return key;
}

async function hashText(text) {
  const data = new TextEncoder().encode(text);

  const hash = await crypto.subtle.digest(
    "SHA-256",
    data
  );

  return base64url(
    new Uint8Array(hash)
  );
}
async function verifyPassword(password, stored) {
  try {
    const parts = stored.split(".");

    if (parts.length !== 2) return false;

    const salt = base64urlDecode(parts[0]);
    const expected = base64urlDecode(parts[1]);

    const actual = await derivePassword(password, salt);

    if (actual.length !== expected.length) return false;

    let result = 0;

    for (let i = 0; i < actual.length; i++) {
      result |= actual[i] ^ expected[i];
    }

    return result === 0;
  } catch {
    return false;
  }
}

async function signToken(payload, secret) {
  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );

  const body = base64url(
    encoder.encode(JSON.stringify(payload))
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(body)
  );

  return `${body}.${base64url(new Uint8Array(signature))}`;
}

async function verifyToken(token, secret) {
  try {
    const parts = token.split(".");

    if (parts.length !== 2) return null;

    const body = parts[0];
    const signature = base64urlDecode(parts[1]);

    const encoder = new TextEncoder();

    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      {
        name: "HMAC",
        hash: "SHA-256",
      },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      signature,
      encoder.encode(body)
    );

    if (!valid) return null;

    const payload = JSON.parse(
      new TextDecoder().decode(
        base64urlDecode(body)
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

function getToken(request) {
  const auth = request.headers.get("Authorization");

  if (!auth) return null;

  if (!auth.startsWith("Bearer ")) {
    return null;
  }

  return auth.substring(7).trim();
}

async function requireUser(request, env) {
  const token = getToken(request);

  if (!token) {
    return {
      error: error("Oturum gerekli", 401),
    };
  }

  if (!env.AUTH_SECRET) {
    return {
      error: error("AUTH_SECRET yapılandırılmamış", 500),
    };
  }

  const payload = await verifyToken(
    token,
    env.AUTH_SECRET
  );

  if (!payload || !payload.user_id) {
    return {
      error: error("Geçersiz veya süresi dolmuş oturum", 401),
    };
  }

  const user = await env.DB.prepare(
    `SELECT id,email,name,test_capsule_used,created_at
     FROM users
     WHERE id = ?`
  )
    .bind(payload.user_id)
    .first();

  if (!user) {
    return {
      error: error("Kullanıcı bulunamadı", 401),
    };
  }

  return {
    user,
  };
}

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 8
  );
}

function validEmail(email) {
  return (
    typeof email === "string" &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

async function register(request, env) {
  const body = await readBody(request);

  if (!body) {
    return error("Geçersiz JSON");
  }

  const email = normalizeEmail(body.email);
  const name = String(body.name || "").trim();
  const password = generatePassword(16);

  if (!validEmail(email)) {
    return error("Geçerli bir e-posta adresi girin");
  }

  if (!name || name.length < 2) {
    return error("Ad soyad gerekli");
  }

  if (!validPassword(password)) {
    return error(
      "Şifre en az 8 karakter olmalıdır"
    );
  }

  const existing = await env.DB.prepare(
    `SELECT id FROM users WHERE email = ?`
  )
    .bind(email)
    .first();

  if (existing) {
    return error(
      "Bu e-posta adresi zaten kayıtlı",
      409
    );
  }

  const id = uuid();
  const passwordHash = await hashPassword(password);

  await env.DB.prepare(
    `INSERT INTO users
      (id,email,name,password_hash,test_capsule_used)
     VALUES (?,?,?,?,0)`
  )
    .bind(
      id,
      email,
      name,
      passwordHash
    )
    .run();

  return json({
  ok: true,
  message: "Kayıt başarılı",

  warning:
    "Bu şifre sistem tarafından otomatik oluşturulmuştur. Şifrenizi güvenli bir yerde saklayın. Şifre kaybolursa kurtarma işlemi için gerekli güvenlik anahtarınız bulunmalıdır.",

  generated_password: password,

  user: {
    id,
    email,
    name,
    test_capsule_used: 0,
    test_available: true,
  },
});
}
async function login(request, env) {
  const body = await readBody(request);

  if (!body) {
    return error("Geçersiz JSON");
  }

  const email = normalizeEmail(body.email);
  const password = body.password;

  const user = await env.DB.prepare(
    `SELECT *
     FROM users
     WHERE email = ?`
  )
    .bind(email)
    .first();

  if (!user) {
    return error(
      "E-posta veya şifre hatalı",
      401
    );
  }

  const valid = await verifyPassword(
    password,
    user.password_hash
  );

  if (!valid) {
    return error(
      "E-posta veya şifre hatalı",
      401
    );
  }

  if (!env.AUTH_SECRET) {
    return error(
      "AUTH_SECRET yapılandırılmamış",
      500
    );
  }

  const now = Date.now();

  const token = await signToken(
    {
      user_id: user.id,
      iat: now,
      exp: now + 7 * 24 * 60 * 60 * 1000,
    },
    env.AUTH_SECRET
  );

  return json({
    ok: true,
    token,
    expires_in: 7 * 24 * 60 * 60,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      test_capsule_used:
        user.test_capsule_used,
      test_available:
        user.test_capsule_used === 0,
    },
  });
}

async function me(request, env) {
  const auth = await requireUser(request, env);

  if (auth.error) return auth.error;

  return json({
    ok: true,
    user: {
      id: auth.user.id,
      email: auth.user.email,
      name: auth.user.name,
      test_capsule_used:
        auth.user.test_capsule_used,
      test_available:
        auth.user.test_capsule_used === 0,
      created_at: auth.user.created_at,
    },
  });
}

async function createCapsule(request, env) {
  const auth = await requireUser(request, env);

  if (auth.error) return auth.error;

  const body = await readBody(request);

  if (!body) {
    return error("Geçersiz JSON");
  }

  const title = String(
    body.title || ""
  ).trim();

  const description =
    body.description == null
      ? null
      : String(body.description);

  const requestedMode =
    body.mode === "real"
      ? "real"
      : "test";

  if (!title) {
    return error("Kapsül başlığı gerekli");
  }

  /*
   * TEST KAPSÜLÜ
   *
   * Kullanıcının tek ücretsiz hakkını
   * D1 transaction ile tüketiyoruz.
   */
  if (requestedMode === "test") {
    const capsuleId = uuid();

    const result = await env.DB.batch([
      env.DB.prepare(
        `UPDATE users
         SET test_capsule_used = 1
         WHERE id = ?
         AND test_capsule_used = 0`
      ).bind(auth.user.id),

      env.DB.prepare(
        `INSERT INTO capsules
          (id,user_id,title,description,mode,status,visibility)
         VALUES (?,?,?,?,?,'DRAFT','private')`
      ).bind(
        capsuleId,
        auth.user.id,
        title,
        description,
        "test"
      ),
    ]);

    const updateResult = result[0];

    if (!updateResult.meta.changes) {
      return error(
        "Ücretsiz test hakkınız daha önce kullanılmış",
        409
      );
    }

    return json({
      ok: true,
      message: "Test kapsülü oluşturuldu",
      capsule: {
        id: capsuleId,
        mode: "test",
        status: "DRAFT",
        title,
        description,
      },
    }, 201);
  }

  /*
   * GERÇEK KAPSÜL
   *
   * Doğrudan gerçek kapsül oluşturulabilir.
   * Ancak LOCKED olarak oluşturulamaz.
   */
  const capsuleId = uuid();

  await env.DB.prepare(
    `INSERT INTO capsules
      (id,user_id,title,description,mode,status,visibility)
     VALUES (?,?,?,?,?,'DRAFT','private')`
  )
    .bind(
      capsuleId,
      auth.user.id,
      title,
      description,
      "real"
    )
    .run();

  return json({
    ok: true,
    message: "Gerçek kapsül oluşturuldu",
    capsule: {
      id: capsuleId,
      mode: "real",
      status: "DRAFT",
      title,
      description,
    },
  }, 201);
}

async function listCapsules(request, env) {
  const auth = await requireUser(request, env);

  if (auth.error) return auth.error;

  const result = await env.DB.prepare(
    `SELECT
       id,
       title,
       description,
       mode,
       status,
       visibility,
       unlock_at,
       locked_at,
       created_at
     FROM capsules
     WHERE user_id = ?
     ORDER BY created_at DESC`
  )
    .bind(auth.user.id)
    .all();

  return json({
    ok: true,
    capsules: result.results || [],
  });
}

async function getCapsule(request, env, capsuleId) {
  const auth = await requireUser(request, env);

  if (auth.error) return auth.error;

  const capsule = await env.DB.prepare(
    `SELECT *
     FROM capsules
     WHERE id = ?
     AND user_id = ?`
  )
    .bind(
      capsuleId,
      auth.user.id
    )
    .first();

  if (!capsule) {
    return error(
      "Kapsül bulunamadı",
      404
    );
  }

  const entries = await env.DB.prepare(
    `SELECT
       id,
       year,
       type,
       title,
       content,
       created_at
     FROM entries
     WHERE capsule_id = ?
     ORDER BY created_at ASC`
  )
    .bind(capsuleId)
    .all();

  const layers = await env.DB.prepare(
    `SELECT
       id,
       layer_no,
       layer_type,
       created_at
     FROM security_layers
     WHERE capsule_id = ?
     ORDER BY layer_no ASC`
  )
    .bind(capsuleId)
    .all();

  return json({
    ok: true,
    capsule,
    entries: entries.results || [],
    security_layers:
      layers.results || [],
  });
}

async function addEntry(
  request,
  env,
  capsuleId
) {
  const auth = await requireUser(request, env);

  if (auth.error) return auth.error;

  const capsule = await env.DB.prepare(
    `SELECT *
     FROM capsules
     WHERE id = ?
     AND user_id = ?`
  )
    .bind(
      capsuleId,
      auth.user.id
    )
    .first();

  if (!capsule) {
    return error(
      "Kapsül bulunamadı",
      404
    );
  }

  if (capsule.status === "LOCKED") {
    return error(
      "Kilitlenmiş kapsüle içerik eklenemez",
      409
    );
  }

  if (capsule.status === "OPEN") {
    return error(
      "Açılmış kapsüle içerik eklenemez",
      409
    );
  }

  const body = await readBody(request);

  if (!body) {
    return error("Geçersiz JSON");
  }

  const allowedTypes = [
    "letter",
    "note",
    "photo",
    "video",
    "audio",
    "document",
  ];

  const type =
    allowedTypes.includes(body.type)
      ? body.type
      : null;

  if (!type) {
    return error(
      "Geçersiz içerik türü"
    );
  }

  const year = Number(
    body.year || new Date().getFullYear()
  );

  if (
    !Number.isInteger(year) ||
    year < 1900 ||
    year > 9999
  ) {
    return error("Geçersiz yıl");
  }

  const id = uuid();

  await env.DB.prepare(
    `INSERT INTO entries
      (id,capsule_id,year,type,title,content)
     VALUES (?,?,?,?,?,?)`
  )
    .bind(
      id,
      capsuleId,
      year,
      type,
      body.title
        ? String(body.title)
        : null,
      body.content
        ? String(body.content)
        : null
    )
    .run();

  return json({
    ok: true,
    message: "İçerik eklendi",
    entry: {
      id,
      capsule_id: capsuleId,
      year,
      type,
    },
  }, 201);
}

async function convertTestToReal(
  request,
  env,
  capsuleId
) {
  const auth = await requireUser(request, env);

  if (auth.error) return auth.error;

  const capsule = await env.DB.prepare(
    `SELECT *
     FROM capsules
     WHERE id = ?
     AND user_id = ?`
  )
    .bind(
      capsuleId,
      auth.user.id
    )
    .first();

  if (!capsule) {
    return error(
      "Kapsül bulunamadı",
      404
    );
  }

  if (capsule.mode !== "test") {
    return error(
      "Bu kapsül test kapsülü değil",
      409
    );
  }

  if (capsule.status !== "DRAFT") {
    return error(
      "Sadece taslak test kapsülü gerçek kapsüle çevrilebilir",
      409
    );
  }

  const body = await readBody(request);

  const title =
    body?.title
      ? String(body.title).trim()
      : capsule.title;

  const description =
    body?.description !== undefined
      ? String(body.description)
      : capsule.description;

  await env.DB.prepare(
    `UPDATE capsules
     SET mode = 'real',
         title = ?,
         description = ?
     WHERE id = ?
     AND user_id = ?
     AND mode = 'test'
     AND status = 'DRAFT'`
  )
    .bind(
      title,
      description,
      capsuleId,
      auth.user.id
    )
    .run();

  return json({
    ok: true,
    message:
      "Test kapsülü gerçek kapsüle dönüştürüldü",
    capsule_id: capsuleId,
    mode: "real",
  });
}

async function lockCapsule(
  request,
  env,
  capsuleId
) {
  const auth = await requireUser(request, env);

  if (auth.error) return auth.error;

  const capsule = await env.DB.prepare(
    `SELECT *
     FROM capsules
     WHERE id = ?
     AND user_id = ?`
  )
    .bind(
      capsuleId,
      auth.user.id
    )
    .first();

  if (!capsule) {
    return error(
      "Kapsül bulunamadı",
      404
    );
  }

  if (capsule.mode !== "real") {
    return error(
      "Test kapsülü kilitlenemez. Önce gerçek kapsüle dönüştürün.",
      409
    );
  }

  if (capsule.status === "LOCKED") {
    return error(
      "Kapsül zaten kalıcı olarak kilitlenmiş",
      409
    );
  }

  if (capsule.status === "OPEN") {
    return error(
      "Açılmış kapsül tekrar kilitlenemez",
      409
    );
  }

  const body = await readBody(request);

  const unlockAt =
    body?.unlock_at
      ? String(body.unlock_at)
      : null;

  if (!unlockAt) {
    return error(
      "Açılış tarihi belirtilmedi"
    );
  }

  const unlockTime =
    Date.parse(unlockAt);

  if (Number.isNaN(unlockTime)) {
    return error(
      "Geçersiz açılış tarihi"
    );
  }

  if (unlockTime <= Date.now()) {
    return error(
      "Açılış tarihi gelecekte olmalıdır"
    );
  }

  /*
   * KRİTİK KURAL:
   *
   * Sadece DRAFT kapsül LOCKED olabilir.
   *
   * UPDATE koşullarında status='DRAFT'
   * bulunduğu için kilitlendikten sonra
   * unlock_at değiştirilemez.
   */
  const lockedAt =
    new Date().toISOString();

  const result = await env.DB.prepare(
    `UPDATE capsules
     SET status = 'LOCKED',
         unlock_at = ?,
         locked_at = ?
     WHERE id = ?
     AND user_id = ?
     AND mode = 'real'
     AND status = 'DRAFT'`
  )
    .bind(
      new Date(unlockTime).toISOString(),
      lockedAt,
      capsuleId,
      auth.user.id
    )
    .run();

  if (!result.meta.changes) {
    return error(
      "Kapsül kilitlenemedi",
      409
    );
  }

  return json({
    ok: true,
    message:
      "Kapsül kalıcı olarak kilitlendi",
    capsule: {
      id: capsuleId,
      status: "LOCKED",
      unlock_at:
        new Date(unlockTime).toISOString(),
      locked_at: lockedAt,
    },
  });
}

async function openCapsule(
  request,
  env,
  capsuleId
) {
  const auth = await requireUser(request, env);

  if (auth.error) return auth.error;

  const capsule = await env.DB.prepare(
    `SELECT *
     FROM capsules
     WHERE id = ?
     AND user_id = ?`
  )
    .bind(
      capsuleId,
      auth.user.id
    )
    .first();

  if (!capsule) {
    return error(
      "Kapsül bulunamadı",
      404
    );
  }

  if (capsule.status === "OPEN") {
    return json({
      ok: true,
      message: "Kapsül zaten açık",
      capsule,
    });
  }

  if (capsule.status !== "LOCKED") {
    return error(
      "Kapsül kilitli değil",
      409
    );
  }

  if (!capsule.unlock_at) {
    return error(
      "Kapsülün açılış tarihi bulunmuyor",
      500
    );
  }

  /*
   * ŞİMDİLİK sunucunun çalıştığı zamanı
   * Date.now() ile kontrol ediyoruz.
   *
   * İlerleyen V1.2 aşamasında burada
   * güvenilir harici zaman doğrulaması
   * ve ek anti-tamper katmanı kurulacak.
   */
  const unlockTime =
    Date.parse(capsule.unlock_at);

  if (Date.now() < unlockTime) {
    return error(
      "Kapsül henüz açılma zamanına ulaşmadı",
      403
    );
  }

  const result = await env.DB.prepare(
    `UPDATE capsules
     SET status = 'OPEN'
     WHERE id = ?
     AND user_id = ?
     AND status = 'LOCKED'
     AND unlock_at <= ?`
  )
    .bind(
      capsuleId,
      auth.user.id,
      new Date().toISOString()
    )
    .run();

  if (!result.meta.changes) {
    return error(
      "Kapsül açılamadı",
      409
    );
  }

  const opened = await env.DB.prepare(
    `SELECT *
     FROM capsules
     WHERE id = ?
     AND user_id = ?`
  )
    .bind(
      capsuleId,
      auth.user.id
    )
    .first();

  return json({
    ok: true,
    message:
      "Kapsül açıldı",
    capsule: opened,
  });
}

async function addSecurityLayer(
  request,
  env,
  capsuleId
) {
  const auth = await requireUser(request, env);

  if (auth.error) return auth.error;

  const capsule = await env.DB.prepare(
    `SELECT *
     FROM capsules
     WHERE id = ?
     AND user_id = ?`
  )
    .bind(
      capsuleId,
      auth.user.id
    )
    .first();

  if (!capsule) {
    return error(
      "Kapsül bulunamadı",
      404
    );
  }

  if (capsule.status === "LOCKED") {
    return error(
      "Kilitlenmiş kapsülün güvenlik katmanı değiştirilemez",
      409
    );
  }

  const body = await readBody(request);

  if (!body?.layer_type) {
    return error(
      "Güvenlik katmanı türü gerekli"
    );
  }

  const last = await env.DB.prepare(
    `SELECT MAX(layer_no) AS max_layer
     FROM security_layers
     WHERE capsule_id = ?`
  )
    .bind(capsuleId)
    .first();

  const layerNo =
    Number(last?.max_layer || 0) + 1;

  const id = uuid();

  await env.DB.prepare(
    `INSERT INTO security_layers
      (id,capsule_id,layer_no,layer_type,secret_hash)
     VALUES (?,?,?,?,?)`
  )
    .bind(
      id,
      capsuleId,
      layerNo,
      String(body.layer_type),
      body.secret_hash
        ? String(body.secret_hash)
        : null
    )
    .run();

  return json({
    ok: true,
    message:
      "Güvenlik katmanı eklendi",
    layer: {
      id,
      capsule_id: capsuleId,
      layer_no: layerNo,
      layer_type:
        String(body.layer_type),
    },
  }, 201);
}

export default {
  async fetch(request, env) {

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: JSON_HEADERS,
      });
    }

    const u = new URL(request.url);

    try {

      // ============================
      // HEALTH
      // ============================

      if (
        request.method === "GET" &&
        u.pathname === "/api/health"
      ) {
        return json({
          ok: true,
          service: "2071 Mektup",
          version: "V1.1",
          now: new Date().toISOString(),
        });
      }

      // ============================
      // AUTH
      // ============================

      if (
        request.method === "POST" &&
        u.pathname === "/api/register"
      ) {
        return await register(
          request,
          env
        );
      }

      if (
        request.method === "POST" &&
        u.pathname === "/api/login"
      ) {
        return await login(
          request,
          env
        );
      }

      if (
        request.method === "GET" &&
        u.pathname === "/api/me"
      ) {
        return await me(
          request,
          env
        );
      }

      // ============================
      // CAPSULE LIST
      // ============================

      if (
        request.method === "GET" &&
        u.pathname === "/api/capsules"
      ) {
        return await listCapsules(
          request,
          env
        );
      }

      // ============================
      // CREATE CAPSULE
      // ============================

      if (
        request.method === "POST" &&
        u.pathname === "/api/capsules"
      ) {
        return await createCapsule(
          request,
          env
        );
      }

      // ============================
      // CAPSULE ROUTES
      // ============================

      const capsuleMatch =
        u.pathname.match(
          /^\/api\/capsules\/([^/]+)$/
        );

      if (
        capsuleMatch &&
        request.method === "GET"
      ) {
        return await getCapsule(
          request,
          env,
          capsuleMatch[1]
        );
      }

      // ============================
      // ADD ENTRY
      // ============================

      const entryMatch =
        u.pathname.match(
          /^\/api\/capsules\/([^/]+)\/entries$/
        );

      if (
        entryMatch &&
        request.method === "POST"
      ) {
        return await addEntry(
          request,
          env,
          entryMatch[1]
        );
      }

      // ============================
      // TEST → REAL
      // ============================

      const convertMatch =
        u.pathname.match(
          /^\/api\/capsules\/([^/]+)\/convert$/
        );

      if (
        convertMatch &&
        request.method === "POST"
      ) {
        return await convertTestToReal(
          request,
          env,
          convertMatch[1]
        );
      }

      // ============================
      // LOCK
      // ============================

      const lockMatch =
        u.pathname.match(
          /^\/api\/capsules\/([^/]+)\/lock$/
        );

      if (
        lockMatch &&
        request.method === "POST"
      ) {
        return await lockCapsule(
          request,
          env,
          lockMatch[1]
        );
      }

      // ============================
      // OPEN
      // ============================

      const openMatch =
        u.pathname.match(
          /^\/api\/capsules\/([^/]+)\/open$/
        );

      if (
        openMatch &&
        request.method === "POST"
      ) {
        return await openCapsule(
          request,
          env,
          openMatch[1]
        );
      }

      // ============================
      // SECURITY LAYER
      // ============================

      const securityMatch =
        u.pathname.match(
          /^\/api\/capsules\/([^/]+)\/security$/
        );

      if (
        securityMatch &&
        request.method === "POST"
      ) {
        return await addSecurityLayer(
          request,
          env,
          securityMatch[1]
        );
      }

      return error(
        "Endpoint bulunamadı",
        404
      );

    } catch (err) {

      console.error(
        "WORKER ERROR:",
        err
      );

      return json({
        ok: false,
        error: "Sunucu hatası",
        detail: err?.message || String(err),
      }, 500);
    }
  },
};
