// Minimal same-origin backend for CompuNova. Email is sent by Resend from the server.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = __dirname;
const DATA = path.join(ROOT, 'data');
const USERS_FILE = path.join(DATA, 'users.json');
const SUBSCRIBERS_FILE = path.join(DATA, 'subscribers.json');
const MESSAGES_FILE = path.join(DATA, 'messages.json');
const ORDERS_FILE = path.join(DATA, 'orders.json');

function loadEnv() {
  const file = path.join(ROOT, '.env');
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (match && !Object.hasOwn(process.env, match[1])) process.env[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
  }
}
loadEnv();
fs.mkdirSync(DATA, { recursive: true });

function readList(file) {
  try { const data = JSON.parse(fs.readFileSync(file, 'utf8')); return Array.isArray(data) ? data : []; }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
}
function writeList(file, values) {
  const temp = file + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(values, null, 2), { mode: 0o600 });
  fs.renameSync(temp, file);
}
const users = new Map(readList(USERS_FILE).map(user => [user.email, user]));
let subscribers = readList(SUBSCRIBERS_FILE);
let messages = readList(MESSAGES_FILE);
let orders = readList(ORDERS_FILE);
const sessions = new Map();
const rateLimits = new Map();
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const mime = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp', '.avif': 'image/avif', '.gif': 'image/gif' };

function json(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(body));
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}
function limit(req, res, key, maximum = 8) {
  const ip = req.socket.remoteAddress || 'unknown';
  const id = ip + ':' + key;
  const now = Date.now();
  const current = rateLimits.get(id);
  if (!current || now - current.started > 10 * 60 * 1000) rateLimits.set(id, { started: now, count: 1 });
  else if (++current.count > maximum) { json(res, 429, { error: 'Demasiados intentos. Espera unos minutos e inténtalo de nuevo.' }); return false; }
  return true;
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 20_000) { reject(Object.assign(new Error('Solicitud demasiado grande'), { status: 413 })); req.destroy(); } });
    req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch { reject(Object.assign(new Error('Solicitud no válida'), { status: 400 })); } });
    req.on('error', reject);
  });
}
function validEmail(email) { return typeof email === 'string' && email.length <= 254 && emailPattern.test(email); }
function saveUsers() { writeList(USERS_FILE, [...users.values()]); }
function sessionCookie(token, maxAge = 60 * 60 * 24 * 7) {
  return `cn_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`;
}
function getUser(req) {
  const cookie = req.headers.cookie || '';
  const token = cookie.match(/(?:^|;\s*)cn_session=([^;]+)/)?.[1];
  const session = token && sessions.get(token);
  if (!session || session.expires < Date.now()) { if (token) sessions.delete(token); return null; }
  return users.get(session.email) || null;
}
async function sendEmail({ to, subject, html, replyTo }) {
  const { SMTP_HOST, SMTP_USER, SMTP_PASS } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) throw Object.assign(new Error('Faltan los datos SMTP del proveedor de correo.'), { status: 503 });
  const nodemailer = require('nodemailer');
  const port = Number(process.env.SMTP_PORT || 587);
  const transporter = nodemailer.createTransport({ host: SMTP_HOST, port, secure: process.env.SMTP_SECURE === 'true' || port === 465, auth: { user: SMTP_USER, pass: SMTP_PASS } });
  await transporter.sendMail({ from: process.env.EMAIL_FROM || SMTP_USER, to, subject, html, ...(replyTo ? { replyTo } : {}) });
}

async function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = await new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, (error, derived) => error ? reject(error) : resolve(derived.toString('hex'))));
  return { salt, hash };
}
function passwordMatches(password, user) {
  return new Promise((resolve, reject) => crypto.scrypt(password, user.salt, 64, (error, derived) => {
    if (error) return reject(error);
    const expected = Buffer.from(user.passwordHash, 'hex');
    resolve(expected.length === derived.length && crypto.timingSafeEqual(expected, derived));
  }));
}
function startSession(email) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { email, expires: Date.now() + 7 * 24 * 60 * 60 * 1000 });
  return token;
}
function validText(value, max) { return typeof value === 'string' && value.trim().length > 0 && value.trim().length <= max; }
function formatOrderPrice(value) { return 'S/ ' + Number(value).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  const url = new URL(req.url, 'http://localhost');
  try {
    if (req.method === 'GET' && url.pathname === '/api/health') return json(res, 200, { ok: true, emailConfigured: Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) });
    if (req.method === 'POST' && url.pathname === '/api/register') {
      if (!limit(req, res, 'register', 5)) return;
      const body = await readBody(req); const name = typeof body.name === 'string' ? body.name.trim() : ''; const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : ''; const password = body.password;
      if (!validText(name, 100) || !validEmail(email) || typeof password !== 'string' || password.length < 8 || password.length > 200) return json(res, 400, { error: 'Revisa tu nombre, correo y contraseña (mínimo 8 caracteres).' });
      if (users.has(email)) return json(res, 409, { error: 'Ya existe una cuenta con ese correo. Inicia sesión.' });
      const { salt, hash } = await hashPassword(password); const user = { name, email, salt, passwordHash: hash, createdAt: new Date().toISOString() };
      users.set(email, user); saveUsers();
      try { await sendEmail({ to: email, subject: 'Tu cuenta CompuNova está lista', html: `<p>Hola ${escapeHtml(name)},</p><p>Tu cuenta de CompuNova se creó correctamente. Ya puedes iniciar sesión y explorar la tienda.</p><p>Si no solicitaste esta cuenta, contáctanos.</p>` }); }
      catch (error) { users.delete(email); saveUsers(); return json(res, error.status || 502, { error: error.message }); }
      const token = startSession(email);
      return json(res, 201, { ok: true, name }, { 'Set-Cookie': sessionCookie(token) });
    }
    if (req.method === 'POST' && url.pathname === '/api/login') {
      if (!limit(req, res, 'login', 10)) return;
      const body = await readBody(req); const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : ''; const password = body.password;
      const user = users.get(email);
      if (!user || typeof password !== 'string' || !await passwordMatches(password, user)) return json(res, 401, { error: 'El correo o la contraseña no coinciden.' });
      const token = startSession(email);
      return json(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie(token) });
    }
    if (req.method === 'GET' && url.pathname === '/api/me') {
      const user = getUser(req); return user ? json(res, 200, { name: user.name, email: user.email }) : json(res, 401, { error: 'Inicia sesión para continuar.' });
    }
    if (req.method === 'POST' && url.pathname === '/api/logout') {
      const cookie = req.headers.cookie || ''; const token = cookie.match(/(?:^|;\s*)cn_session=([^;]+)/)?.[1]; if (token) sessions.delete(token);
      return json(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie('', 0) });
    }
    if (req.method === 'POST' && url.pathname === '/api/newsletter') {
      if (!limit(req, res, 'newsletter', 4)) return;
      const body = await readBody(req); const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
      if (!validEmail(email) || body.consent !== true) return json(res, 400, { error: 'Ingresa un correo válido y acepta recibir novedades.' });
      if (subscribers.some(item => item.email === email)) return json(res, 200, { ok: true, alreadySubscribed: true });
      await sendEmail({ to: email, subject: 'Te suscribiste a Nova Notes', html: '<p>¡Gracias por suscribirte a Nova Notes!</p><p>Recibirás novedades y recomendaciones de CompuNova en este correo.</p><p>Si no solicitaste esta suscripción, puedes ignorar este mensaje.</p>' });
      subscribers.push({ email, consentedAt: new Date().toISOString() }); writeList(SUBSCRIBERS_FILE, subscribers);
      return json(res, 200, { ok: true });
    }
    if (req.method === 'POST' && url.pathname === '/api/orders') {
      if (!limit(req, res, 'orders', 5)) return;
      const body = await readBody(req);
      const name = typeof body.name === 'string' ? body.name.trim() : '';
      const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
      const phone = typeof body.phone === 'string' ? body.phone.trim() : '';
      const address = typeof body.address === 'string' ? body.address.trim() : '';
      const district = typeof body.district === 'string' ? body.district.trim() : '';
      const methods = ['Tarjeta (simulación)', 'Transferencia (simulación)'];
      if (!validText(name, 100) || !validEmail(email) || !validText(phone, 40) || !validText(address, 200) || !validText(district, 100) || !methods.includes(body.paymentMethod)) return json(res, 400, { error: 'Revisa tus datos de contacto y entrega.' });
      if (!process.env.ADMIN_EMAIL || !validEmail(process.env.ADMIN_EMAIL)) return json(res, 503, { error: 'Falta configurar el correo de la tienda para recibir los pedidos.' });
      if (!Array.isArray(body.items) || body.items.length < 1 || body.items.length > 30) return json(res, 400, { error: 'El carrito está vacío o no es válido.' });
      const items = [];
      for (const item of body.items) {
        if (!validText(item.name, 120) || !Number.isFinite(Number(item.price)) || Number(item.price) < 0 || !Number.isInteger(Number(item.quantity)) || Number(item.quantity) < 1 || Number(item.quantity) > 20) return json(res, 400, { error: 'Hay un producto inválido en el carrito.' });
        items.push({ name: item.name.trim(), price: Number(item.price), quantity: Number(item.quantity) });
      }
      const total = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
      const orderId = 'CN-' + crypto.randomBytes(4).toString('hex').toUpperCase();
      const safeItems = items.map(item => `<li>${escapeHtml(item.name)} × ${item.quantity} — ${formatOrderPrice(item.price * item.quantity)}</li>`).join('');
      const details = `<p><strong>Pedido de demostración ${orderId}</strong></p><ul>${safeItems}</ul><p><strong>Total simulado:</strong> ${formatOrderPrice(total)}</p><p><strong>Pago:</strong> ${escapeHtml(body.paymentMethod)} — no se realizó ningún cobro.</p><p><strong>Entrega:</strong> ${escapeHtml(address)}, ${escapeHtml(district)}</p><p><strong>Cliente:</strong> ${escapeHtml(name)} · ${escapeHtml(phone)} · ${escapeHtml(email)}</p>`;
      const order = { orderId, name, email, phone, address, district, paymentMethod: body.paymentMethod, items, total, status: 'simulado', createdAt: new Date().toISOString() };
      orders.push(order); writeList(ORDERS_FILE, orders);
      try {
        await sendEmail({ to: process.env.ADMIN_EMAIL, replyTo: email, subject: `Pedido simulado ${orderId} · CompuNova`, html: `<p>Se recibió un pedido de demostración. No hay cobro real.</p>${details}` });
        await sendEmail({ to: email, subject: `Confirmación de compra de prueba ${orderId} · CompuNova`, html: `<p>Hola ${escapeHtml(name)}, recibimos tu compra de demostración.</p><p>No se realizó ningún cobro ni se generó una compra real.</p>${details}` });
      } catch (error) { return json(res, error.status || 502, { error: `El pedido de prueba quedó registrado, pero no se pudo enviar el correo. ${error.message}`, orderId }); }
      return json(res, 201, { ok: true, orderId, simulated: true });
    }
    if (req.method === 'POST' && url.pathname === '/api/contact') {
      if (!limit(req, res, 'contact', 5)) return;
      const body = await readBody(req); const name = typeof body.name === 'string' ? body.name.trim() : ''; const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : ''; const message = typeof body.message === 'string' ? body.message.trim() : '';
      if (!validText(name, 100) || !validEmail(email) || !validText(message, 4000)) return json(res, 400, { error: 'Completa tu nombre, un correo válido y tu consulta.' });
      if (!process.env.ADMIN_EMAIL || !validEmail(process.env.ADMIN_EMAIL)) return json(res, 503, { error: 'El correo de contacto de la tienda aún no está configurado.' });
      const safeName = escapeHtml(name), safeMessage = escapeHtml(message).replace(/\n/g, '<br>');
      await sendEmail({ to: email, subject: 'Recibimos tu consulta en CompuNova', html: `<p>Hola ${safeName},</p><p>Recibimos tu mensaje y te responderemos pronto.</p><blockquote>${safeMessage}</blockquote>` });
      await sendEmail({ to: process.env.ADMIN_EMAIL, replyTo: email, subject: `Consulta de CompuNova: ${name}`, html: `<p><strong>${safeName}</strong> (${escapeHtml(email)}) escribió:</p><p>${safeMessage}</p>` });
      messages.push({ name, email, message, createdAt: new Date().toISOString() }); writeList(MESSAGES_FILE, messages);
      return json(res, 200, { ok: true });
    }
    if (url.pathname.startsWith('/api/')) return json(res, 404, { error: 'No encontramos esa función.' });
    if (req.method !== 'GET' && req.method !== 'HEAD') return json(res, 405, { error: 'Método no permitido.' });
    let pathname;
    try { pathname = decodeURIComponent(url.pathname); } catch { return json(res, 400, { error: 'Ruta no válida.' }); }
    const file = path.resolve(ROOT, pathname === '/' ? 'index.html' : '.' + pathname);
    if (!file.startsWith(ROOT + path.sep) || !mime[path.extname(file)]) return json(res, 404, { error: 'No encontramos esa página.' });
    fs.readFile(file, (error, content) => {
      if (error) return json(res, 404, { error: 'No encontramos esa página.' });
      res.writeHead(200, { 'Content-Type': mime[path.extname(file)], 'Cache-Control': 'no-cache' });
      res.end(req.method === 'HEAD' ? undefined : content);
    });
  } catch (error) {
    if (!res.headersSent) json(res, error.status || 500, { error: error.status ? error.message : 'No se pudo completar la solicitud. Inténtalo de nuevo.' });
  }
});

const port = Number(process.env.PORT || 3000);
server.listen(port, '::1', () => console.log(`CompuNova disponible en http://localhost:${port}`));
