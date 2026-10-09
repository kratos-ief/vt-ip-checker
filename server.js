/**
 * VT IP Checker - servidor local.
 *
 * VirusTotal no permite llamadas directas desde el navegador (no envía cabeceras CORS),
 * así que este servidor sirve la aplicación y reenvía cada consulta a la API de VirusTotal.
 * No tiene dependencias: solo requiere Node.js 18 o superior.
 *
 *   node server.js           -> http://127.0.0.1:8080
 *   PORT=3000 node server.js -> http://127.0.0.1:3000
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT) || 8080;
const HOST = '127.0.0.1'; // solo accesible desde este equipo
const ROOT = __dirname;
const VT_IP_URL = 'https://www.virustotal.com/api/v3/ip_addresses/';
const IP_PATTERN = /^[0-9a-fA-F:.]{2,45}$/;
const PROXY_PREFIX = '/vt/ip/';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.writeHead(status, {
    'Content-Type': type,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}

function sendError(res, status, message) {
  send(res, status, JSON.stringify({ error: { code: status, message } }));
}

async function proxyIP(req, res, ip) {
  if (req.method !== 'GET') return sendError(res, 405, 'Método no permitido.');
  if (!IP_PATTERN.test(ip) || !(ip.includes('.') || ip.includes(':'))) {
    return sendError(res, 400, 'Dirección IP con formato no válido.');
  }

  const key = req.headers['x-apikey'];
  if (!key) return sendError(res, 401, 'Falta la API key.');

  try {
    const upstream = await fetch(VT_IP_URL + encodeURIComponent(ip), {
      headers: { 'x-apikey': String(key), Accept: 'application/json' },
    });
    const body = await upstream.text();
    send(res, upstream.status, body, upstream.headers.get('content-type') || 'application/json');
  } catch {
    sendError(res, 502, 'No se pudo contactar con VirusTotal desde el servidor local.');
  }
}

function serveStatic(req, res, pathname) {
  const requested = pathname === '/' ? '/index.html' : pathname;
  const filePath = path.normalize(path.join(ROOT, decodeURIComponent(requested)));

  // Evita salir de la carpeta del proyecto (path traversal)
  if (!filePath.startsWith(ROOT + path.sep) && filePath !== ROOT) {
    return sendError(res, 403, 'Acceso denegado.');
  }

  fs.readFile(filePath, (err, data) => {
    if (err) return sendError(res, 404, 'Archivo no encontrado.');
    const type = MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
    send(res, 200, data, type);
  });
}

const server = http.createServer((req, res) => {
  const { pathname } = new URL(req.url, `http://${HOST}:${PORT}`);

  if (pathname.startsWith(PROXY_PREFIX)) {
    const ip = decodeURIComponent(pathname.slice(PROXY_PREFIX.length));
    return proxyIP(req, res, ip);
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return sendError(res, 405, 'Método no permitido.');
  }
  return serveStatic(req, res, pathname);
});

server.listen(PORT, HOST, () => {
  console.log(`VT IP Checker en http://${HOST}:${PORT}`);
  console.log('Pulsa Ctrl+C para detener el servidor.');
});
