(() => {
  'use strict';

  /* ---------- Configuración ---------- */
  const IS_LOCAL = ['localhost', '127.0.0.1'].includes(location.hostname);
  // En local las consultas pasan por server.js (VirusTotal no admite CORS desde el navegador).
  const VT_API_BASE = IS_LOCAL
    ? '/vt/ip/'
    : 'https://www.virustotal.com/api/v3/ip_addresses/';
  const VT_GUI_BASE = 'https://www.virustotal.com/gui/ip-address/';
  const MAX_IPS = 10;             // máximo de IPs por consulta
  const MIN_IOC = 3;              // "más de 2 IoC" => 3 o más
  const REQUEST_GAP_MS = 15000;   // plan gratuito: 4 solicitudes por minuto
  const STORAGE_KEY = 'vtipchecker.apikey';

  const $ = (id) => document.getElementById(id);
  const ui = {
    apiKey: $('apiKey'),
    toggleKey: $('toggleKey'),
    rememberKey: $('rememberKey'),
    ipInput: $('ipInput'),
    ipCount: $('ipCount'),
    limitAlert: $('limitAlert'),
    invalidNote: $('invalidNote'),
    startBtn: $('startBtn'),
    cancelBtn: $('cancelBtn'),
    clearBtn: $('clearBtn'),
    progressWrap: $('progressWrap'),
    progressBar: $('progressBar'),
    statusText: $('statusText'),
    statTotal: $('statTotal'),
    statIssues: $('statIssues'),
    statClean: $('statClean'),
    statErrors: $('statErrors'),
    resultsBody: $('resultsBody'),
    resultsEmpty: $('resultsEmpty'),
    errorsCard: $('errorsCard'),
    errorsBody: $('errorsBody'),
  };

  let analyzed = [];   // resultados válidos (incluye IPs sin problemas)
  let errors = [];     // IPs que no pudieron consultarse
  let controller = null;
  let running = false;

  /* ---------- Utilidades ---------- */
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));

  const fmtDate = (unix) => (unix ? new Date(unix * 1000).toLocaleString('es-ES') : '—');

  function isIPv4(s) {
    return /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(s);
  }

  function isIPv6(s) {
    if (!s.includes(':') || !/^[0-9a-f:.]+$/i.test(s)) return false;
    try {
      return new URL(`http://[${s}]`).hostname.startsWith('[');
    } catch {
      return false;
    }
  }

  const isIP = (s) => isIPv4(s) || isIPv6(s);

  /** Separa la entrada, valida, quita duplicados y devuelve las IPs válidas. */
  function parseInput(text) {
    const tokens = text.split(/[\s,;]+/).filter(Boolean);
    const seen = new Set();
    const valid = [];
    const invalid = [];
    let duplicates = 0;

    for (const token of tokens) {
      if (!isIP(token)) {
        invalid.push(token);
        continue;
      }
      if (seen.has(token)) {
        duplicates++;
        continue;
      }
      seen.add(token);
      valid.push(token);
    }
    return { valid, invalid, duplicates };
  }

  /* ---------- API de VirusTotal ---------- */
  class VTError extends Error {
    constructor(message, fatal = false) {
      super(message);
      this.fatal = fatal;
    }
  }

  async function fetchIP(ip, key, signal) {
    let res;
    try {
      res = await fetch(VT_API_BASE + encodeURIComponent(ip), {
        method: 'GET',
        headers: { 'x-apikey': key, Accept: 'application/json' },
        signal,
      });
    } catch (err) {
      if (err.name === 'AbortError') throw err;
      throw new VTError(IS_LOCAL
        ? 'No se pudo contactar con el servidor local.'
        : 'Bloqueo CORS: VirusTotal no permite consultas directas desde el navegador. Ejecuta la app con server.js.');
    }

    if (res.status === 404) return { ip, notFound: true, malicious: 0, suspicious: 0, ioc: 0 };
    if (res.status === 401 || res.status === 403) {
      throw new VTError(`API key inválida o sin permisos (HTTP ${res.status}).`, true);
    }
    if (res.status === 429) throw new VTError('Límite de solicitudes excedido (HTTP 429).');
    if (!res.ok) throw new VTError(`Respuesta inesperada de VirusTotal (HTTP ${res.status}).`);

    const { data } = await res.json();
    const attr = data?.attributes ?? {};
    const stats = attr.last_analysis_stats ?? {};
    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;

    return {
      ip,
      notFound: false,
      malicious,
      suspicious,
      ioc: malicious + suspicious,
      engines: Object.values(stats).reduce((a, b) => a + b, 0),
      country: attr.country ?? '—',
      asOwner: attr.as_owner ?? '—',
      lastAnalysis: attr.last_analysis_date ?? null,
    };
  }

  /** Espera `ms` milisegundos, actualizando el contador; se interrumpe con la señal. */
  async function pause(ms, signal, label) {
    const end = Date.now() + ms;
    for (;;) {
      const left = end - Date.now();
      if (left <= 0) return;
      setStatus(`${label} Siguiente consulta en ${Math.ceil(left / 1000)} s (límite gratuito de VirusTotal).`);
      await sleep(Math.min(1000, left), signal);
    }
  }

  function sleep(ms, signal) {
    return new Promise((resolve, reject) => {
      const onAbort = () => {
        clearTimeout(timer);
        reject(new DOMException('Cancelado', 'AbortError'));
      };
      const timer = setTimeout(() => {
        signal.removeEventListener('abort', onAbort);
        resolve();
      }, ms);
      signal.addEventListener('abort', onAbort, { once: true });
    });
  }

  /* ---------- Flujo principal ---------- */
  async function startAnalysis() {
    const key = ui.apiKey.value.trim();
    const { valid, invalid, duplicates } = parseInput(ui.ipInput.value);

    if (!key) {
      setStatus('Ingresa tu API key de VirusTotal.', 'error');
      ui.apiKey.focus();
      return;
    }
    if (!valid.length) {
      setStatus('No hay direcciones IP válidas para consultar.', 'error');
      return;
    }
    if (valid.length > MAX_IPS) {
      updateInputState();
      return;
    }

    persistKey(key);
    analyzed = [];
    errors = [];
    renderInvalidNote(invalid, duplicates);
    renderAll();
    setRunning(true);

    controller = new AbortController();
    const { signal } = controller;

    try {
      for (let i = 0; i < valid.length; i++) {
        const ip = valid[i];
        setStatus(`Consultando ${ip} (${i + 1} de ${valid.length})…`);
        setProgress(i, valid.length);

        try {
          analyzed.push(await fetchIP(ip, key, signal));
        } catch (err) {
          if (err.name === 'AbortError') throw err;
          errors.push({ ip, message: err instanceof VTError ? err.message : 'Error inesperado.' });
          if (err.fatal) {
            setStatus(err.message, 'error');
            break;
          }
        }
        renderAll();

        if (i < valid.length - 1) {
          await pause(REQUEST_GAP_MS, signal, `${i + 1} de ${valid.length} completadas.`);
        }
      }

      if (!ui.statusText.classList.contains('error')) {
        setProgress(valid.length, valid.length);
        setStatus(
          `Análisis finalizado: ${analyzed.length} consultadas, ${flagged().length} con problemas, ${errors.length} con error.`,
          'ok'
        );
      }
    } catch (err) {
      if (err.name === 'AbortError') {
        setStatus('Análisis cancelado. Se muestran los resultados obtenidos hasta el momento.', 'warn');
      } else {
        setStatus('Ocurrió un error inesperado durante el análisis.', 'error');
      }
    } finally {
      controller = null;
      setRunning(false);
    }
  }

  /** IPs con más de 2 IoC, de mayor a menor. */
  function flagged() {
    return analyzed
      .filter((r) => !r.notFound && r.ioc >= MIN_IOC)
      .sort((a, b) => b.ioc - a.ioc);
  }

  /* ---------- Renderizado ---------- */
  function renderAll() {
    const issues = flagged();
    ui.statTotal.textContent = analyzed.length;
    ui.statIssues.textContent = issues.length;
    ui.statClean.textContent = analyzed.length - issues.length;
    ui.statErrors.textContent = errors.length;

    if (!issues.length) {
      ui.resultsBody.innerHTML = '';
      ui.resultsEmpty.hidden = false;
      ui.resultsEmpty.textContent = analyzed.length
        ? 'Ninguna IP analizada supera los 2 IoC.'
        : 'Aún no hay resultados.';
    } else {
      ui.resultsEmpty.hidden = true;
      ui.resultsBody.innerHTML = issues.map((r, idx) => `
        <tr>
          <td>${idx + 1}</td>
          <td class="mono">${esc(r.ip)}</td>
          <td><span class="badge bad">${r.ioc}</span></td>
          <td>${r.malicious}</td>
          <td>${r.suspicious}</td>
          <td>${r.engines}</td>
          <td>${esc(r.country)}</td>
          <td>${esc(r.asOwner)}</td>
          <td>${esc(fmtDate(r.lastAnalysis))}</td>
          <td><a class="btn ghost small" href="${VT_GUI_BASE}${encodeURIComponent(r.ip)}" target="_blank" rel="noopener noreferrer">Ver en VT ↗</a></td>
        </tr>`).join('');
    }

    ui.errorsCard.hidden = errors.length === 0;
    ui.errorsBody.innerHTML = errors.map((e) => `
      <li><span class="mono">${esc(e.ip)}</span> — ${esc(e.message)}</li>`).join('');
  }

  function renderInvalidNote(invalid, duplicates) {
    const parts = [];
    if (invalid.length) parts.push(`Entradas no válidas omitidas (${invalid.length}): ${invalid.map(esc).join(', ')}`);
    if (duplicates) parts.push(`Duplicadas eliminadas: ${duplicates}`);
    ui.invalidNote.hidden = parts.length === 0;
    ui.invalidNote.innerHTML = parts.join('<br>');
  }

  /** Actualiza contador, alerta de límite y estado del botón según la entrada. */
  function updateInputState() {
    const { valid, invalid } = parseInput(ui.ipInput.value);
    const count = valid.length;
    const over = count > MAX_IPS;

    ui.ipCount.textContent = `${count} / ${MAX_IPS} IPs`;
    ui.ipCount.style.color = over ? 'var(--danger)' : '';

    ui.limitAlert.hidden = !over;
    if (over) {
      ui.limitAlert.textContent =
        `Ingresó ${count} IPs. El máximo por consulta es ${MAX_IPS}. ` +
        'Reduzca la lista para poder iniciar el análisis.';
    }

    if (!running) ui.startBtn.disabled = over || count === 0;
    if (!ui.invalidNote.hidden && !invalid.length) ui.invalidNote.hidden = true;
  }

  function setStatus(message, tone = '') {
    ui.statusText.textContent = message;
    ui.statusText.className = `status ${tone}`.trim();
  }

  function setProgress(done, total) {
    ui.progressBar.style.width = total ? `${(done / total) * 100}%` : '0%';
  }

  function setRunning(on) {
    running = on;
    ui.cancelBtn.hidden = !on;
    ui.progressWrap.hidden = !on;
    ui.clearBtn.disabled = on;
    if (on) ui.startBtn.disabled = true;
    else updateInputState();
  }

  /* ---------- Persistencia opcional de la API key ---------- */
  function loadKey() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        ui.apiKey.value = saved;
        ui.rememberKey.checked = true;
      }
    } catch {
      /* almacenamiento bloqueado: se ignora */
    }
  }

  function persistKey(key) {
    try {
      if (ui.rememberKey.checked && key) localStorage.setItem(STORAGE_KEY, key);
      else localStorage.removeItem(STORAGE_KEY);
    } catch {
      /* almacenamiento bloqueado: se ignora */
    }
  }

  /* ---------- Eventos ---------- */
  function clearAll() {
    ui.ipInput.value = '';
    analyzed = [];
    errors = [];
    renderInvalidNote([], 0);
    renderAll();
    setProgress(0, 1);
    setStatus('');
    updateInputState();
  }

  function init() {
    loadKey();
    updateInputState();
    renderAll();
    if (!IS_LOCAL) {
      setStatus('Esta página no puede consultar VirusTotal directamente (bloqueo CORS). Ejecuta "node server.js" y abre http://127.0.0.1:8080', 'warn');
    }

    ui.ipInput.addEventListener('input', updateInputState);
    ui.startBtn.addEventListener('click', startAnalysis);
    ui.cancelBtn.addEventListener('click', () => controller?.abort());
    ui.clearBtn.addEventListener('click', clearAll);

    ui.toggleKey.addEventListener('click', () => {
      const hidden = ui.apiKey.type === 'password';
      ui.apiKey.type = hidden ? 'text' : 'password';
      ui.toggleKey.textContent = hidden ? 'Ocultar' : 'Mostrar';
    });

    ui.rememberKey.addEventListener('change', () => persistKey(ui.apiKey.value.trim()));
    ui.apiKey.addEventListener('change', () => persistKey(ui.apiKey.value.trim()));
  }

  init();
})();
