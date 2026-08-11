(() => {
  'use strict';

  const previewMode = new URLSearchParams(window.location.search).has('preview');
  const mockEvents = new Map();
  let mockCIDR = '192.168.1.0/24';
  let mockTimer = null;

  const previewRuntime = {
    EventsOn(name, callback) { mockEvents.set(name, callback); },
    BrowserOpenURL() {},
    ClipboardSetText() {},
  };

  const previewApp = {
    async PresetCIDRs() { return ['192.168.0.0/24', '192.168.1.0/24', '192.168.8.0/24', '192.168.10.0/24']; },
    async DefaultCIDR() { return mockCIDR; },
    async SetCIDR(value) { mockCIDR = value; },
    async IsScanning() { return false; },
    async Results() { return []; },
    async ClearResults() {},
    async SaveResults() { return 'C:\\Red\\resultados_busqueda.txt'; },
    async StopScan() {
      window.clearInterval(mockTimer);
      mockEvents.get('scan:complete')?.({ count: 0, durationMs: 1300, cancelled: true });
    },
    async GetNics() {
      return [
        { name: 'Ethernet', hardware: 'Intel Ethernet Controller', hostname: 'EQUIPO', ip: ['192.168.1.34', 'fe80::15'], subnet: ['/24', '/64'], mac: 'A4:BB:6D:22:18:90', gateway: ['192.168.1.1'] },
        { name: 'Wi-Fi', hardware: 'Wireless Network Adapter', hostname: 'EQUIPO', ip: ['192.168.10.22'], subnet: ['/24'], mac: '70:CF:49:12:31:AA', gateway: [] },
      ];
    },
    async StartScan() {
      mockEvents.get('scan:start')?.({ cidr: mockCIDR });
      let scanned = 0;
      const samples = [
        { ip: '192.168.1.10', title: 'pve · Proxmox Virtual Environment', type: 'Proxmox' },
        { ip: '192.168.1.45', title: 'DiskStation', type: 'Synology' },
        { ip: '192.168.1.72', title: 'QNAP NAS', type: 'QNAP' },
      ];
      mockTimer = window.setInterval(() => {
        scanned += 96;
        mockEvents.get('scan:progress')?.({ scanned: Math.min(scanned, 768), total: 768 });
        if (scanned === 192) mockEvents.get('scan:result')?.(samples[0]);
        if (scanned === 480) mockEvents.get('scan:result')?.(samples[1]);
        if (scanned === 672) mockEvents.get('scan:result')?.(samples[2]);
        if (scanned >= 768) {
          window.clearInterval(mockTimer);
          mockEvents.get('scan:complete')?.({ count: 3, durationMs: 3400, cancelled: false });
        }
      }, 170);
    },
  };

  const App = window.go?.main?.App || (previewMode ? previewApp : undefined);
  const Runtime = window.runtime || (previewMode ? previewRuntime : undefined);

  if (!App || !Runtime) {
    document.body.innerHTML = '<div class="runtime-error"><div><strong>No se pudo iniciar la interfaz.</strong><br>Abre la aplicación desde el ejecutable de escritorio.</div></div>';
    return;
  }

  const $ = (id) => document.getElementById(id);
  const elements = {
    status: $('status'),
    statusText: $('statusText'),
    cidrInput: $('cidrInput'),
    cidrShell: $('cidrShell'),
    cidrPreset: $('cidrPreset'),
    cidrError: $('cidrError'),
    startBtn: $('startBtn'),
    stopBtn: $('stopBtn'),
    clearBtn: $('clearBtn'),
    saveBtn: $('saveBtn'),
    progressPanel: $('progressPanel'),
    progressBar: $('progressBar'),
    progressPercent: $('progressPercent'),
    progressLabel: $('progressLabel'),
    progressDetail: $('progressDetail'),
    progressTrack: document.querySelector('.progress-track'),
    refreshNicsBtn: $('refreshNicsBtn'),
    nicsList: $('nicsList'),
    totalCount: $('totalCount'),
    proxmoxCount: $('proxmoxCount'),
    synologyCount: $('synologyCount'),
    qnapCount: $('qnapCount'),
    resultsSubtitle: $('resultsSubtitle'),
    emptyState: $('emptyState'),
    groups: $('groups'),
    toastRegion: $('toastRegion'),
  };

  const state = {
    scanning: false,
    stopping: false,
    cidr: '',
    progress: { scanned: 0, total: 0 },
    results: { Proxmox: [], Synology: [], QNAP: [] },
  };

  const services = [
    { type: 'Proxmox', className: 'proxmox', color: '#f36b2b', scheme: 'https', port: 8006, description: 'Virtualización y clúster' },
    { type: 'Synology', className: 'synology', color: '#3f8cff', scheme: 'http', port: 5000, description: 'DiskStation Manager' },
    { type: 'QNAP', className: 'qnap', color: '#21a9c7', scheme: 'http', port: 8080, description: 'Administración de NAS' },
  ];

  function getErrorMessage(error) {
    if (error && typeof error === 'object' && 'message' in error) return String(error.message);
    return String(error || 'Error desconocido');
  }

  function setStatus(label, kind = 'idle') {
    elements.statusText.textContent = label;
    elements.status.className = `status-pill ${kind}`;
  }

  function showToast(message, type = '') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`.trim();
    toast.textContent = message;
    elements.toastRegion.appendChild(toast);
    window.setTimeout(() => {
      toast.classList.add('leaving');
      window.setTimeout(() => toast.remove(), 200);
    }, 2800);
  }

  function isValidCIDR(value) {
    const match = value.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
    if (!match) return false;
    const validOctets = match.slice(1, 5).every((octet) => Number(octet) >= 0 && Number(octet) <= 255);
    return validOctets && Number(match[5]) >= 0 && Number(match[5]) <= 32;
  }

  function validateCIDR(showMessage = true) {
    const value = elements.cidrInput.value.trim();
    const valid = isValidCIDR(value);
    elements.cidrShell.classList.toggle('invalid', Boolean(value) && !valid);
    elements.cidrInput.setAttribute('aria-invalid', String(Boolean(value) && !valid));
    elements.cidrError.textContent = showMessage && value && !valid ? 'Rango no válido' : '';
    updateControls();
    return valid;
  }

  function totalResults() {
    return Object.values(state.results).reduce((total, items) => total + items.length, 0);
  }

  function updateControls() {
    const hasResults = totalResults() > 0;
    const validCIDR = isValidCIDR(elements.cidrInput.value.trim());
    elements.startBtn.disabled = state.scanning || !validCIDR;
    elements.stopBtn.disabled = !state.scanning || state.stopping;
    elements.clearBtn.disabled = state.scanning || !hasResults;
    elements.saveBtn.disabled = state.scanning || !hasResults;
    elements.cidrInput.disabled = state.scanning;
    elements.cidrPreset.disabled = state.scanning;
  }

  function updateProgress(scanned, total) {
	const safeScanned = total === state.progress.total ? Math.max(state.progress.scanned, scanned) : scanned;
	state.progress = { scanned: safeScanned, total };
	const percent = total > 0 ? Math.min(100, Math.round((safeScanned / total) * 100)) : 0;
    elements.progressBar.style.width = `${percent}%`;
    elements.progressPercent.textContent = `${percent}%`;
    elements.progressDetail.textContent = total > 0
	  ? `${safeScanned.toLocaleString('es-ES')} de ${total.toLocaleString('es-ES')} comprobaciones`
      : 'Preparando el análisis';
    elements.progressTrack.setAttribute('aria-valuenow', String(percent));
  }

  function makeIcon(path) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    const node = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    node.setAttribute('d', path);
    svg.appendChild(node);
    return svg;
  }

  function createResultRow(item, service) {
    const row = document.createElement('div');
    row.className = 'result-row';

    const name = document.createElement('div');
    name.className = 'result-name';
    const title = document.createElement('strong');
    title.textContent = item.title || `${service.type} en ${item.ip}`;
    const caption = document.createElement('span');
    caption.textContent = service.description;
    name.append(title, caption);

    const address = document.createElement('code');
    address.className = 'result-address';
    address.textContent = `${item.ip}:${service.port}`;

    const actions = document.createElement('div');
    actions.className = 'row-actions';

    const copy = document.createElement('button');
    copy.type = 'button';
    copy.className = 'result-action';
    copy.title = `Copiar ${item.ip}`;
    copy.append(makeIcon('M9 9h10v10H9z M5 15H4V5h10v1'), document.createTextNode('Copiar'));
    copy.addEventListener('click', async () => {
      try {
        if (typeof Runtime.ClipboardSetText === 'function') await Runtime.ClipboardSetText(item.ip);
        else await navigator.clipboard.writeText(item.ip);
        showToast(`IP copiada: ${item.ip}`, 'success');
      } catch (error) {
        showToast(`No se pudo copiar: ${getErrorMessage(error)}`, 'error');
      }
    });

    const open = document.createElement('button');
    open.type = 'button';
    open.className = 'result-action open';
    open.append(makeIcon('M14 5h5v5 M19 5l-8 8 M11 7H5v12h12v-6'), document.createTextNode('Abrir'));
    open.addEventListener('click', () => Runtime.BrowserOpenURL(`${service.scheme}://${item.ip}:${service.port}`));

    actions.append(copy, open);
    row.append(name, address, actions);
    return row;
  }

  function renderResults() {
    const total = totalResults();
    elements.totalCount.textContent = String(total);
    elements.proxmoxCount.textContent = String(state.results.Proxmox.length);
    elements.synologyCount.textContent = String(state.results.Synology.length);
    elements.qnapCount.textContent = String(state.results.QNAP.length);
    elements.emptyState.hidden = total > 0;
    elements.groups.replaceChildren();

    for (const service of services) {
      const items = state.results[service.type];
      if (!items.length) continue;

      const group = document.createElement('article');
      group.className = 'result-group';
      group.style.setProperty('--service-color', service.color);

      const header = document.createElement('div');
      header.className = 'group-header';
      const accent = document.createElement('span');
      accent.className = 'group-accent';
      const heading = document.createElement('div');
      heading.className = 'group-title';
      const title = document.createElement('strong');
      title.textContent = service.type;
      const detail = document.createElement('span');
      detail.textContent = service.description;
      heading.append(title, detail);
      const count = document.createElement('span');
      count.className = 'group-count';
      count.textContent = `${items.length} ${items.length === 1 ? 'dispositivo' : 'dispositivos'}`;
      header.append(accent, heading, count);
      group.appendChild(header);

      [...items]
        .sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }))
        .forEach((item) => group.appendChild(createResultRow(item, service)));
      elements.groups.appendChild(group);
    }

    elements.resultsSubtitle.textContent = total > 0
      ? `${total} ${total === 1 ? 'servicio detectado' : 'servicios detectados'} en ${state.cidr || 'la red seleccionada'}.`
      : 'Los resultados aparecerán en tiempo real durante el escaneo.';
    updateControls();
  }

  function deriveCIDR(ip, prefixValue) {
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return '';
    const prefix = Number(String(prefixValue || '/24').replace('/', ''));
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return '';
    const value = ip.split('.').reduce((acc, octet) => ((acc << 8) | Number(octet)) >>> 0, 0);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const network = (value & mask) >>> 0;
    return [24, 16, 8, 0].map((shift) => (network >>> shift) & 255).join('.') + `/${prefix}`;
  }

  async function selectCIDR(value) {
    if (!value) return;
    elements.cidrInput.value = value;
    elements.cidrPreset.value = [...elements.cidrPreset.options].some((option) => option.value === value) ? value : '';
    validateCIDR(false);
    try {
      await App.SetCIDR(value);
      state.cidr = value;
    } catch (error) {
      elements.cidrError.textContent = getErrorMessage(error);
    }
  }

  function renderNics(nics) {
    elements.nicsList.replaceChildren();
    if (!Array.isArray(nics) || nics.length === 0) {
      const message = document.createElement('div');
      message.className = 'network-message';
      message.textContent = 'No hay conexiones activas disponibles.';
      elements.nicsList.appendChild(message);
      return;
    }

    for (const nic of nics) {
      const card = document.createElement('article');
      card.className = 'nic-card';
      const top = document.createElement('div');
      top.className = 'nic-card-top';
      const dot = document.createElement('span');
      dot.className = 'nic-status';
      const title = document.createElement('div');
      title.className = 'nic-title';
      const name = document.createElement('strong');
      name.textContent = nic.name || nic.hardware || 'Adaptador de red';
      name.title = nic.name || nic.hardware || '';
      const hardware = document.createElement('span');
      hardware.textContent = nic.mac || nic.hardware || nic.hostname || 'Conexión activa';
      hardware.title = nic.hardware || '';
      title.append(name, hardware);
      top.append(dot, title);
      card.appendChild(top);

      const ipv4Index = (nic.ip || []).findIndex((ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip));
      const ipv4 = ipv4Index >= 0 ? nic.ip[ipv4Index] : (nic.ip || [])[0];
      if (ipv4) {
        const address = document.createElement('div');
        address.className = 'nic-address';
        const code = document.createElement('code');
        code.textContent = ipv4 + ((nic.subnet || [])[ipv4Index] || '');
        address.appendChild(code);
        const suggestedCIDR = deriveCIDR(ipv4, (nic.subnet || [])[ipv4Index]);
        if (suggestedCIDR) {
          const use = document.createElement('button');
          use.type = 'button';
          use.className = 'use-network';
          use.textContent = 'Usar esta red';
          use.addEventListener('click', () => selectCIDR(suggestedCIDR));
          address.appendChild(use);
        }
        card.appendChild(address);
      }
      elements.nicsList.appendChild(card);
    }
  }

  async function loadNics() {
    elements.refreshNicsBtn.classList.add('loading');
    elements.refreshNicsBtn.disabled = true;
    try {
      renderNics(await App.GetNics());
    } catch (error) {
      elements.nicsList.innerHTML = '';
      const message = document.createElement('div');
      message.className = 'network-message error';
      message.textContent = `No se pudieron cargar las conexiones: ${getErrorMessage(error)}`;
      elements.nicsList.appendChild(message);
    } finally {
      elements.refreshNicsBtn.classList.remove('loading');
      elements.refreshNicsBtn.disabled = false;
    }
  }

  function wireBackendEvents() {
    Runtime.EventsOn('scan:start', (data) => {
      state.scanning = true;
      state.stopping = false;
      state.cidr = data.cidr;
      state.results = { Proxmox: [], Synology: [], QNAP: [] };
      elements.progressPanel.hidden = false;
      elements.progressLabel.textContent = 'Analizando direcciones…';
      updateProgress(0, 0);
      renderResults();
      setStatus(`Escaneando ${data.cidr}`, 'scanning');
    });

    Runtime.EventsOn('scan:progress', (data) => updateProgress(Number(data.scanned || 0), Number(data.total || 0)));

    Runtime.EventsOn('scan:result', (result) => {
      if (!state.results[result.type]) return;
      const duplicate = state.results[result.type].some((item) => item.ip === result.ip);
      if (!duplicate) state.results[result.type].push(result);
      renderResults();
    });

    Runtime.EventsOn('scan:complete', (data) => {
      state.scanning = false;
      state.stopping = false;
      elements.progressPanel.hidden = true;
      const seconds = (Number(data.durationMs || 0) / 1000).toFixed(1);
      if (data.cancelled) {
        setStatus(`Escaneo detenido · ${data.count} encontrados`, 'idle');
        showToast('Escaneo detenido. Se conservan los resultados parciales.');
      } else {
        setStatus(`Completado · ${data.count} encontrados · ${seconds}s`, 'done');
        showToast(`Escaneo completado: ${data.count} encontrados`, 'success');
      }
      renderResults();
    });

    Runtime.EventsOn('scan:error', (data) => {
      state.scanning = false;
      state.stopping = false;
      elements.progressPanel.hidden = true;
      setStatus('Error durante el escaneo', 'error');
      showToast(`Error: ${data.message}`, 'error');
      updateControls();
    });
  }

  elements.cidrPreset.addEventListener('change', () => selectCIDR(elements.cidrPreset.value));

  elements.cidrInput.addEventListener('input', () => {
    elements.cidrPreset.value = '';
    validateCIDR(true);
  });

  elements.cidrInput.addEventListener('blur', async () => {
    const value = elements.cidrInput.value.trim();
    if (isValidCIDR(value)) await selectCIDR(value);
  });

  elements.cidrInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !elements.startBtn.disabled) elements.startBtn.click();
  });

  elements.startBtn.addEventListener('click', async () => {
    const cidr = elements.cidrInput.value.trim();
    if (!validateCIDR(true)) return;
    elements.startBtn.disabled = true;
    try {
      await App.SetCIDR(cidr);
      state.cidr = cidr;
      await App.StartScan();
    } catch (error) {
      showToast(`No se pudo iniciar: ${getErrorMessage(error)}`, 'error');
      updateControls();
    }
  });

  elements.stopBtn.addEventListener('click', async () => {
    state.stopping = true;
    elements.progressLabel.textContent = 'Deteniendo el escaneo…';
    setStatus('Deteniendo…', 'scanning');
    updateControls();
    try {
      await App.StopScan();
    } catch (error) {
      state.stopping = false;
      showToast(`No se pudo detener: ${getErrorMessage(error)}`, 'error');
      updateControls();
    }
  });

  elements.clearBtn.addEventListener('click', async () => {
    try {
      await App.ClearResults();
      state.results = { Proxmox: [], Synology: [], QNAP: [] };
      renderResults();
      setStatus('Preparado', 'idle');
    } catch (error) {
      showToast(`No se pudo limpiar: ${getErrorMessage(error)}`, 'error');
    }
  });

  elements.saveBtn.addEventListener('click', async () => {
    try {
      const path = await App.SaveResults();
      if (path) showToast(`Resultados guardados en ${path}`, 'success');
    } catch (error) {
      showToast(`No se pudo exportar: ${getErrorMessage(error)}`, 'error');
    }
  });

  elements.refreshNicsBtn.addEventListener('click', loadNics);

  async function init() {
    wireBackendEvents();
    try {
      const [presets, defaultCIDR, currentResults, scanning] = await Promise.all([
        App.PresetCIDRs(),
        App.DefaultCIDR(),
        App.Results(),
        App.IsScanning(),
      ]);

      for (const cidr of presets || []) {
        const option = document.createElement('option');
        option.value = cidr;
        option.textContent = cidr;
        elements.cidrPreset.appendChild(option);
      }
      await selectCIDR(defaultCIDR || '192.168.1.0/24');

      for (const result of currentResults || []) {
        if (state.results[result.type]) state.results[result.type].push(result);
      }
      state.scanning = Boolean(scanning);
      if (state.scanning) {
        elements.progressPanel.hidden = false;
        setStatus(`Escaneando ${state.cidr}`, 'scanning');
      }
      renderResults();
    } catch (error) {
      setStatus('No se pudo inicializar', 'error');
      showToast(`Error de inicio: ${getErrorMessage(error)}`, 'error');
    }
    await loadNics();
  }

  init();
})();
