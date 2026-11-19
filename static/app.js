const body = document.querySelector('#table-body');
const stateFilter = document.querySelector('#status-filter');
const severityFilter = document.querySelector('#severity-filter');
const searchInput = document.querySelector('#search');
const dialog = document.querySelector('#create-dialog');
const form = document.querySelector('#create-form');
const toast = document.querySelector('#toast');
let toastTimer;

function showToast(message) {
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 2600);
}

function escapeHtml(value = '') {
  return String(value).replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
}

function statusClass(value) {
  return value.toLowerCase().replaceAll(' ', '-').normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

function severityClass(value) {
  return value.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

function formatDate(value) {
  if (!value) return 'Sem prazo';
  return new Intl.DateTimeFormat('pt-BR', {timeZone: 'UTC'}).format(new Date(`${value}T00:00:00Z`));
}

async function loadSummary() {
  const response = await fetch('/api/summary');
  const data = await response.json();
  document.querySelector('#metric-total').textContent = data.total;
  document.querySelector('#metric-open').textContent = data.open;
  document.querySelector('#metric-critical').textContent = data.critical;
  document.querySelector('#metric-overdue').textContent = data.overdue;
  document.querySelector('#nav-count').textContent = data.total;
}

async function loadItems() {
  body.innerHTML = '<tr><td colspan="7" class="loading">Carregando inventário…</td></tr>';
  const params = new URLSearchParams();
  if (stateFilter.value) params.set('status', stateFilter.value);
  if (severityFilter.value) params.set('severity', severityFilter.value);
  if (searchInput.value.trim()) params.set('search', searchInput.value.trim());
  const response = await fetch(`/api/vulnerabilities?${params}`);
  if (!response.ok) {
    body.innerHTML = '<tr><td colspan="7" class="empty">Não foi possível carregar os registros.</td></tr>';
    return;
  }
  const items = await response.json();
  document.querySelector('#result-count').textContent = `${items.length} ${items.length === 1 ? 'registro' : 'registros'}`;
  if (!items.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">Nenhuma vulnerabilidade encontrada para esses filtros.</td></tr>';
    return;
  }
  body.innerHTML = items.map((item) => {
    const pastDue = item.due_date && item.due_date < new Date().toISOString().slice(0, 10) && !['Validada', 'Aceita'].includes(item.status);
    const statusOptions = ['Aberta', 'Em análise', 'Em correção', 'Validada', 'Aceita']
      .map((value) => `<option ${value === item.status ? 'selected' : ''}>${value}</option>`).join('');
    return `<tr>
      <td><div class="vuln-title">${escapeHtml(item.title)}</div><div class="vuln-sub">${item.cve ? escapeHtml(item.cve) : 'Sem CVE'}${item.cvss !== null ? ` · CVSS ${Number(item.cvss).toFixed(1)}` : ''}</div></td>
      <td><span class="asset-chip">${escapeHtml(item.asset)}</span></td>
      <td><span class="severity ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span></td>
      <td><select class="status-select ${statusClass(item.status)}" data-id="${item.id}" aria-label="Alterar status de ${escapeHtml(item.title)}">${statusOptions}</select></td>
      <td>${escapeHtml(item.owner || '—')}</td><td class="${pastDue ? 'date-overdue' : ''}">${formatDate(item.due_date)}</td>
      <td><button class="row-menu" data-delete="${item.id}" aria-label="Excluir registro">···</button></td>
    </tr>`;
  }).join('');
  body.querySelectorAll('.status-select').forEach((select) => select.addEventListener('change', updateStatus));
  body.querySelectorAll('[data-delete]').forEach((button) => button.addEventListener('click', removeItem));
}

async function refresh() {
  await Promise.all([loadSummary(), loadItems()]);
}

async function updateStatus(event) {
  const select = event.currentTarget;
  const response = await fetch(`/api/vulnerabilities/${select.dataset.id}/status`, {
    method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({status: select.value})
  });
  if (!response.ok) {
    const detail = await response.json();
    showToast(detail.detail || 'Transição de status não permitida.');
    await loadItems();
    return;
  }
  showToast('Status atualizado.');
  await refresh();
}

async function removeItem(event) {
  const id = event.currentTarget.dataset.delete;
  if (!window.confirm('Excluir este registro de demonstração?')) return;
  const response = await fetch(`/api/vulnerabilities/${id}`, {method: 'DELETE'});
  if (response.ok) { showToast('Registro excluído.'); await refresh(); }
  else showToast('Não foi possível excluir o registro.');
}

document.querySelector('#new-button').addEventListener('click', () => dialog.showModal());
document.querySelector('#close-dialog').addEventListener('click', () => dialog.close());
document.querySelector('#cancel-dialog').addEventListener('click', () => dialog.close());
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(form));
  if (!data.cvss) data.cvss = null;
  else data.cvss = Number(data.cvss);
  for (const key of ['cve', 'due_date', 'owner']) if (!data[key]) data[key] = null;
  const response = await fetch('/api/vulnerabilities', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)});
  if (!response.ok) {
    const error = await response.json();
    showToast(error.detail?.[0]?.msg || error.detail || 'Revise os campos e tente novamente.');
    return;
  }
  form.reset(); dialog.close(); showToast('Vulnerabilidade cadastrada.'); await refresh();
});

let searchTimer;
searchInput.addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(loadItems, 220); });
stateFilter.addEventListener('change', loadItems);
severityFilter.addEventListener('change', loadItems);
document.querySelector('#export-button').addEventListener('click', async () => {
  const response = await fetch('/api/vulnerabilities');
  const items = await response.json();
  const columns = ['title','cve','asset','severity','cvss','status','due_date','owner','mitigation'];
  const quote = (value) => `"${String(value ?? '').replaceAll('"', '""')}"`;
  const csv = '\ufeff' + [columns.join(';'), ...items.map((item) => columns.map((key) => quote(item[key])).join(';'))].join('\r\n');
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([csv], {type: 'text/csv;charset=utf-8'}));
  link.download = 'vulntrack-inventario.csv'; link.click(); URL.revokeObjectURL(link.href);
});

refresh().catch(() => showToast('A API está indisponível. Tente recarregar a página.'));
