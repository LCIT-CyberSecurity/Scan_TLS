(function(){
  'use strict';

  const data = JSON.parse(document.getElementById('report-data').textContent);
  const $ = (id) => document.getElementById(id);
  const severityOrder = {critical:0, high:1, medium:2, low:3, informational:4, none:5};
  const gradeOrder = {'A+':0, A:1, B:2, C:3, D:4, F:5, 'Not Tested':6};
  const severityColors = {critical:'#d92d20', high:'#f04438', medium:'#f79009', low:'#facc15', informational:'#2563eb', none:'#64748b'};
  const complianceColors = ['#16a34a','#ef4444','#f59e0b','#64748b'];
  const gradeColors = {'A+':'#16a34a', A:'#22c55e', B:'#3b82f6', C:'#facc15', D:'#f97316', F:'#ef4444', 'Not Tested':'#64748b'};

  const normalize = (value) => String(value == null || value === '' ? '-' : value);
  const pct = (part,total) => total ? Math.round(Number(part || 0) * 100 / total) : 0;

  function el(tag, cls, value){
    const node = document.createElement(tag);
    if(cls) node.className = cls;
    if(value !== undefined) node.textContent = normalize(value);
    return node;
  }

  function valueNode(value, cls){
    const node = el('span', cls ? `truncate ${cls}` : 'truncate', value);
    node.title = normalize(value);
    return node;
  }

  function button(label, onClick, cls){
    const node = el('button', cls || 'button', label);
    node.type = 'button';
    node.addEventListener('click', onClick);
    return node;
  }

  function copyButton(value){
    const node = button('Copy', () => copyText(normalize(value)), 'copy-button no-print');
    node.setAttribute('aria-label', `Copy ${normalize(value)}`);
    return node;
  }

  function copyText(value){
    if(navigator.clipboard && window.isSecureContext){
      navigator.clipboard.writeText(value).catch(() => fallbackCopy(value));
      return;
    }
    fallbackCopy(value);
  }

  function fallbackCopy(value){
    const input = document.createElement('textarea');
    input.value = value;
    input.setAttribute('readonly', '');
    input.style.position = 'fixed';
    input.style.left = '-9999px';
    document.body.append(input);
    input.select();
    document.execCommand('copy');
    input.remove();
  }

  function badge(value, cls){ return el('span', `badge ${cls || ''}`, value); }
  function severityClass(value){ return `severity-${String(value || 'informational').toLowerCase()}`; }
  function statusClass(value){ return `status-${String(value || 'not_tested').toLowerCase().replace(/[\s-]+/g,'_')}`; }
  function gradeClass(value){ return `grade-${String(value || 'not-tested').replace('+','plus').replace(/\s+/g,'-').toLowerCase()}`; }

  function metricCard(label, value, tone, extra){
    const card = el('article', `metric-card ${tone ? `tone-${tone}` : ''}`);
    card.append(el('div','metric-label',label), el('div','metric-value',value));
    if(extra) card.append(el('div','metric-extra',extra));
    return card;
  }

  function infoItem(label, value, copy){
    const item = el('div','info-item');
    item.append(el('span','info-label',label));
    const row = el('div','info-value-row');
    row.append(valueNode(value, 'info-value'));
    if(copy) row.append(copyButton(value));
    item.append(row);
    return item;
  }

  function cellText(cell){
    if(cell instanceof Node) return cell.textContent || '';
    return normalize(cell);
  }

  function compareValues(a, b){
    const left = String(a).trim();
    const right = String(b).trim();
    const leftNumber = Number(left.replace(/[^0-9.-]/g, ''));
    const rightNumber = Number(right.replace(/[^0-9.-]/g, ''));
    if(left !== '' && right !== '' && !Number.isNaN(leftNumber) && !Number.isNaN(rightNumber)) return leftNumber - rightNumber;
    return left.localeCompare(right, undefined, {numeric:true, sensitivity:'base'});
  }

  function renderRows(tbody, rows){
    tbody.textContent = '';
    rows.forEach((cells) => {
      const row = document.createElement('tr');
      cells.forEach((cell) => {
        const td = document.createElement('td');
        if(cell instanceof Node) td.append(cell); else td.append(valueNode(cell));
        row.append(td);
      });
      tbody.append(row);
    });
  }

  function table(headers, rows, options){
    const sortable = !options || options.sortable !== false;
    const wrap = el('div','table-wrap');
    const t = document.createElement('table');
    const thead = document.createElement('thead');
    const tr = document.createElement('tr');
    const tbody = document.createElement('tbody');
    const state = {index:-1, direction:1};
    headers.forEach((h, index) => {
      const th = el('th','',h);
      if(sortable){
        const sortButton = button(h, () => {
          state.direction = state.index === index ? state.direction * -1 : 1;
          state.index = index;
          const sorted = [...rows].sort((a,b) => compareValues(cellText(a[index]), cellText(b[index])) * state.direction);
          renderRows(tbody, sorted);
          Array.from(tr.children).forEach((item) => item.removeAttribute('aria-sort'));
          th.setAttribute('aria-sort', state.direction === 1 ? 'ascending' : 'descending');
        }, 'table-sort');
        sortButton.title = `Sort by ${h}`;
        th.append(sortButton);
      } else {
        th.textContent = h;
      }
      tr.append(th);
    });
    thead.append(tr);
    renderRows(tbody, rows);
    t.append(thead, tbody);
    wrap.append(t);
    return wrap;
  }

  function barChart(title, counts, unit, colorResolver){
    const card = el('article','card chart chart-bars');
    card.append(el('h3','',title));
    const total = Object.values(counts).reduce((a,b) => a + Number(b || 0), 0);
    Object.entries(counts).forEach(([label,count]) => {
      const row = el('div','bar-row');
      const top = el('div','bar-top');
      top.append(valueNode(label, 'bar-label'), el('strong','bar-value',`${count}${unit ? ` ${unit}` : ''}`));
      const track = el('div','bar-track');
      const fill = el('div','bar-fill');
      fill.style.width = `${pct(count,total)}%`;
      fill.style.background = colorResolver ? colorResolver(label) : '#2563eb';
      track.append(fill);
      row.append(top, track);
      card.append(row);
    });
    if(!total) card.append(el('p','muted','No data available.'));
    return card;
  }

  function donutChart(title, counts, colors){
    const card = el('article','card chart chart-donut');
    card.append(el('h3','',title));
    const total = Object.values(counts).reduce((a,b) => a + Number(b || 0), 0);
    let start = 0;
    const stops = [];
    Object.values(counts).forEach((count, index) => {
      const deg = total ? Number(count || 0) * 360 / total : 0;
      stops.push(`${colors[index % colors.length]} ${start}deg ${start + deg}deg`);
      start += deg;
    });
    const visual = el('div','donut-wrap');
    const donut = el('div','donut');
    donut.style.background = `conic-gradient(${stops.join(',') || '#e2e8f0 0deg 360deg'})`;
    donut.setAttribute('role','img');
    donut.setAttribute('aria-label', Object.entries(counts).map(([k,v]) => `${k}: ${v}`).join(', '));
    const center = el('div','donut-center');
    center.append(el('strong','',`${total}`), el('span','','total'));
    donut.append(center);
    visual.append(donut);
    const legend = el('div','legend');
    Object.entries(counts).forEach(([label,count], index) => {
      const item = el('span','legend-item');
      const swatch = el('i','');
      swatch.style.background = colors[index % colors.length];
      item.append(swatch, valueNode(`${label}: ${count}`));
      legend.append(item);
    });
    card.append(visual, legend);
    return card;
  }

  function priorityActions(){
    const s = data.statistics;
    const actions = [];
    if(s.critical_findings) actions.push(['Critical', `${s.critical_findings} critical finding(s) need immediate ownership`, 'critical']);
    if(s.high_findings) actions.push(['High', `${s.high_findings} high-risk finding(s) should be prioritized`, 'high']);
    if(s.certificates_expiring_soon) actions.push(['Certificates', `${s.certificates_expiring_soon} certificate(s) expire soon`, 'medium']);
    if(s.endpoints_with_errors) actions.push(['Coverage', `${s.endpoints_with_errors} endpoint(s) need scan reliability review`, 'low']);
    if(!actions.length) actions.push(['Maintain', 'Keep policy monitoring and certificate renewal cadence active', 'informational']);
    actions.slice(0,4).forEach(([label,text,tone]) => {
      const item = el('div',`priority-item ${severityClass(tone)}`);
      item.append(badge(label, severityClass(tone)), valueNode(text));
      $('priorityActions').append(item);
    });
  }

  function initContext(){
    const m = data.metadata, s = data.statistics;
    $('overallGrade').textContent = s.overall_grade;
    $('overallGrade').className = gradeClass(s.overall_grade);
    $('overallCompliance').textContent = s.compliance_status;
    $('overallCompliance').className = `score-status ${statusClass(s.compliance_status)}`;
    $('scoreMeta').append(
      el('span','',`${s.total_endpoints} endpoints`),
      el('span','',`${pct(s.compliant_endpoints, s.total_endpoints)}% compliant`)
    );
    const policyName = data.policies.map((p) => p.name).join(', ') || 'Legacy scanner policy';
    const rows = [
      ['Scan Date', m.scan_timestamp, false],
      ['Duration', m.scan_duration_seconds == null ? 'Not Recorded' : `${m.scan_duration_seconds}s`, false],
      ['Policy', policyName, true],
      ['Scanner Version', m.scanner_version, false],
      ['Ports', m.ports, false],
      ['Run ID', m.scan_run_id || '-', true],
    ];
    rows.forEach(([label,value,copy]) => $('scanContext').append(infoItem(label,value,copy)));
    priorityActions();
  }

  function initKpis(){
    const s = data.statistics;
    const severity = s.findings_by_severity || {};
    const unique = (name) => severity[name] ? severity[name].unique : 0;
    [
      ['Hosts', s.total_hosts, 'info'],
      ['Endpoints', s.total_endpoints, 'info'],
      ['Critical', unique('critical'), 'critical'],
      ['High', unique('high'), 'high'],
      ['Medium', unique('medium'), 'medium'],
      ['Low', unique('low'), 'low'],
      ['Passed', s.compliant_endpoints, 'pass'],
      ['Failed', s.non_compliant_endpoints + s.endpoints_with_errors, 'fail'],
    ].forEach(([label,value,tone]) => $('kpis').append(metricCard(label,value,tone)));
  }

  function initCharts(){
    const s = data.statistics;
    $('charts').append(barChart('Grade Distribution', s.grade_distribution, '', (label) => gradeColors[label] || '#64748b'));
    $('charts').append(donutChart('Endpoint Compliance', s.endpoint_compliance, complianceColors));
    $('charts').append(barChart('Findings by Severity', Object.fromEntries(Object.entries(s.findings_by_severity).map(([k,v]) => [k, v.occurrences])), '', (label) => severityColors[label] || '#64748b'));
    $('charts').append(barChart('Top Findings', Object.fromEntries(s.top_findings.map((f) => [f.title, f.affected_endpoints])), 'endpoint(s)', (label) => severityColors[(s.top_findings.find((f) => f.title === label) || {}).severity] || '#2563eb'));
    $('charts').append(barChart('TLS Version Distribution', s.tls_version_distribution, '', (label) => label.includes('1.3') ? '#16a34a' : label.includes('1.2') ? '#2563eb' : '#f97316'));
    $('charts').append(donutChart('Certificate Status', s.certificate_status, ['#16a34a','#facc15','#ef4444','#f97316','#d92d20','#b91c1c','#64748b']));
    $('charts').append(barChart('Certificate Expiration Timeline', s.certificate_expiration_timeline, '', (label) => label.includes('expired') ? '#ef4444' : label.includes('7') || label.includes('30') ? '#f97316' : '#2563eb'));
    $('charts').append(donutChart('PQC Readiness', s.pqc_readiness, ['#16a34a','#f97316','#64748b','#ef4444']));
  }

  function findingCard(finding){
    const card = el('article',`finding-card card ${severityClass(finding.severity)}`);
    const head = el('div','finding-head');
    const title = el('div','finding-title');
    title.append(badge(finding.severity, severityClass(finding.severity)), valueNode(finding.title, 'finding-name'));
    const impacted = el('div','impact-count');
    impacted.append(el('strong','',finding.affected_endpoint_ids.length), el('span','','impacted endpoint(s)'));
    head.append(title, impacted);
    const body = el('div','finding-body');
    [['Risk', finding.technical_impact], ['Recommendation', finding.remediation], ['Evidence', finding.evidence]].forEach(([label,value]) => {
      const block = el('div','finding-block');
      block.append(el('span','block-label',label), valueNode(value));
      body.append(block);
    });
    const foot = el('div','finding-foot');
    foot.append(valueNode(finding.finding_id, 'mono'), copyButton(finding.finding_id));
    if(finding.policy_ids && finding.policy_ids.length) foot.append(valueNode(finding.policy_ids.join(', '), 'mono'));
    card.append(head, body, foot);
    return card;
  }

  function initFindings(){
    const filters = $('findingFilters');
    const search = document.createElement('input');
    search.placeholder = 'Search findings';
    search.setAttribute('aria-label','Search findings');
    const sev = document.createElement('select');
    sev.setAttribute('aria-label','Filter by severity');
    ['all','critical','high','medium','low','informational'].forEach((value) => sev.add(new Option(value === 'all' ? 'All severities' : value, value)));
    filters.append(search, sev);
    const render = () => {
      const q = search.value.toLowerCase();
      const findings = data.findings
        .filter((f) => (sev.value === 'all' || f.severity === sev.value) && JSON.stringify(f).toLowerCase().includes(q))
        .sort((a,b) => severityOrder[a.severity] - severityOrder[b.severity] || b.affected_endpoint_ids.length - a.affected_endpoint_ids.length || a.title.localeCompare(b.title));
      $('findingCount').textContent = `${findings.length} shown`;
      $('findingsList').replaceChildren(...findings.map(findingCard));
      if(!findings.length) $('findingsList').append(el('div','empty','No findings match the current filters.'));
    };
    search.addEventListener('input', render);
    sev.addEventListener('change', render);
    render();
  }

  function endpointCard(endpoint){
    const card = el('article','endpoint-card card');
    const head = el('div','endpoint-head');
    const identity = el('div','endpoint-identity');
    identity.append(valueNode(endpoint.hostname, 'endpoint-host'), valueNode(`${endpoint.ip_address}:${endpoint.port}/${endpoint.protocol}`, 'endpoint-address'));
    head.append(identity, badge(endpoint.overall_grade, `grade-badge ${gradeClass(endpoint.overall_grade)}`));
    const grid = el('div','endpoint-grid');
    const tls = (endpoint.supported_tls_versions || []).join(', ') || 'Not Tested';
    const cert = endpoint.certificate.valid_until || endpoint.certificate.status;
    [
      ['Compliance', endpoint.compliance_status, statusClass(endpoint.compliance_status)],
      ['Protocols', tls, ''],
      ['Certificate', cert, ''],
      ['Findings', endpoint.finding_count, severityClass(endpoint.highest_severity)],
      ['Highest Severity', endpoint.highest_severity, severityClass(endpoint.highest_severity)],
      ['PQC', endpoint.pqc.readiness, ''],
    ].forEach(([label,value,cls]) => {
      const item = el('div','endpoint-field');
      item.append(el('span','field-label',label), valueNode(value, cls));
      grid.append(item);
    });
    const actions = el('div','endpoint-actions');
    actions.append(copyButton(endpoint.endpoint_id), button('Open details', () => openEndpoint(endpoint.endpoint_id), 'button'));
    card.append(head, grid, actions);
    return card;
  }

  function initEndpoints(){
    const filters = $('endpointFilters');
    const search = document.createElement('input');
    search.placeholder = 'Search endpoints';
    search.setAttribute('aria-label','Search endpoints');
    const compliance = document.createElement('select');
    compliance.setAttribute('aria-label','Filter by compliance');
    ['all','compliant','non_compliant','error','not_tested'].forEach((value) => compliance.add(new Option(value === 'all' ? 'All compliance states' : value, value)));
    const sort = document.createElement('select');
    sort.setAttribute('aria-label','Sort endpoints');
    [['severity','Severity'],['hostname','Hostname'],['grade','Grade'],['findings','Finding count'],['expiration','Certificate expiration']].forEach(([value,label]) => sort.add(new Option(`Sort by ${label}`, value)));
    filters.append(search, compliance, sort);
    const render = () => {
      let rows = data.endpoints.filter((endpoint) => (compliance.value === 'all' || endpoint.compliance_status === compliance.value) && JSON.stringify(endpoint).toLowerCase().includes(search.value.toLowerCase()));
      rows.sort((a,b) => {
        if(sort.value === 'findings') return b.finding_count - a.finding_count;
        if(sort.value === 'expiration') return String(a.certificate.valid_until).localeCompare(String(b.certificate.valid_until));
        if(sort.value === 'grade') return (gradeOrder[a.overall_grade] ?? 99) - (gradeOrder[b.overall_grade] ?? 99);
        if(sort.value === 'severity') return (severityOrder[a.highest_severity] ?? 9) - (severityOrder[b.highest_severity] ?? 9) || b.finding_count - a.finding_count;
        return a.hostname.localeCompare(b.hostname);
      });
      $('endpointCount').textContent = `${rows.length} shown${rows.length > 500 ? ' - first 500 rendered' : ''}`;
      $('endpointTable').replaceChildren(...rows.slice(0,500).map(endpointCard));
      if(!rows.length) $('endpointTable').append(el('div','empty','No endpoints match the current filters.'));
    };
    [search, compliance, sort].forEach((node) => node.addEventListener('input', render));
    render();
  }

  function initCertificates(){
    const filters = $('certificateFilters');
    const status = document.createElement('select');
    status.setAttribute('aria-label','Filter certificates by status');
    ['all','Valid','Expiring soon','Expired','Self-signed','Weak key','Weak signature','Validation not tested'].forEach((value) => status.add(new Option(value === 'all' ? 'All certificate states' : value, value)));
    filters.append(status);
    const render = () => {
      const rows = data.endpoints
        .filter((endpoint) => status.value === 'all' || endpoint.certificate.status === status.value)
        .map((endpoint) => [endpoint.endpoint_id, endpoint.certificate.subject, endpoint.certificate.issuer, (endpoint.certificate.san || []).join(', '), endpoint.certificate.valid_until, endpoint.certificate.remaining_days, endpoint.certificate.self_signed, endpoint.certificate.key_type, endpoint.certificate.key_size, endpoint.certificate.signature_algorithm, endpoint.certificate.trust_status, endpoint.certificate.hostname_validation_status, endpoint.certificate.chain_validation_status, endpoint.certificate.revocation_status]);
      $('certificateTable').replaceChildren(table(['Endpoint','Subject','Issuer','SAN','Expiration','Remaining days','Self-signed','Key type','Key size','Signature','Trust','Hostname validation','Chain validation','Revocation'], rows));
    };
    status.addEventListener('change', render);
    render();
  }

  function initCompliance(){
    data.policies.forEach((policy) => {
      const card = el('article','policy-card card');
      card.append(el('h3','',`${policy.name}${policy.version ? ` v${policy.version}` : ''}`), el('p','muted',policy.description || 'Selected policy'));
      const progress = el('div','progress');
      const fill = el('span','');
      fill.style.width = `${policy.compliance_percentage}%`;
      progress.append(fill);
      card.append(progress, el('p','',`${policy.compliance_percentage}% compliant - ${policy.non_compliant_endpoints} non-compliant endpoint(s), ${policy.failed_controls} failed control occurrence(s).`));
      $('policyCompliance').append(card);
    });
    if(!data.policies.length) $('policyCompliance').append(el('div','empty','No policy summary is available.'));
  }

  function initPqc(){
    Object.entries(data.statistics.pqc_readiness).forEach(([key,value]) => $('pqcReadiness').append(metricCard(key,value,'info')));
    $('pqcReadiness').append(metricCard('Readiness Meaning','Internal TLS Scan indicator','info','This is not a certification or an official standard.'));
  }

  function openEndpoint(id){
    const endpoint = data.endpoints.find((item) => item.endpoint_id === id);
    if(!endpoint) return;
    const root = $('drawerContent');
    root.textContent = '';
    root.append(el('h2','',`${endpoint.hostname}:${endpoint.port}`));
    root.append(table(['Field','Value'], [['Endpoint ID', endpoint.endpoint_id], ['IP address', endpoint.ip_address], ['Protocol', endpoint.protocol], ['Overall Grade', endpoint.overall_grade], ['Compliance Status', endpoint.compliance_status], ['Findings', endpoint.finding_count], ['Highest Severity', endpoint.highest_severity]]));
    root.append(el('h3','','Security Breakdown'), table(['Area','Result'], Object.entries(endpoint.security_breakdown)));
    root.append(el('h3','','Findings'), table(['Finding'], endpoint.finding_ids.map((finding) => [finding])));
    root.append(el('h3','','TLS Versions'), table(['Version','Status'], Object.entries(endpoint.tls_versions)));
    root.append(el('h3','','Cipher Suites'), table(['TLS version','Cipher suite','Key exchange','Authentication','Encryption','Hash','Forward secrecy','Strength','Compliance','Policy reason'], endpoint.cipher_suites.slice(0,300).map((suite) => [suite.tls_version, suite.name, suite.key_exchange, suite.authentication, suite.encryption, suite.hash_algorithm, suite.forward_secrecy, suite.strength, suite.compliance_status, suite.policy_reason])));
    root.append(el('h3','','Certificate'), table(['Field','Value'], Object.entries(endpoint.certificate).map(([key,value]) => [key, Array.isArray(value) ? value.join(', ') : value])));
    root.append(el('h3','','PKI Validation'), table(['Check','Status'], Object.entries(endpoint.pki)));
    root.append(el('h3','','PQC'), table(['Field','Value'], Object.entries(endpoint.pqc).map(([key,value]) => [key, Array.isArray(value) ? value.join(', ') : value])));
    $('endpointDrawer').classList.add('open');
    $('endpointDrawer').setAttribute('aria-hidden','false');
    $('drawerBackdrop').classList.add('open');
  }


  function initNavigation(){
    const links = Array.from(document.querySelectorAll('.app-shell nav a'));
    const sections = links.map((link) => document.querySelector(link.getAttribute('href'))).filter(Boolean);
    const setActive = () => {
      const current = sections.reduce((active, section) => section.getBoundingClientRect().top <= 120 ? section : active, sections[0]);
      links.forEach((link) => link.classList.toggle('active', link.getAttribute('href') === `#${current.id}`));
    };
    setActive();
    document.addEventListener('scroll', setActive, {passive:true});
    window.addEventListener('hashchange', setActive);
  }

  function initTechnical(){
    $('technicalDetails').append(table(['Endpoint','Raw rows'], data.endpoints.map((endpoint) => [endpoint.endpoint_id, JSON.stringify(endpoint.technical_rows)])));
  }

  function closeDrawer(){
    $('endpointDrawer').classList.remove('open');
    $('endpointDrawer').setAttribute('aria-hidden','true');
    $('drawerBackdrop').classList.remove('open');
  }

  $('printReport').addEventListener('click', () => window.print());
  $('closeDrawer').addEventListener('click', closeDrawer);
  $('drawerBackdrop').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', (event) => { if(event.key === 'Escape') closeDrawer(); });

  initNavigation();
  initContext();
  initKpis();
  initCharts();
  initFindings();
  initEndpoints();
  initCertificates();
  initCompliance();
  initPqc();
  initTechnical();
})();
