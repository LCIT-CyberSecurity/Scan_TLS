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

  function renderRows(tbody, rows, emptyColspan){
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
    if(!rows.length){
      const row = document.createElement('tr');
      const td = el('td','empty-cell','No rows match the current filters.');
      td.colSpan = emptyColspan;
      row.append(td);
      tbody.append(row);
    }
  }

  function table(headers, rows, options){
    const sortable = !options || options.sortable !== false;
    const filterable = Boolean(options && options.filterable);
    const onRender = options && options.onRender;
    const wrap = el('div', filterable ? 'table-wrap filterable-table-wrap' : 'table-wrap');
    const t = document.createElement('table');
    const thead = document.createElement('thead');
    const tr = document.createElement('tr');
    const tbody = document.createElement('tbody');
    const state = {index:-1, direction:1, filters:headers.map(() => '')};

    const applyState = () => {
      let visible = rows.filter((cells) => state.filters.every((filter, index) => !filter || cellText(cells[index]).toLowerCase().includes(filter)));
      if(state.index >= 0){
        visible = [...visible].sort((a,b) => compareValues(cellText(a[state.index]), cellText(b[state.index])) * state.direction);
      }
      renderRows(tbody, visible, headers.length);
      if(onRender) onRender(visible.length, rows.length);
    };

    headers.forEach((h, index) => {
      const th = el('th','',h);
      if(sortable){
        const sortButton = button(h, () => {
          state.direction = state.index === index ? state.direction * -1 : 1;
          state.index = index;
          Array.from(tr.children).forEach((item) => item.removeAttribute('aria-sort'));
          th.setAttribute('aria-sort', state.direction === 1 ? 'ascending' : 'descending');
          applyState();
        }, 'table-sort');
        sortButton.title = `Sort by ${h}`;
        th.append(sortButton);
      } else {
        th.textContent = h;
      }
      tr.append(th);
    });
    thead.append(tr);

    if(filterable){
      const filterRow = document.createElement('tr');
      filterRow.className = 'column-filter-row no-print';
      headers.forEach((h, index) => {
        const th = document.createElement('th');
        const input = document.createElement('input');
        input.className = 'column-filter';
        input.placeholder = `Filter ${h}`;
        input.setAttribute('aria-label', `Filter ${h}`);
        input.addEventListener('input', () => {
          state.filters[index] = input.value.trim().toLowerCase();
          applyState();
        });
        th.append(input);
        filterRow.append(th);
      });
      thead.append(filterRow);
    }

    applyState();
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

  function hostKey(endpoint){
    return endpoint.hostname || endpoint.ip_address || endpoint.host_id || endpoint.endpoint_id;
  }

  function summarizeHost(endpoints){
    return {
      grade: endpoints.reduce((worst, endpoint) => (gradeOrder[endpoint.overall_grade] ?? 99) > (gradeOrder[worst] ?? 99) ? endpoint.overall_grade : worst, endpoints[0].overall_grade),
      severity: endpoints.reduce((worst, endpoint) => (severityOrder[endpoint.highest_severity] ?? 9) < (severityOrder[worst] ?? 9) ? endpoint.highest_severity : worst, endpoints[0].highest_severity),
      findings: endpoints.reduce((total, endpoint) => total + Number(endpoint.finding_count || 0), 0),
      failed: endpoints.filter((endpoint) => endpoint.compliance_status !== 'compliant').length,
      certificates: Array.from(new Set(endpoints.map((endpoint) => endpoint.certificate.valid_until || endpoint.certificate.status).filter(Boolean))),
      protocols: Array.from(new Set(endpoints.flatMap((endpoint) => endpoint.supported_tls_versions || []))),
    };
  }

  function endpointPortRow(endpoint){
    const row = el('div','endpoint-port-row');
    const port = el('div','endpoint-port-main');
    port.append(valueNode(`${endpoint.port}/${endpoint.protocol}`, 'endpoint-port'), valueNode(endpoint.ip_address, 'endpoint-address'));
    const tls = (endpoint.supported_tls_versions || []).join(', ') || 'Not Tested';
    const cert = endpoint.certificate.valid_until || endpoint.certificate.status;
    [
      port,
      badge(endpoint.overall_grade, `grade-badge ${gradeClass(endpoint.overall_grade)}`),
      valueNode(endpoint.compliance_status, statusClass(endpoint.compliance_status)),
      valueNode(tls),
      valueNode(cert),
      valueNode(`${endpoint.finding_count} finding(s)`, severityClass(endpoint.highest_severity)),
      button('Open details', () => openEndpoint(endpoint.endpoint_id), 'button'),
    ].forEach((item) => row.append(item));
    return row;
  }

  function hostEndpointCard(group){
    const summary = summarizeHost(group.endpoints);
    const card = el('article','endpoint-card host-card card');
    const head = el('div','endpoint-head');
    const identity = el('div','endpoint-identity');
    identity.append(valueNode(group.host, 'endpoint-host'), valueNode(`${group.endpoints.length} endpoint(s) across ${new Set(group.endpoints.map((endpoint) => endpoint.port)).size} port(s)`, 'endpoint-address'));
    const headBadges = el('div','host-badges');
    headBadges.append(badge(summary.grade, `grade-badge ${gradeClass(summary.grade)}`), badge(`${summary.findings} finding(s)`, severityClass(summary.severity)));
    head.append(identity, headBadges);
    const grid = el('div','endpoint-grid host-summary-grid');
    [
      ['Failed Endpoints', `${summary.failed}/${group.endpoints.length}`, summary.failed ? 'status-non_compliant' : 'status-compliant'],
      ['Protocols', summary.protocols.join(', ') || 'Not Tested', ''],
      ['Certificates', summary.certificates.join(', ') || 'Not Tested', ''],
    ].forEach(([label,value,cls]) => {
      const item = el('div','endpoint-field');
      item.append(el('span','field-label',label), valueNode(value, cls));
      grid.append(item);
    });
    const portList = el('div','endpoint-port-list');
    const header = el('div','endpoint-port-row endpoint-port-header');
    ['Port','Grade','Compliance','Protocols','Certificate','Findings','Details'].forEach((label) => header.append(el('span','',label)));
    portList.append(header, ...group.endpoints.map(endpointPortRow));
    card.append(head, grid, portList);
    return card;
  }

  function endpointMatches(endpoint, q){
    return JSON.stringify(endpoint).toLowerCase().includes(q);
  }

  function groupEndpoints(endpoints){
    const grouped = new Map();
    endpoints.forEach((endpoint) => {
      const key = hostKey(endpoint);
      if(!grouped.has(key)) grouped.set(key, {host:key, endpoints:[]});
      grouped.get(key).endpoints.push(endpoint);
    });
    return Array.from(grouped.values()).map((group) => ({
      ...group,
      endpoints: group.endpoints.sort((a,b) => Number(a.port) - Number(b.port) || a.endpoint_id.localeCompare(b.endpoint_id)),
    }));
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
    sort.setAttribute('aria-label','Sort endpoint groups');
    [['severity','Severity'],['hostname','Hostname'],['grade','Grade'],['findings','Finding count'],['ports','Port count'],['expiration','Certificate expiration']].forEach(([value,label]) => sort.add(new Option(`Sort by ${label}`, value)));
    filters.append(search, compliance, sort);
    const render = () => {
      const q = search.value.toLowerCase();
      const rows = data.endpoints.filter((endpoint) => (compliance.value === 'all' || endpoint.compliance_status === compliance.value) && endpointMatches(endpoint, q));
      const groups = groupEndpoints(rows);
      groups.sort((a,b) => {
        const sa = summarizeHost(a.endpoints);
        const sb = summarizeHost(b.endpoints);
        if(sort.value === 'findings') return sb.findings - sa.findings;
        if(sort.value === 'ports') return b.endpoints.length - a.endpoints.length;
        if(sort.value === 'expiration') return String(sa.certificates[0] || '').localeCompare(String(sb.certificates[0] || ''));
        if(sort.value === 'grade') return (gradeOrder[sa.grade] ?? 99) - (gradeOrder[sb.grade] ?? 99);
        if(sort.value === 'severity') return (severityOrder[sa.severity] ?? 9) - (severityOrder[sb.severity] ?? 9) || sb.findings - sa.findings;
        return a.host.localeCompare(b.host);
      });
      const shownEndpoints = groups.reduce((total, group) => total + group.endpoints.length, 0);
      $('endpointCount').textContent = `${groups.length} host(s) / ${shownEndpoints} endpoint(s) shown${shownEndpoints > 500 ? ' - first 500 endpoints rendered' : ''}`;
      let rendered = 0;
      const cards = [];
      for(const group of groups){
        if(rendered >= 500) break;
        const remaining = 500 - rendered;
        const visibleGroup = {...group, endpoints: group.endpoints.slice(0, remaining)};
        rendered += visibleGroup.endpoints.length;
        cards.push(hostEndpointCard(visibleGroup));
      }
      $('endpointTable').replaceChildren(...cards);
      if(!groups.length) $('endpointTable').append(el('div','empty','No endpoints match the current filters.'));
    };
    [search, compliance, sort].forEach((node) => node.addEventListener('input', render));
    render();
  }

  function initCertificates(){
    const filters = $('certificateFilters');
    const status = document.createElement('select');
    status.setAttribute('aria-label','Filter certificates by status');
    ['all','Valid','Expiring soon','Expired','Self-signed','Weak key','Weak signature','Validation not tested'].forEach((value) => status.add(new Option(value === 'all' ? 'All certificate states' : value, value)));
    const sort = document.createElement('select');
    sort.setAttribute('aria-label','Sort certificates');
    [['expiration','Expiration'],['remaining','Remaining days'],['status','Status'],['endpoint','Endpoint'],['issuer','Issuer'],['key_size','Key size']].forEach(([value,label]) => sort.add(new Option(`Sort by ${label}`, value)));
    filters.append(status, sort);
    const render = () => {
      const endpoints = data.endpoints.filter((endpoint) => status.value === 'all' || endpoint.certificate.status === status.value);
      endpoints.sort((a,b) => {
        if(sort.value === 'remaining') return (Number(a.certificate.remaining_days) || 0) - (Number(b.certificate.remaining_days) || 0);
        if(sort.value === 'status') return String(a.certificate.status).localeCompare(String(b.certificate.status));
        if(sort.value === 'issuer') return String(a.certificate.issuer).localeCompare(String(b.certificate.issuer));
        if(sort.value === 'key_size') return (Number(a.certificate.key_size) || 0) - (Number(b.certificate.key_size) || 0);
        if(sort.value === 'endpoint') return String(a.endpoint_id).localeCompare(String(b.endpoint_id), undefined, {numeric:true, sensitivity:'base'});
        return String(a.certificate.valid_until).localeCompare(String(b.certificate.valid_until));
      });
      const rows = endpoints.map((endpoint) => [endpoint.endpoint_id, endpoint.certificate.subject, endpoint.certificate.issuer, (endpoint.certificate.san || []).join(', '), endpoint.certificate.valid_until, endpoint.certificate.remaining_days, endpoint.certificate.self_signed, endpoint.certificate.key_type, endpoint.certificate.key_size, endpoint.certificate.signature_algorithm, endpoint.certificate.trust_status, endpoint.certificate.hostname_validation_status, endpoint.certificate.chain_validation_status, endpoint.certificate.revocation_status]);
      $('certificateTable').replaceChildren(table(['Endpoint','Subject','Issuer','SAN','Expiration','Remaining days','Self-signed','Key type','Key size','Signature','Trust','Hostname validation','Chain validation','Revocation'], rows));
    };
    [status, sort].forEach((node) => node.addEventListener('change', render));
    render();
  }


  function initCommunicationSecurity(){
    const rows = data.endpoints.flatMap((endpoint) => endpoint.cipher_suites.map((suite) => [
      endpoint.endpoint_id,
      endpoint.hostname,
      endpoint.port,
      suite.tls_version,
      suite.name,
      suite.key_exchange,
      suite.authentication,
      suite.encryption,
      suite.hash_algorithm,
      suite.forward_secrecy,
      suite.strength,
      suite.compliance_status,
      suite.policy_reason,
    ]));
    const headers = ['Endpoint','Host','Port','TLS Version','Cipher Suite','Key Exchange','Authentication','Encryption','Hash','Forward Secrecy','Strength','Compliance','Policy Reason'];
    $('communicationTable').replaceChildren(table(headers, rows, {
      filterable:true,
      onRender:(visible,total) => { $('communicationCount').textContent = `${visible} shown / ${total} suites`; },
    }));
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
  initCommunicationSecurity();
  initCompliance();
  initPqc();
  initTechnical();
})();
