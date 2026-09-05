(function(){
  'use strict';

  const data = JSON.parse(document.getElementById('report-data').textContent);
  const $ = (id) => document.getElementById(id);
  const severityOrder = {critical:0, high:1, medium:2, low:3, informational:4, none:5};
  const gradeOrder = {'A+':0, A:1, B:2, C:3, D:4, F:5, 'Not Tested':6};
  const severityColors = {critical:'#b42318', high:'#d92d20', medium:'#f79009', low:'#ca8a04', informational:'#2563eb', none:'#64748b'};
    const tlsOrder = ['SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1','TLS 1.2','TLS 1.3'];
  const certOrder = ['Valid','Expiring soon','Expired','Revoked','Self-signed','Weak key','Weak signature','Validation not tested'];
  const expirationOrder = ['Already expired','Within 7 days','Within 30 days','Within 60 days','Within 90 days','After 90 days'];

  const normalize = (value) => String(value == null || value === '' ? '-' : value);
  const pct = (part,total) => total ? Math.round(Number(part || 0) * 100 / total) : 0;
  const sum = (obj) => Object.values(obj || {}).reduce((a,b) => a + Number(b || 0), 0);

  function el(tag, cls, value){
    const node = document.createElement(tag);
    if(cls) node.className = cls;
    if(value !== undefined) node.textContent = normalize(value);
    return node;
  }

  function icon(name){
    const svg = document.createElementNS('http://www.w3.org/2000/svg','svg');
    svg.setAttribute('viewBox','0 0 24 24');
    svg.setAttribute('aria-hidden','true');
    svg.setAttribute('focusable','false');
    const paths = {
      shield:['M12 3l7 3v5c0 4.7-2.8 8.6-7 10-4.2-1.4-7-5.3-7-10V6l7-3z','M9 12l2 2 4-5'],
      activity:['M4 12h4l2-6 4 12 2-6h4'],
      certificate:['M7 3h10v10H7z','M9 17l3-2 3 2v4l-3-2-3 2z'],
      clock:['M12 4a8 8 0 108 8 8 8 0 00-8-8z','M12 8v5l3 2'],
      quantum:['M12 4a8 8 0 100 16 8 8 0 000-16z','M4 12h16','M12 4c2 2 3 5 3 8s-1 6-3 8','M12 4c-2 2-3 5-3 8s1 6 3 8'],
      server:['M5 6h14v5H5z','M5 13h14v5H5z','M8 8h.1','M8 15h.1'],
      alert:['M12 4l9 16H3L12 4z','M12 9v5','M12 17h.1'],
    }[name] || [];
    paths.forEach((d) => {
      const path = document.createElementNS('http://www.w3.org/2000/svg','path');
      path.setAttribute('d', d);
      svg.append(path);
    });
    return svg;
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

  function formatReportDate(value){
    const date = new Date(value);
    if(Number.isNaN(date.getTime())) return normalize(value);
    const pad = (item) => String(item).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  function csvHeaders(){
    const headers = ['IP','FQDN','Port', data.metadata.crypto_profile === 'pqc' ? 'TLS Grade' : 'Grade', 'TLS Version', 'Cipher Suite', 'Public Key', 'Certificate Validity'];
    if(data.metadata.crypto_profile === 'pqc') headers.push('Key Exchange');
    headers.push('Certificate Crypto','Self-signed','Certificate Days Left','Certificate Issuer','Certificate Subject','Certificate SAN','Certificate Key Type','Certificate Key Size','Certificate Signature Algorithm','Certificate Trust Classification','Certificate Trusted By','Certificate Trust Anchor','Certificate Chain Validation','Certificate Revocation','Certificate OCSP','Certificate CRL','Compliance','Reason');
    return headers;
  }

  function csvCell(value){
    const normalized = normalize(value);
    return /[",\n\r]/.test(normalized) ? `"${normalized.replace(/"/g, '""')}"` : normalized;
  }

  function csvContent(){
    const rows = [csvHeaders(), ...(data.raw_results || [])];
    return rows.map((row) => row.map(csvCell).join(',')).join('\n') + '\n';
  }

  function safeFilename(value){
    return String(value || 'tls_scan_report').replace(/[^a-z0-9._-]+/gi, '_').replace(/^_+|_+$/g, '') || 'tls_scan_report';
  }

  function downloadCsv(){
    const blob = new Blob([csvContent()], {type:'text/csv;charset=utf-8'});
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${safeFilename(data.metadata.report_name)}.csv`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  function badge(value, cls){ return el('span', `badge ${cls || ''}`, value); }
  function severityClass(value){ return `severity-${String(value || 'informational').toLowerCase()}`; }
  function statusClass(value){ return `status-${String(value || 'not_tested').toLowerCase().replace(/[\s-]+/g,'_')}`; }
  function statusBadge(value){ return badge(value, statusClass(value)); }
  function dot(label, count, cls){
    const item = el('div','status-line');
    item.append(el('i', cls || ''), el('span','',label), el('strong','',count));
    return item;
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

  function postureTone(){
    const s = data.statistics;
    if(s.critical_findings || s.high_findings || s.non_compliant_endpoints) return 'high-risk';
    if(s.endpoints_with_errors || s.endpoints_not_fully_tested) return 'needs-attention';
    return 'strong';
  }

  function postureLabel(){
    const tone = postureTone();
    if(tone === 'strong') return 'Strong';
    if(tone === 'high-risk') return 'High risk';
    return 'Needs attention';
  }

  function initContext(){
    const m = data.metadata, s = data.statistics;
    const compliantPct = pct(s.compliant_endpoints, s.total_endpoints);
    const posture = postureLabel();
    $('postureTitle').textContent = posture === 'Strong' ? 'Your TLS security posture is policy aligned' : 'Your TLS security posture requires focused remediation';
    const policyName = data.policies.map((p) => p.name).join(', ') || 'Legacy scanner policy';
    [
      ['Scan Date', formatReportDate(m.scan_timestamp), false],
      ['Duration', m.scan_duration_seconds == null ? 'Not Recorded' : `${m.scan_duration_seconds}s`, false],
      ['Policy', policyName, true],
      ['Scanner Version', m.scanner_version, false],
      ['Ports', m.ports, false],
      ['Run ID', m.scan_run_id || '-', true],
    ].forEach(([label,value,copy]) => $('scanContext').append(infoItem(label,value,copy)));
    $('pageFooterMeta').textContent = `${policyName} | ${compliantPct}% compliant`;
    priorityActions();
  }

  function priorityActions(){
    const s = data.statistics;
    const actions = [];
    if(s.top_findings && s.top_findings.length) s.top_findings.slice(0,3).forEach((finding) => actions.push([finding.title, `${finding.affected_endpoints} impacted endpoint(s)`, finding.severity]));
    if(!actions.length) actions.push(['No recurring weaknesses', 'Maintain monitoring cadence', 'informational']);
    actions.forEach(([label,text,tone]) => {
      const item = el('div',`priority-item ${severityClass(tone)}`);
      item.append(badge(label, severityClass(tone)), valueNode(text));
      $('priorityActions').append(item);
    });
  }

  function initKpis(){
    const s = data.statistics;
    const compliantPct = `${pct(s.compliant_endpoints, s.total_endpoints)}% compliant`;
    const highRisk = Number(s.critical_findings || 0) + Number(s.high_findings || 0);
    [
      ['Hosts', s.total_hosts, 'server'],
      ['Endpoints', s.total_endpoints, 'activity'],
      ['High risk findings', highRisk, 'alert'],
      ['Total findings', s.finding_occurrences, 'shield'],
      ['Compliant endpoints', compliantPct, 'certificate'],
    ].forEach(([label,value,iconName]) => {
      const item = el('article','kpi-item');
      item.append(icon(iconName), el('span','kpi-label',label), el('strong','kpi-value',value));
      $('kpis').append(item);
    });
  }

  function horizontalBars(counts, order, classResolver){
    const total = sum(counts);
    const wrap = el('div','bars-compact');
    order.forEach((label) => {
      const count = Number(counts[label] || 0);
      const row = el('div','bar-row');
      const top = el('div','bar-top');
      top.append(valueNode(label, 'bar-label'), el('strong','bar-value',count));
      const track = el('div','bar-track');
      const fill = el('div','bar-fill');
      fill.style.width = `${pct(count,total)}%`;
      if(classResolver) fill.className = `bar-fill ${classResolver(label)}`;
      track.append(fill);
      row.append(top, track);
      wrap.append(row);
    });
    return wrap;
  }

  function donutCompliance(){
    const s = data.statistics;
    const total = s.total_endpoints;
    const value = pct(s.compliant_endpoints, total);
    const donut = el('div','donut compliance-donut');
    donut.style.background = `conic-gradient(#16a34a 0deg ${value * 3.6}deg, #d92d20 ${value * 3.6}deg 360deg)`;
    donut.setAttribute('role','img');
    donut.setAttribute('aria-label', `${value}% compliant endpoints`);
    const center = el('div','donut-center');
    center.append(el('strong','',`${value}%`), el('span','','compliant'));
    donut.append(center);
    return donut;
  }

  function insight(text, tone){
    const node = el('aside',`analytics-insight ${tone || 'info'}`);
    node.append(el('strong','','Insight'), el('p','',text));
    return node;
  }

  function analyticsRow(iconName, title, subtitle, visual, takeaway){
    const row = el('article','analytics-row');
    const head = el('div','analytics-head');
    const iconWrap = el('div','analytics-icon');
    iconWrap.append(icon(iconName));
    head.append(iconWrap, el('h3','',title), el('p','',subtitle));
    row.append(head, el('div','analytics-visual'), takeaway);
    row.children[1].append(visual);
    return row;
  }

  function initCharts(){
    const s = data.statistics;
    const complianceList = el('div','compliance-visual');
    complianceList.append(donutCompliance());
    const legend = el('div','status-list');
    Object.entries(s.endpoint_compliance).forEach(([label,count]) => legend.append(dot(label.replace(' endpoints',''), count, `dot-${label.toLowerCase().replace(/[^a-z]+/g,'-')}`)));
    complianceList.append(legend);
    $('charts').append(analyticsRow('shield', 'Endpoint compliance', 'Compliance status of scanned endpoints against the selected policy.', complianceList, insight(s.non_compliant_endpoints === s.total_endpoints && s.total_endpoints ? 'All scanned endpoints are non-compliant. Remediation is required.' : `${s.compliant_endpoints} of ${s.total_endpoints} endpoints are compliant.`, s.non_compliant_endpoints ? 'danger' : 'success')));

    const legacy = Number(s.tls_version_distribution['SSL 2.0'] || 0) + Number(s.tls_version_distribution['SSL 3.0'] || 0) + Number(s.tls_version_distribution['TLS 1.0'] || 0) + Number(s.tls_version_distribution['TLS 1.1'] || 0);
    $('charts').append(analyticsRow('activity', 'TLS version distribution', 'Distribution of supported TLS versions across all endpoints.', horizontalBars(s.tls_version_distribution, tlsOrder, (label) => label === 'TLS 1.3' ? 'success' : label === 'TLS 1.2' ? 'info' : 'warning'), insight(legacy ? `Legacy TLS versions are still enabled on ${legacy} endpoint occurrence(s).` : 'No legacy TLS versions were observed.', legacy ? 'warning' : 'success')));

    const certList = el('div','status-list certificate-status-list');
    certOrder.forEach((label) => certList.append(dot(label, s.certificate_status[label] || 0, `dot-cert-${label.toLowerCase().replace(/[^a-z]+/g,'-')}`)));
    const certText = s.expired_certificates ? `${s.expired_certificates} expired certificate(s) detected. Ensure certificates are renewed and properly trusted.` : `${s.certificates_expiring_soon} certificate(s) are expiring soon.`;
    $('charts').append(analyticsRow('certificate', 'Certificate status', 'Status of server certificates found on scanned endpoints.', certList, insight(certText, s.expired_certificates ? 'danger' : s.certificates_expiring_soon ? 'warning' : 'success')));

    const expiringSoon = Number(s.certificate_expiration_timeline['Within 7 days'] || 0) + Number(s.certificate_expiration_timeline['Within 30 days'] || 0) + Number(s.certificate_expiration_timeline['Within 60 days'] || 0);
    const expireText = `${s.certificate_expiration_timeline['Already expired'] || 0} certificate(s) are already expired. ${expiringSoon} certificate(s) expire within 60 days.`;
    $('charts').append(analyticsRow('clock', 'Certificate expiration timeline', 'Time remaining before certificate expiration across all endpoints.', horizontalBars(s.certificate_expiration_timeline, expirationOrder, (label) => label === 'Already expired' ? 'danger' : label.includes('7') || label.includes('30') || label.includes('60') ? 'warning' : 'info'), insight(expireText, s.certificate_expiration_timeline['Already expired'] ? 'danger' : expiringSoon ? 'warning' : 'info')));

    const pqc = s.pqc_readiness || {};
    const pqcTested = Number(pqc['Endpoints supporting hybrid ML-KEM groups'] || 0) + Number(pqc['Classical cryptography only'] || 0) + Number(pqc['Endpoints with PQC scan errors'] || 0);
    let pqcVisual;
    let pqcInsight;
    if(!pqcTested){
      pqcVisual = el('div','pqc-empty-state');
      pqcVisual.append(el('strong','','PQC testing was not enabled for this scan.'), el('p','','Enable PQC analysis to assess readiness for post-quantum cryptography.'));
      pqcInsight = insight('No PQC negotiation data is available in this report.', 'info');
    } else {
      pqcVisual = horizontalBars(pqc, Object.keys(pqc), (label) => label.includes('supporting') ? 'success' : label.includes('errors') ? 'danger' : 'info');
      pqcInsight = insight(`${pqc['Classical cryptography only'] || 0} endpoint(s) use classical cryptography only.`, 'info');
    }
    $('charts').append(analyticsRow('quantum', 'PQC readiness', 'Post-quantum cryptography support detected on scanned endpoints.', pqcVisual, pqcInsight));
  }

  function topFindingRow(finding, index){
    const full = data.findings.find((item) => item.finding_id === finding.finding_id) || {};
    const row = el('article','top-finding-row');
    const summary = el('div','top-finding-summary');
    summary.append(valueNode(finding.title, 'top-finding-title'), valueNode(full.description || full.technical_impact || 'Prioritized remediation theme.', 'top-finding-description'));
    row.append(el('strong','rank',index + 1), badge(finding.severity, severityClass(finding.severity)), summary, valueNode(`${finding.affected_endpoints} impacted endpoint(s)`, 'top-finding-impact'));
    return row;
  }

  function initTopFindings(){
    const root = $('topFindingsList');
    const top = data.statistics.top_findings || [];
    if(!top.length){
      root.append(el('div','empty','No findings were identified.'));
      return;
    }
    top.slice(0,6).forEach((finding, index) => root.append(topFindingRow(finding, index)));
  }

  function findingCard(finding){
    const card = el('article',`finding-card ${severityClass(finding.severity)}`);
    const head = el('div','finding-head');
    const title = el('div','finding-title');
    title.append(badge(finding.severity, severityClass(finding.severity)), valueNode(finding.title, 'finding-name'));
    const impacted = el('div','impact-count');
    impacted.append(el('strong','',finding.affected_endpoint_ids.length), el('span','','impacted endpoints'));
    head.append(title, impacted);
    const body = el('div','finding-body');
    [['Risk', finding.technical_impact, 'risk'], ['Recommendation', finding.remediation, 'recommendation'], ['Evidence', finding.evidence, 'evidence']].forEach(([label,value,type]) => {
      const block = el('section',`finding-block finding-block-${type}`);
      block.append(el('span','block-label',label), valueNode(value));
      body.append(block);
    });
    const foot = el('div','finding-foot');
    foot.append(valueNode(`ID ${finding.finding_id}`, 'mono'), copyButton(finding.finding_id));
    if(finding.policy_ids && finding.policy_ids.length) foot.append(valueNode(`Policy ${finding.policy_ids.join(', ')}`, 'mono'));
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

  function endpointScore(endpoint){
    const gradeScores = {'A+':100, A:95, B:80, C:65, D:50, F:0, 'Not Tested':0};
    const gradeScore = gradeScores[endpoint.overall_grade] ?? 0;
    const suites = endpoint.cipher_suites || [];
    if(!suites.length) return gradeScore;
    const compliantSuites = suites.filter((suite) => suite.compliance_status === 'compliant').length;
    const communicationScore = Math.round(compliantSuites * 100 / suites.length);
    return Math.round((gradeScore + communicationScore) / 2);
  }

  function scoreTone(score){
    if(score >= 90) return 'score-good';
    if(score >= 70) return 'score-info';
    if(score >= 50) return 'score-warning';
    return 'score-bad';
  }

  function hostKey(endpoint){ return endpoint.hostname || endpoint.ip_address || endpoint.host_id || endpoint.endpoint_id; }

  function groupEndpointsByHost(endpoints){
    const grouped = new Map();
    endpoints.forEach((endpoint) => {
      const key = hostKey(endpoint);
      if(!grouped.has(key)) grouped.set(key, {host:key, endpoints:[]});
      grouped.get(key).endpoints.push(endpoint);
    });
    return Array.from(grouped.values()).map((group) => ({...group,endpoints: group.endpoints.sort((a,b) => Number(a.port) - Number(b.port) || a.endpoint_id.localeCompare(b.endpoint_id))}));
  }

  function hostSummary(group){
    const endpoints = group.endpoints;
    const scores = endpoints.map(endpointScore);
    const score = scores.length ? Math.round(scores.reduce((total, item) => total + item, 0) / scores.length) : 0;
    const worstGrade = endpoints.reduce((worst, endpoint) => (gradeOrder[endpoint.overall_grade] ?? 99) > (gradeOrder[worst] ?? 99) ? endpoint.overall_grade : worst, endpoints[0].overall_grade);
    const highestSeverity = endpoints.reduce((worst, endpoint) => (severityOrder[endpoint.highest_severity] ?? 9) < (severityOrder[worst] ?? 9) ? endpoint.highest_severity : worst, endpoints[0].highest_severity);
    const findings = endpoints.reduce((total, endpoint) => total + Number(endpoint.finding_count || 0), 0);
    const failed = endpoints.filter((endpoint) => endpoint.compliance_status !== 'compliant').length;
    const ports = Array.from(new Set(endpoints.map((endpoint) => `${endpoint.port}/${endpoint.protocol}`)));
    const protocols = Array.from(new Set(endpoints.flatMap((endpoint) => endpoint.supported_tls_versions || [])));
    const certStatuses = Array.from(new Set(endpoints.map((endpoint) => endpoint.certificate.status).filter(Boolean)));
    const trust = Array.from(new Set(endpoints.map((endpoint) => endpoint.certificate.trust_classification).filter(Boolean)));
    return {score, worstGrade, highestSeverity, findings, failed, ports, protocols, certStatuses, trust};
  }

  function portList(ports){
    const list = el('div','host-port-list');
    ports.slice(0, 8).forEach((port) => list.append(badge(port, 'port-badge')));
    if(ports.length > 8) list.append(badge(`+${ports.length - 8}`, 'port-badge port-more'));
    list.title = ports.join(', ');
    return list;
  }

  function compactCounts(group){
    const counts = {critical:0, high:0, medium:0, low:0, informational:0};
    group.endpoints.forEach((endpoint) => (endpoint.finding_ids || []).forEach((id) => {
      const finding = data.findings.find((item) => item.finding_id === id);
      if(finding) counts[finding.severity] += 1;
    }));
    return counts;
  }

  function hostEndpointCard(group){
    const summary = hostSummary(group);
    const counts = compactCounts(group);
    const card = el('article','endpoint-card host-card');
    const main = el('div','endpoint-main');
    const identity = el('div','endpoint-identity');
    identity.append(valueNode(group.host, 'endpoint-host'), valueNode(`${group.endpoints[0].ip_address} · ${summary.ports.join(', ')}`, 'endpoint-address'));
    identity.append(portList(summary.protocols));
    const state = el('div','endpoint-state');
    state.append(statusBadge(summary.failed ? 'Non-compliant' : 'Compliant'), valueNode(`Certificate: ${summary.certStatuses.join(', ') || 'Not Tested'} · ${summary.trust.join(', ') || 'Trust not tested'}`, 'endpoint-cert'));
    const risk = el('div','endpoint-risk');
    risk.append(valueNode(`High ${counts.critical + counts.high}`, severityClass(counts.critical + counts.high ? 'high' : 'none')), valueNode(`Medium ${counts.medium}`, severityClass(counts.medium ? 'medium' : 'none')), valueNode(`${summary.findings} findings`, 'muted'));
    const action = button('View details', () => openHostEndpoints(group), 'text-button no-print');
    main.append(identity, state, risk, action);
    card.append(main);
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
    sort.setAttribute('aria-label','Sort endpoint hosts');
    [['severity','Severity'],['score','Average score'],['hostname','Hostname'],['grade','Worst grade'],['findings','Finding count'],['ports','Port count'],['expiration','Certificate expiration']].forEach(([value,label]) => sort.add(new Option(`Sort by ${label}`, value)));
    filters.append(search, compliance, sort);
    const render = () => {
      const q = search.value.toLowerCase();
      const endpoints = data.endpoints.filter((endpoint) => (compliance.value === 'all' || endpoint.compliance_status === compliance.value) && JSON.stringify(endpoint).toLowerCase().includes(q));
      const groups = groupEndpointsByHost(endpoints);
      groups.sort((a,b) => {
        const sa = hostSummary(a);
        const sb = hostSummary(b);
        if(sort.value === 'score') return sb.score - sa.score;
        if(sort.value === 'findings') return sb.findings - sa.findings;
        if(sort.value === 'ports') return b.endpoints.length - a.endpoints.length;
        if(sort.value === 'expiration') return String(a.endpoints[0].certificate.valid_until).localeCompare(String(b.endpoints[0].certificate.valid_until));
        if(sort.value === 'grade') return (gradeOrder[sa.worstGrade] ?? 99) - (gradeOrder[sb.worstGrade] ?? 99);
        if(sort.value === 'severity') return (severityOrder[sa.highestSeverity] ?? 9) - (severityOrder[sb.highestSeverity] ?? 9) || sb.findings - sa.findings;
        return a.host.localeCompare(b.host);
      });
      const shownEndpoints = groups.reduce((total, group) => total + group.endpoints.length, 0);
      const visibleGroups = groups.slice(0, 500);
      $('endpointCount').textContent = `${visibleGroups.length} host(s) / ${shownEndpoints} endpoint(s) shown${groups.length > visibleGroups.length ? ' - first 500 hosts rendered' : ''}`;
      const cards = visibleGroups.map(hostEndpointCard);
      $('endpointTable').replaceChildren(...cards);
      if(!groups.length) $('endpointTable').append(el('div','empty','No endpoints match the current filters.'));
    };
    [search, compliance, sort].forEach((node) => node.addEventListener('input', render));
    render();
  }

  function openHostEndpoints(group){
    const summary = hostSummary(group);
    const root = $('drawerContent');
    root.textContent = '';
    root.append(el('h2','',group.host));
    root.append(table(['Metric','Value'], [
      ['Average Score', `${summary.score}/100`],
      ['Worst TLS Grade', summary.worstGrade],
      ['Endpoints', group.endpoints.length],
      ['Failed Endpoints', `${summary.failed}/${group.endpoints.length}`],
      ['Ports', summary.ports.join(', ')],
      ['Findings', summary.findings],
    ]));
    root.append(el('h3','','Endpoints'));
    root.append(table(['Endpoint','IP','Port','TLS Grade','Score','Compliance','Protocols','Findings','Details'], group.endpoints.map((endpoint) => [
      endpoint.endpoint_id,
      endpoint.ip_address,
      `${endpoint.port}/${endpoint.protocol}`,
      endpoint.overall_grade,
      `${endpointScore(endpoint)}/100`,
      endpoint.compliance_status,
      (endpoint.supported_tls_versions || []).join(', ') || 'Not Tested',
      endpoint.finding_count,
      button('Open', () => openEndpoint(endpoint.endpoint_id), 'button'),
    ])));
    $('endpointDrawer').classList.add('open');
    $('endpointDrawer').setAttribute('aria-hidden','false');
    $('drawerBackdrop').classList.add('open');
  }

  function trustedByLabel(cert){ return (cert.trusted_by || []).join(', ') || 'N/A'; }
  function trustAnchorLabel(cert){ return cert.trust_anchor || 'N/A'; }

  function initCertificates(){
    const filters = $('certificateFilters');
    const status = document.createElement('select');
    status.setAttribute('aria-label','Filter certificates by status');
    ['all',...certOrder].forEach((value) => status.add(new Option(value === 'all' ? 'All certificate states' : value, value)));
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
      const rows = endpoints.map((endpoint) => [
        endpoint.endpoint_id,
        endpoint.certificate.subject,
        endpoint.certificate.valid_until,
        `${endpoint.certificate.key_type} ${endpoint.certificate.key_size || ''}`.trim(),
        badge(endpoint.certificate.trust_classification, trustTone(endpoint.certificate.trust_classification)),
        badge(endpoint.certificate.hostname_validation_status, trustTone(endpoint.certificate.hostname_validation_status)),
        endpoint.certificate.issuer,
        (endpoint.certificate.san || []).join(', '),
        trustedByLabel(endpoint.certificate),
        trustAnchorLabel(endpoint.certificate),
        endpoint.certificate.signature_algorithm,
        endpoint.certificate.chain_validation_status,
        endpoint.certificate.revocation_status,
      ]);
      $('certificateTable').replaceChildren(table(['Endpoint','Subject','Expiration','Key','Trust','Hostname validation','Issuer','SAN','Trusted by','Trust anchor','Signature','Chain validation','Revocation'], rows, {filterable:true}));
    };
    [status, sort].forEach((node) => node.addEventListener('change', render));
    render();
  }

  function trustTone(value){
    const normalized = String(value || '').toLowerCase();
    if(normalized === 'public_trusted' || normalized === 'private_trusted' || normalized === 'trusted' || normalized === 'passed' || normalized === 'valid') return 'status-compliant';
    if(normalized === 'untrusted' || normalized === 'failed' || normalized === 'revoked') return 'status-non_compliant';
    if(normalized === 'error') return 'status-error';
    return 'status-not_tested';
  }

  function trustDefinitions(){
    const definitions = [
      ['PUBLIC_TRUSTED', 'Validated by public trust store.'],
      ['PRIVATE_TRUSTED', 'Validated by a configured private store.'],
      ['UNTRUSTED', 'No executed trust store validated the chain.'],
      ['NOT_TESTED', 'Trust validation was not executed or inconclusive.'],
      ['ERROR', 'A technical error prevented TLS Scan from reaching a conclusive trust result.'],
    ];
    const wrap = el('div','trust-definition-grid');
    definitions.forEach(([label, text]) => {
      const item = el('div','trust-definition-item');
      item.append(badge(label, trustTone(label)), valueNode(text));
      wrap.append(item);
    });
    return wrap;
  }

  function initCertificateTrust(){
    const summaryRows = data.endpoints.map((endpoint) => {
      const cert = endpoint.certificate;
      return [endpoint.endpoint_id, badge(cert.trust_classification, trustTone(cert.trust_classification)), badge(cert.chain_validation_status, trustTone(cert.chain_validation_status)), trustedByLabel(cert), trustAnchorLabel(cert)];
    });
    const storeRows = data.endpoints.flatMap((endpoint) => (endpoint.certificate.trust_store_results || []).map((result) => [endpoint.endpoint_id, result.store_name, badge(result.status, trustTone(result.status)), result.trust_anchor_subject || 'None', result.validation_error || '']));
    const root = $('certificateTrust');
    root.append(trustDefinitions());
    root.append(table(['Endpoint','Trust classification','Chain validation','Trusted by','Trust anchor'], summaryRows, {filterable:true}));
    root.append(el('h3','trust-store-heading','Trust Store Results'));
    root.append(table(['Endpoint','Trust Store','Result','Trust Anchor','Error'], storeRows, {filterable:true}));
  }

  function initCommunicationSecurity(){
    const rows = data.endpoints.flatMap((endpoint) => endpoint.cipher_suites.map((suite) => [endpoint.endpoint_id, endpoint.hostname, endpoint.port, suite.tls_version, suite.name, suite.key_exchange, suite.authentication, suite.encryption, suite.hash_algorithm, suite.forward_secrecy, suite.strength, suite.compliance_status, suite.policy_reason]));
    const headers = ['Endpoint','Host','Port','TLS Version','Cipher Suite','Key Exchange','Authentication','Encryption','Hash','Forward Secrecy','Strength','Compliance','Policy Reason'];
    $('communicationTable').replaceChildren(table(headers, rows, {filterable:true,onRender:(visible,total) => { $('communicationCount').textContent = `${visible} shown / ${total} suites`; }}));
  }

  function initCompliance(){
    data.policies.forEach((policy) => {
      const card = el('article','policy-card');
      const head = el('div','policy-head');
      head.append(el('div','policy-name',`${policy.name}${policy.version ? ` v${policy.version}` : ''}`), badge(policy.non_compliant_endpoints ? 'Non-compliant' : 'Compliant', policy.non_compliant_endpoints ? 'status-non_compliant' : 'status-compliant'));
      const progress = el('div','progress');
      const fill = el('span','');
      fill.style.width = `${policy.compliance_percentage}%`;
      progress.append(fill);
      card.append(head, el('p','muted',policy.description || 'Selected policy'), progress, el('p','policy-summary',`${policy.compliance_percentage}% compliant · ${policy.non_compliant_endpoints} non-compliant endpoint(s) · ${policy.failed_controls} failed control occurrence(s).`));
      $('policyCompliance').append(card);
    });
    if(!data.policies.length) $('policyCompliance').append(el('div','empty','No policy summary is available.'));
  }

  function initPqc(){
    const root = $('pqcReadiness');
    const pqc = data.statistics.pqc_readiness || {};
    const tested = Number(pqc['Endpoints supporting hybrid ML-KEM groups'] || 0) + Number(pqc['Classical cryptography only'] || 0) + Number(pqc['Endpoints with PQC scan errors'] || 0);
    if(!tested){
      $('pqc').classList.add('print-skip-when-brief');
      root.append(el('div','empty','PQC testing was not enabled for this scan. The readiness summary is included above.'));
      return;
    }
    Object.entries(pqc).forEach(([key,value]) => {
      const item = el('article','pqc-detail-item');
      item.append(el('span','',key), el('strong','',value));
      root.append(item);
    });
    root.append(el('p','muted','This is an internal TLS Scan indicator, not a certification or an official standard.'));
  }

  function openEndpoint(id){
    const endpoint = data.endpoints.find((item) => item.endpoint_id === id);
    if(!endpoint) return;
    const root = $('drawerContent');
    root.textContent = '';
    root.append(el('h2','',`${endpoint.hostname}:${endpoint.port}`));
    root.append(table(['Field','Value'], [['Endpoint ID', endpoint.endpoint_id], ['IP address', endpoint.ip_address], ['Protocol', endpoint.protocol], ['TLS Grade', endpoint.overall_grade], ['Compliance Status', endpoint.compliance_status], ['Findings', endpoint.finding_count], ['Highest Severity', endpoint.highest_severity]]));
    root.append(el('h3','','Security Breakdown'), table(['Area','Result'], Object.entries(endpoint.security_breakdown)));
    root.append(el('h3','','Findings'), table(['Finding'], endpoint.finding_ids.map((finding) => [finding])));
    root.append(el('h3','','TLS Versions'), table(['Version','Status'], Object.entries(endpoint.tls_versions)));
    root.append(el('h3','','Cipher Suites'), table(['TLS version','Cipher suite','Key exchange','Authentication','Encryption','Hash','Forward secrecy','Strength','Compliance','Policy reason'], endpoint.cipher_suites.slice(0,300).map((suite) => [suite.tls_version, suite.name, suite.key_exchange, suite.authentication, suite.encryption, suite.hash_algorithm, suite.forward_secrecy, suite.strength, suite.compliance_status, suite.policy_reason])));
    root.append(el('h3','','Certificate'), table(['Field','Value'], Object.entries(endpoint.certificate).map(([key,value]) => [key, Array.isArray(value) ? value.join(', ') : value])));
    root.append(el('h3','','Certificate Trust'), table(['Field','Value'], [['Trust classification', endpoint.certificate.trust_classification], ['Chain validation', endpoint.certificate.chain_validation_status], ['Trusted by', trustedByLabel(endpoint.certificate)], ['Trust anchor', trustAnchorLabel(endpoint.certificate)]]));
    root.append(el('h3','trust-store-heading','Trust Store Results'), table(['Trust Store','Result','Trust Anchor','Error'], (endpoint.certificate.trust_store_results || []).map((result) => [result.store_name, result.status, result.trust_anchor_subject || 'None', result.validation_error || ''])));
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
  $('downloadCsv').addEventListener('click', downloadCsv);
  $('closeDrawer').addEventListener('click', closeDrawer);
  $('drawerBackdrop').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', (event) => { if(event.key === 'Escape') closeDrawer(); });

  initNavigation();
  initContext();
  initKpis();
  initCharts();
  initTopFindings();
  initFindings();
  initEndpoints();
  initCertificates();
  initCertificateTrust();
  initCommunicationSecurity();
  initCompliance();
  initPqc();
  initTechnical();
})();
