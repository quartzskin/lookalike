"use strict";

const $ = (id) => document.getElementById(id);
let reports = [];

function cell(row, text, cls) {
  const td = document.createElement("td");
  td.textContent = text;
  if (cls) td.className = cls;
  row.appendChild(td);
}

function fillTable(id, rows, emptyText, cols) {
  const body = $(id).tBodies[0];
  body.replaceChildren();
  if (!rows.length) {
    const tr = body.insertRow();
    const td = tr.insertCell();
    td.colSpan = cols;
    td.className = "none";
    td.textContent = emptyText;
    return;
  }
  rows.forEach((r) => {
    const tr = body.insertRow();
    r.forEach((text) => cell(tr, text));
  });
}

function setStatus(msg) { $("status").textContent = msg || ""; }

async function post(path, body, type) {
  const res = await fetch(path, { method: "POST", headers: { "Content-Type": type }, body });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function show(list) {
  reports = list;
  const picker = $("picker");
  picker.replaceChildren();
  list.forEach((r, i) => {
    const opt = document.createElement("option");
    opt.value = i;
    opt.textContent = (r.link_text ? r.link_text + " -> " : "") + (r.host_unicode || r.input);
    picker.appendChild(opt);
  });
  $("picker-row").hidden = list.length < 2;
  $("result").hidden = list.length === 0;
  if (list.length) render(list[0]); else setStatus("no links found");
}

function render(r) {
  const v = $("verdict");
  v.textContent = r.error ? "Verdict: unreadable (" + r.error + ")" : "Verdict: " + r.verdict + ", score " + r.score + " of 100";
  v.className = r.verdict === "high-risk" || r.error ? "high-risk" : "";

  const findings = (r.findings || []).slice().sort((a, b) => b.score - a.score);
  fillTable("findings", findings.map((f) => [f.code, f.message, f.severity + ", score " + f.score]),
    "No findings.", 3);

  const rows = [];
  (r.chars || []).forEach((c, i) => {
    if (!c.kind) return;
    const shown = c.kind === "invisible" ? "(invisible)" : c.char;
    const twin = c.looks_like ? c.looks_like + " (" + c.looks_like_name + ")" : "-";
    rows.push([String(i + 1), shown, c.codepoint, c.name, twin]);
  });
  fillTable("chars", rows, "No lookalike characters in the host.", 5);
}

$("picker").addEventListener("change", (e) => render(reports[Number(e.target.value)]));

$("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = $("input").value;
  if (!text.trim()) { setStatus("type or paste something first"); return; }
  setStatus("");
  try {
    const data = await post("/api/check", JSON.stringify({ input: text, html: $("html").checked }), "application/json");
    show(data.reports);
  } catch (err) { setStatus(err.message); }
});

$("qr").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  setStatus("");
  try {
    const data = await post("/api/qr", await file.arrayBuffer(), "application/octet-stream");
    $("input").value = data.text;
    show(data.reports);
  } catch (err) { setStatus(err.message); }
  e.target.value = "";
});

// #text in the address bar prefills and runs a check; the fragment never leaves the browser
if (location.hash.length > 1) {
  try { $("input").value = decodeURIComponent(location.hash.slice(1)); } catch (e) { /* malformed escape: ignore */ }
  if ($("input").value) $("form").requestSubmit();
}
