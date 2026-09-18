// Shared scope-type classifier. Asset strings are classified by shape since platforms label types differently.
const STYPES = {w: "Wildcards", d: "Domains / URLs", m: "Mobile apps", i: "IP ranges", c: "Source code", o: "Other"};
const RDNS = /^(com|org|net|io|de|fr|nl|app|co|uk|ai|tv|me|ch|se|be|dk|no|fi|br|jp|au|ca|in|es|it|pl|at)\.[\w-]+(\.[\w-]+)+$/i;
function stype(a){
  a = String(a).trim();
  if(/play\.google\.com|apps\.apple\.com|itunes\.apple\.com|^id\d{6,}$|^\d{9,10}$/i.test(a) || (RDNS.test(a) && !/\//.test(a) && !/\.(com|net|org|io|de|fr|nl|app|co|ai)$/i.test(a))) return "m";
  if(a.includes("*")) return "w";
  if(/(github\.com|gitlab\.com|bitbucket\.org)\//i.test(a)) return "c";
  if(/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|^(\d{1,3}\.){3}\d{1,3}\s*-\s*(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]*(\/\d+)?$/i.test(a)) return "i";
  if(/^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(:\d+)?(\/\S*)?$/i.test(a)) return "d";
  return "o";
}
// Filter value: "" (any), a single type code, or "wd" (has both wildcards and domains).
function typeMatch(assets, f){
  if(!f) return true;
  const t = new Set(assets.map(stype));
  return f === "wd" ? t.has("w") && t.has("d") : t.has(f);
}
function typeOptions(label){
  return `<option value="">${label}</option><option value="w">Wildcards</option><option value="d">Domains / URLs</option><option value="wd">Wildcards + domains</option>`
    + `<option value="m">Mobile apps</option><option value="i">IP ranges</option><option value="c">Source code</option><option value="o">Other</option>`;
}
function typeSummary(assets){
  const n = {}; assets.forEach(a => { const t = stype(a); n[t] = (n[t]||0) + 1; });
  return Object.keys(STYPES).filter(t => n[t]).map(t => `${n[t]} ${STYPES[t].toLowerCase()}`).join(" · ");
}
