import http from 'node:http';
import { Readable } from 'node:stream';
import * as cheerio from 'cheerio';
import { WebSocketServer, WebSocket } from 'ws';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';
const MAX_BYTES = 10 * 1024 * 1024;
const JS_REWRITE_LIMIT = 4 * 1024 * 1024;
const MAX_REDIRECTS = 5;
const PROXY = '/api/proxy?url=';
let ALLOW_PRIVATE = false;
let SELF_HOST = '';

const dec = b => new TextDecoder('utf-8').decode(b);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const decodeEntities = s => String(s).replace(/&(#x?[0-9a-f]+|amp|lt|gt|quot|apos|nbsp);/gi, (m, e) => {
  const l = e.toLowerCase();
  if (l === 'amp') return '&'; if (l === 'lt') return '<'; if (l === 'gt') return '>';
  if (l === 'quot') return '"'; if (l === 'apos') return "'"; if (l === 'nbsp') return ' ';
  const n = l[1] === 'x' ? parseInt(l.slice(2), 16) : parseInt(l.slice(1), 10);
  try { return String.fromCodePoint(n); } catch { return m; }
});
const stripTags = s => decodeEntities(String(s).replace(/<[^>]*>/g, '')).replace(/\s+/g, ' ').trim();

function decodeBody(buf, ctype) {
  let cs = (/charset\s*=\s*["']?([\w.:-]+)/i.exec(ctype || '') || [])[1];
  if (!cs) {
    const head = new TextDecoder('latin1').decode(buf.subarray(0, 2048));
    const m = head.match(/<meta[^>]+charset\s*=\s*["']?([\w.:-]+)/i);
    cs = m && m[1];
  }
  try { return new TextDecoder(cs || 'utf-8').decode(buf); } catch { return dec(buf); }
}

function httpErr(status, message) { const e = new Error(message); e.status = status; return e; }
function isPrivateHost(host) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.internal') || h.endsWith('.local')) return true;
  if (/^\d+$/.test(h) || /^0x[0-9a-f]+$/i.test(h)) return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 198 && (b === 18 || b === 19)) || a >= 224;
  }
  if (h.includes(':')) {
    if (h === '::1' || h === '::' || /^f[cd]/.test(h) || /^fe[89ab]/.test(h)) return true;
    if (h.startsWith('::ffff:')) return true;
  }
  return false;
}
function checkTarget(raw) {
  let u;
  try { u = new URL(raw); } catch { throw httpErr(400, 'That is not a valid URL.'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw httpErr(400, 'Only http and https URLs are supported.');
  if (!ALLOW_PRIVATE && isPrivateHost(u.hostname)) throw httpErr(403, 'That address is not allowed.');
  if (SELF_HOST && u.hostname.toLowerCase() === SELF_HOST) throw httpErr(403, 'The proxy cannot fetch itself.');
  return u;
}

function refererFor(u, ref) {
  if (!ref) return u.origin + '/';
  try { const r = new URL(ref); return r.origin === u.origin ? r.href : r.origin + '/'; } catch { return u.origin + '/'; }
}
async function fetchFollow(startUrl, init = {}) {
  let url = startUrl, method = init.method || 'GET', body = init.body;
  const extra = { ...(init.headers || {}) };
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const u = checkTarget(url);
    const headers = { 'user-agent': UA, accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'accept-language': 'en-US,en;q=0.9', ...extra, referer: refererFor(u, init.referrer) };
    if (method !== 'GET' && method !== 'HEAD') headers.origin = u.origin;
    let res;
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 12000);
    try {
      res = await fetch(u.href, { method, body, redirect: 'manual', signal: ac.signal, headers });
    } catch (e) {
      throw httpErr(504, 'Could not reach ' + u.hostname + ' (' + (e && e.name === 'AbortError' ? 'timed out' : 'connection failed') + ').');
    } finally { clearTimeout(timer); }
    const loc = res.headers.get('location');
    if ([301, 302, 303, 307, 308].includes(res.status) && loc) {
      let next;
      try { next = new URL(loc, u); } catch { throw httpErr(502, 'The site sent an invalid redirect.'); }
      try { await res.body?.cancel(); } catch {}
      if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === 'POST')) {
        if (method !== 'HEAD') method = 'GET';
        body = undefined; delete extra['content-type'];
      }
      if (next.origin !== u.origin) delete extra.authorization;
      url = next.href;
      continue;
    }
    return { res, url: u.href };
  }
  throw httpErr(508, 'Too many redirects.');
}
async function readBody(res) {
  const len = Number(res.headers.get('content-length') || 0);
  if (len > MAX_BYTES) throw httpErr(413, 'That file is too large to proxy (limit 10 MB).');
  let buf;
  try { buf = new Uint8Array(await res.arrayBuffer()); } catch { throw httpErr(504, 'The connection dropped while downloading.'); }
  if (buf.length > MAX_BYTES) throw httpErr(413, 'That file is too large to proxy (limit 10 MB).');
  return buf;
}

const DROP_REQ = /^(host|connection|content-length|cookie|origin|referer|user-agent|accept-encoding|te|upgrade|upgrade-insecure-requests|transfer-encoding|keep-alive|via|forwarded|priority|dnt|proxy-.*|cf-.*|x-forwarded-.*|x-real-ip|true-client-ip|sec-.*)$/i;
function forwardHeaders(h) {
  const o = {};
  for (const [k, v] of h) if (!DROP_REQ.test(k)) o[k.toLowerCase()] = v;
  return o;
}

function realFromReferer(request, reqUrl) {
  try {
    const r = new URL(request.headers.get('referer') || '');
    if (r.host !== reqUrl.host || r.pathname !== '/api/proxy') return null;
    const u = r.searchParams.get('url');
    return u ? new URL(u).href : null;
  } catch { return null; }
}

const ytParse=raw=>{let u;try{u=new URL(raw)}catch{return null}const h=u.hostname.toLowerCase().replace(/^(www|m)\./,'');let id=null;if(h==='youtu.be')id=u.pathname.slice(1).split('/')[0];else if(h==='youtube.com'||h==='youtube-nocookie.com'){const p=u.pathname;if(p==='/watch')id=u.searchParams.get('v');else{const m=p.match(/^\/(shorts|embed|live|v)\/([\w-]{6,})/);if(m)id=m[2]}}if(!id||!/^[\w-]{6,20}$/.test(id))return null;return{id,list:u.searchParams.get('list'),t:u.searchParams.get('t')||u.searchParams.get('start')}};
const ytPage=y=>{const q=new URLSearchParams({autoplay:'1',rel:'0',playsinline:'1',modestbranding:'1'});if(y.list&&!/^RD/.test(y.list))q.set('list',y.list);const st=parseInt(y.t,10);if(st>0)q.set('start',String(st));return'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>YouTube</title><style>html,body{height:100%;margin:0;background:#000}iframe{position:absolute;inset:0;width:100%;height:100%;border:0}</style><iframe src="https://www.youtube-nocookie.com/embed/'+y.id+'?'+q.toString()+'" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share; fullscreen" allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe>'};
function parseDDG(html) {
  const out = [];
  const tagRe = /<a\b[^>]*class="[^"]*\bresult__a\b[^"]*"[^>]*>/gi;
  const starts = [];
  let m;
  while ((m = tagRe.exec(html))) starts.push({ tag: m[0], idx: m.index, end: m.index + m[0].length });
  for (let i = 0; i < starts.length; i++) {
    const s = starts[i];
    const chunkEnd = i + 1 < starts.length ? starts[i + 1].idx : html.length;
    const closeIdx = html.indexOf('</a>', s.end);
    const title = stripTags(html.slice(s.end, closeIdx < 0 ? s.end : closeIdx));
    const hm = s.tag.match(/href="([^"]*)"/i);
    if (!hm || !title) continue;
    let href = decodeEntities(hm[1]);
    try {
      const x = new URL(href, 'https://duckduckgo.com');
      const real = x.searchParams.get('uddg');
      href = real || x.href;
    } catch { continue; }
    if (!/^https?:\/\//i.test(href) || /duckduckgo\.com\/y\.js/.test(href)) continue;
    const rest = html.slice(s.end, chunkEnd);
    const sm = rest.match(/class="[^"]*\bresult__snippet\b[^"]*"[^>]*>([\s\S]*?)<\/a>/i);
    out.push({ t: title, u: href, s: sm ? stripTags(sm[1]) : '' });
  }
  return out;
}
function parseBing(html) {
  const out = [];
  const blocks = html.split(/<li class="b_algo\b[^"]*"/i).slice(1);
  for (const b of blocks) {
    const a = b.match(/<h2[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/i);
    if (!a) continue;
    let href = decodeEntities(a[1]);
    const bm = href.match(/[?&]u=a1([^&]+)/);
    if (bm) {
      try {
        const bin = atob(bm[1].replace(/-/g, '+').replace(/_/g, '/'));
        href = dec(Uint8Array.from(bin, c => c.charCodeAt(0)));
      } catch {}
    }
    if (!/^https?:\/\//i.test(href)) continue;
    const p = b.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
    out.push({ t: stripTags(a[2]), u: href, s: p ? stripTags(p[1]) : '' });
  }
  return out;
}
async function wikiSearch(q) {
  let r;
  try {
    r = await fetch('https://en.wikipedia.org/w/api.php?action=query&list=search&srlimit=10&format=json&srsearch=' + encodeURIComponent(q), { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(10000) });
  } catch { throw httpErr(504, 'Could not reach Wikipedia.'); }
  if (!r.ok) throw httpErr(502, 'Wikipedia answered ' + r.status + '.');
  let j;
  try { j = await r.json(); } catch { throw httpErr(502, 'Wikipedia sent an unreadable answer.'); }
  return ((j.query && j.query.search) || []).map(x => ({
    t: x.title, u: 'https://en.wikipedia.org/wiki/' + encodeURIComponent(x.title.replace(/ /g, '_')), s: stripTags(x.snippet),
  }));
}
async function runSearch(q, engine) {
  const enc = encodeURIComponent;
  if (engine === 'wikipedia') return { label: 'Wikipedia', results: await wikiSearch(q) };
  try {
    if (engine === 'bing') {
      const { res } = await fetchFollow('https://www.bing.com/search?q=' + enc(q) + '&setlang=en');
      const r = parseBing(decodeBody(await readBody(res), res.headers.get('content-type')));
      if (r.length) return { label: 'Bing', results: r };
    } else {
      const { res } = await fetchFollow('https://html.duckduckgo.com/html/?q=' + enc(q));
      const r = parseDDG(decodeBody(await readBody(res), res.headers.get('content-type')));
      if (r.length) return { label: 'Venom', results: r };
    }
  } catch {}
  return { label: 'Wikipedia (web search was unavailable)', results: await wikiSearch(q) };
}

const CSS = '@font-face{font-family:"Avenir Next LT Pro Light";src:local("Avenir Next LT Pro Light"),local("AvenirNextLTPro-Light"),local("Avenir Next LT Pro"),local("AvenirNextLTPro-Regular"),local("Avenir Light"),local("Avenir-Light"),local("Avenir Next"),local("Avenir"),local("Nunito Sans");font-weight:300;font-style:normal}*{box-sizing:border-box}body{margin:0;font:15px/1.55 -apple-system,system-ui,"Segoe UI",sans-serif;background:#fff;color:#202124}header{display:flex;gap:16px;align-items:center;padding:14px 24px;border-bottom:1px solid #e3e3e8;position:sticky;top:0;background:inherit}.lg,input,select,button{font-family:"Avenir Next LT Pro Light","Avenir Next","Avenir","Nunito Sans","Segoe UI",system-ui,sans-serif;font-weight:300}.lg{display:flex;align-items:center;gap:10px;font-size:26px;letter-spacing:-.2px}.lg img{width:36px;height:36px;border-radius:9px;display:block;box-shadow:0 2px 8px rgba(76,29,149,.4)}.lg b{font-weight:300;background:linear-gradient(90deg,#7c3aed,#2563eb);-webkit-background-clip:text;background-clip:text;color:transparent}form{display:flex;gap:8px;flex:1;max-width:640px}input,select{font-size:15px;padding:9px 16px;border-radius:999px;border:1px solid #d0d0d8;background:transparent;color:inherit;outline:none}input{flex:1}input:focus{border-color:#7c3aed}select{cursor:pointer;border-color:#c4b5fd;background:linear-gradient(180deg,rgba(124,58,237,.07),rgba(76,29,149,.16));box-shadow:0 2px 8px rgba(76,29,149,.28),inset 0 -2px 0 rgba(91,33,182,.2)}button{font-size:15px;padding:9px 20px;border-radius:999px;border:0;color:#fff;cursor:pointer;background:linear-gradient(180deg,#6d28d9,#4c1d95);box-shadow:0 2px 0 #35106f,0 6px 14px rgba(76,29,149,.5),inset 0 1px 0 rgba(255,255,255,.2)}button:hover{background:linear-gradient(180deg,#5b21b6,#3b0f7a)}button:active{transform:translateY(1px);box-shadow:0 1px 0 #35106f,0 2px 6px rgba(76,29,149,.45),inset 0 2px 4px rgba(0,0,0,.25)}main{max-width:720px;padding:8px 24px 48px;margin:0}h2{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#777;margin:28px 0 6px}ul{list-style:none;margin:0;padding:0}li{padding:10px 0}a.t{font-size:18px;color:#1a0dab;text-decoration:none}a.t:hover{text-decoration:underline}.u{font-size:12.5px;color:#0b7a3b}li p{margin:2px 0 0;color:#4d5156}.note{color:#777;font-size:13.5px;padding:8px 0}option{color:#000}@media(prefers-color-scheme:dark){body{background:#1c1c1e;color:#e8e8ea}header{border-color:#38383c}a.t{color:#9db4ff}.u{color:#6fcf97}li p{color:#b4b4ba}input{border-color:#48484e}select{border-color:#6d4bd1;box-shadow:0 2px 8px rgba(0,0,0,.5),inset 0 -2px 0 rgba(139,92,246,.25)}.lg img{box-shadow:0 2px 10px rgba(0,0,0,.6)}}';
const LOGO = 'data:image/png;base64,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';
function searchPage(q, engine, label, results, noteHtml) {
  const items = results.map(r => '<li><a class="t" href="' + PROXY + encodeURIComponent(r.u) + '">' + esc(r.t) + '</a><div class="u">' +
    esc(r.u.replace(/^https?:\/\/(www\.)?/i, '').slice(0, 90)) + '</div>' + (r.s ? '<p>' + esc(r.s) + '</p>' : '') + '</li>').join('');
  const body = results.length ? '<ul>' + items + '</ul>'
    : (q ? '<p class="note">No results for “' + esc(q) + '”.</p>' : (noteHtml || ''));
  return '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>' + esc(q || 'Search') + ' – Venom</title><style>' + CSS + '</style>' +
    '<header><span class="lg"><img src="' + LOGO + '" alt=""><b>Venom</b></span><form action="/api/proxy" method="get"><input name="q" value="' + esc(q) + '" autocomplete="off" aria-label="Search"><select name="engine" aria-label="Engine"><option value="bing" selected>Bing</option><option value="venom">Venom</option><option value="wikipedia">Wikipedia</option></select><button type="submit">Search</button></form></header>' +
    '<main><h2>' + esc(label) + '</h2>' + body + '</main>';
}
function messagePage(status, message) {
  return '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>Venom</title><style>' + CSS + 'body{display:grid;place-content:center;min-height:100vh;text-align:center;padding:24px}</style>' +
    '<h1 style="margin:0 0 8px">' + esc(status) + '</h1><p class="note">' + esc(message) + '</p>';
}

function proxify(v, base) {
  const s = String(v).trim();
  if (!s || s[0] === '#' || /^(?:data|blob|javascript|mailto|tel|about):/i.test(s)) return v;
  try {
    const x = new URL(s, base);
    if (x.protocol !== 'http:' && x.protocol !== 'https:') return v;
    const hash = x.hash;
    x.hash = '';
    return PROXY + encodeURIComponent(x.href) + hash;
  } catch { return v; }
}
function proxifySrcset(s, base) {
  return String(s).split(/\s*,\s+/).filter(Boolean).map(c => {
    const p = c.trim().split(/\s+/);
    p[0] = proxify(p[0], base);
    return p.join(' ');
  }).join(', ');
}
function rewriteCss(css, base) {
  return css
    .replace(/(@import\s+)(["'])([^"'\n]+)\2/gi, (m, a, q, u) => a + q + proxify(u, base) + q)
    .replace(/url\(\s*(?:(["'])(.*?)\1|([^)"'\s][^)]*?))\s*\)/gi, (m, q, u1, u2) => {
      const u = (u1 !== undefined ? u1 : u2).trim();
      const p = proxify(u, base);
      return p === u ? m : 'url("' + p + '")';
    });
}

function rewriteJs(js, base) {
  if (!/\b(?:import|export)\b/.test(js)) return js;
  const fix = s => (/^(?:\.{0,2}\/|https?:\/\/)/.test(s) ? proxify(s, base) : s);
  const sub = (m, a, q, s) => a + q + fix(s) + q;
  return js
    .replace(/(\b(?:import|export)\b[^'"`;()=]*?\bfrom\s*)(["'])([^"'\n]+)\2/g, sub)
    .replace(/(\bimport\s*)(["'])([^"'\n]+)\2/g, sub)
    .replace(/(\bimport\s*\(\s*)(["'])([^"'\n]+)\2/g, sub);
}

const CLIENT_SHIM = String.raw`(function(B){
var P='/api/proxy?url=',O=location.origin;
var IF=false;try{IF=window.parent!==window}catch(e){}
function RP(m){if(!IF)return;try{window.parent.postMessage(m,'*')}catch(e){}}
function RL(u){var s=String(u),r=unpx(s);if(r)return r;try{return new URL(s,B).href}catch(e){return s}}
function RS(){RP({venomos:'page',url:String(B).replace(/#.*$/,''),title:document.title||'',ready:document.readyState})}
function isP(s){return s.indexOf(P)===0||s.indexOf(O+P)===0}
function unpx(u){var s=String(u);if(!isP(s))return null;var r=s.slice(s.indexOf('?url=')+5),h=r.indexOf('#');if(h>-1)r=r.slice(0,h);try{return decodeURIComponent(r)}catch(e){return null}}
function px(u){try{var s=String(u);if(!s||s.charAt(0)==='#'||/^(data|blob|javascript|mailto|tel|about):/i.test(s)||isP(s))return u;var x=new URL(s,B);if(x.protocol!=='http:'&&x.protocol!=='https:')return u;if(x.host===location.host){if(x.pathname==='/api/proxy')return u;x=new URL(x.pathname+x.search+x.hash,B)}var h=x.hash;x.hash='';return P+encodeURIComponent(x.href)+h}catch(e){return u}}
var F=window.fetch;
if(F)window.fetch=function(i,n){var self=this;try{
if(typeof i==='string'||i instanceof URL)i=px(i);
else if(i&&i.url&&typeof Request!=='undefined'&&i instanceof Request){var u0=i.url,u1=px(u0);if(u1!==u0){var rq=i,mt=rq.method;
if(mt==='GET'||mt==='HEAD'){i=new Request(new URL(u1,location.href).href,rq)}
else{var nn=n;return rq.clone().arrayBuffer().then(function(b){var o={method:mt,headers:rq.headers,credentials:rq.credentials,cache:rq.cache,redirect:rq.redirect,signal:rq.signal};if(b.byteLength)o.body=b;if(nn){o=Object.assign(o,nn);delete o.referrer}return F.call(self,u1,o)})}}}
if(n&&n.referrer){n=Object.assign({},n);delete n.referrer}
}catch(e){}return F.call(this,i,n)};
var XO=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){var a=[].slice.call(arguments);a[1]=px(u);return XO.apply(this,a)};
var WO=window.open;
window.open=function(u){var a=[].slice.call(arguments);if(u&&IF&&!/^(javascript|data|blob|about|mailto|tel):/i.test(String(u))){var ru=RL(u);if(/^https?:/i.test(ru)){RP({venomos:'open',url:ru});return null}}if(u)a[0]=px(u);return WO.apply(this,a)};
var WS=window.WebSocket;
if(WS){var PW=function(u,p){var x,w=u;try{x=new URL(String(u),B);if(x.host===location.host){if(x.pathname!=='/api/proxy'){x=new URL(x.pathname+x.search,B);w=(location.protocol==='https:'?'wss:':'ws:')+'//'+location.host+P+encodeURIComponent(x.href)}}else w=(location.protocol==='https:'?'wss:':'ws:')+'//'+location.host+P+encodeURIComponent(x.href)}catch(e){}return arguments.length>1?new WS(w,p):new WS(w)};PW.prototype=WS.prototype;PW.CONNECTING=0;PW.OPEN=1;PW.CLOSING=2;PW.CLOSED=3;window.WebSocket=PW}
var ES=window.EventSource;
if(ES){var PE=function(u,o){return new ES(px(u),o)};PE.prototype=ES.prototype;PE.CONNECTING=0;PE.OPEN=1;PE.CLOSED=2;window.EventSource=PE}
var SB=navigator.sendBeacon;
if(SB)navigator.sendBeacon=function(u,d){return SB.call(navigator,px(u),d)};
var WK=window.Worker;
if(WK){var PK=function(u,o){return new WK(px(u),o)};PK.prototype=WK.prototype;window.Worker=PK}
try{if(navigator.serviceWorker)navigator.serviceWorker.register=function(){return Promise.reject(new DOMException('Service workers are not available in the proxy','SecurityError'))}}catch(e){}
try{Object.defineProperty(Navigator.prototype,'onLine',{get:function(){return true},configurable:true})}catch(e){}
var AT={src:1,href:1,poster:1,data:1};
var TG=/^(script|link|img|source|iframe|frame|video|audio|track|embed|object|input)$/i;
var SA=Element.prototype.setAttribute;
Element.prototype.setAttribute=function(n,v){var l=String(n).toLowerCase();if(AT[l]&&this.namespaceURI==='http://www.w3.org/1999/xhtml'&&TG.test(this.tagName))v=px(v);return SA.call(this,n,v)};
function hp(C,p){try{var c=window[C];if(!c)return;var d=Object.getOwnPropertyDescriptor(c.prototype,p);if(!d||!d.set)return;Object.defineProperty(c.prototype,p,{configurable:true,enumerable:d.enumerable,get:d.get,set:function(v){d.set.call(this,px(v))}})}catch(e){}}
[['HTMLScriptElement','src'],['HTMLImageElement','src'],['HTMLLinkElement','href'],['HTMLIFrameElement','src'],['HTMLSourceElement','src'],['HTMLMediaElement','src'],['HTMLEmbedElement','src'],['HTMLTrackElement','src'],['HTMLInputElement','src'],['HTMLObjectElement','data'],['HTMLVideoElement','poster']].forEach(function(a){hp(a[0],a[1])});
['pushState','replaceState'].forEach(function(k){var o=history[k];history[k]=function(s,t,u){if(u!=null&&u!==''){try{var x=unpx(u)||new URL(String(u),B).href;B=x;var y=new URL(x);u=P+encodeURIComponent(y.href.replace(/#.*$/,''))+y.hash}catch(e){}}var r=o.call(this,s,t,u);try{RS()}catch(e){}return r}});
function fix(n){if(!n||n.nodeType!==1)return;var els=[n].concat([].slice.call(n.querySelectorAll?n.querySelectorAll('[src],[poster],link[href],object[data]'):[]));els.forEach(function(el){if(!TG.test(el.tagName))return;['src','poster','href','data'].forEach(function(a){var v=el.getAttribute(a);if(v==null)return;if(a==='href'&&el.tagName.toLowerCase()!=='link')return;var p=px(v);if(p!==v)SA.call(el,a,p)})})}
try{new MutationObserver(function(ms){ms.forEach(function(m){[].forEach.call(m.addedNodes,fix)})}).observe(document,{childList:true,subtree:true})}catch(e){}
document.addEventListener('click',function(e){
var a=e.target&&e.target.closest&&e.target.closest('a[href],area[href]');
if(!a||e.defaultPrevented||e.button||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey)return;
var h=a.getAttribute('href')||'';
if(IF&&a.getAttribute('target')==='_blank'&&!/^(javascript|mailto|tel|data|blob):/i.test(h)&&h.charAt(0)!=='#'){var ru=RL(h);if(/^https?:/i.test(ru)){e.preventDefault();RP({venomos:'open',url:ru});return}}
if(/^(javascript|mailto|tel|data|blob):/i.test(h)||isP(h))return;
if(h.charAt(0)==='#'){e.preventDefault();location.hash=h.slice(1);return}
var g=px(h);if(g===h)return;
e.preventDefault();
if(a.getAttribute('target')==='_blank')window.open(g);else location.href=g
},false);
document.addEventListener('submit',function(e){
var f=e.target;if(!f||f.tagName!=='FORM'||e.defaultPrevented)return;
if((f.getAttribute('method')||'get').toLowerCase()!=='get')return;
var x;try{x=new URL(unpx(f.getAttribute('action')||'')||f.getAttribute('action')||B,B)}catch(_){return}
if(x.protocol!=='http:'&&x.protocol!=='https:')return;
e.preventDefault();
var d;try{d=new FormData(f,e.submitter)}catch(_){d=new FormData(f)}
var q=new URLSearchParams();d.forEach(function(v,k){if(typeof v==='string')q.append(k,v)});
x.search=q.toString();
location.href=px(x.href)
},false);
function ytHost(){try{return /(^|\.)youtube(-nocookie)?\.com$/i.test(new URL(B).hostname)}catch(e){return false}}
window.addEventListener('click',function(e){
if(e.button||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey||!ytHost())return;
var a=null,pa=e.composedPath?e.composedPath():[];
for(var k=0;k<pa.length;k++){var t=pa[k];if(t&&t.tagName==='A'&&t.getAttribute&&t.getAttribute('href')){a=t;break}}
if(!a||a.getAttribute('target')==='_blank'||a.hasAttribute('download'))return;
var h=a.getAttribute('href')||'';
if(!h||h.charAt(0)==='#'||/^(javascript|mailto|tel|data|blob):/i.test(h)||isP(h))return;
var tg;try{tg=new URL(h,B)}catch(_){return}
if(!/^https?:$/.test(tg.protocol)||!/(^|\.)youtube\.com$/i.test(tg.hostname))return;
e.preventDefault();e.stopImmediatePropagation();
location.href=px(tg.href)
},true);
try{if(window.navigation&&navigation.addEventListener)navigation.addEventListener('navigate',function(e){
try{
if(e.hashChange||e.formData||e.downloadRequest!=null||e.navigationType==='reload'||e.navigationType==='traverse'||!e.cancelable)return;
if(e.destination.sameDocument)return;
var d=new URL(e.destination.url);
if(d.protocol!=='http:'&&d.protocol!=='https:')return;
if(d.origin===O&&d.pathname==='/api/proxy'&&d.searchParams.has('url'))return;
var nx=px(d.href);
if(nx===d.href)return;
e.preventDefault();
if(e.navigationType==='replace')location.replace(nx);else location.assign(nx)
}catch(_){}})}catch(_){}
RS();document.addEventListener('DOMContentLoaded',RS);window.addEventListener('load',RS);window.addEventListener('hashchange',RS);
if(IF){var LT=document.title;setInterval(function(){if(document.title!==LT){LT=document.title;RS()}},800)}
})`;

const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];
function reply(req, status, headers, body) {
  const origin = req && req.headers.get('origin');
  const h = new Headers({
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': (req && req.headers.get('access-control-request-headers')) || '*',
    'Access-Control-Expose-Headers': 'x-final-url, content-type, content-range, accept-ranges, content-disposition',
  });
  if (origin) { h.set('Access-Control-Allow-Credentials', 'true'); h.set('Vary', 'Origin'); }
  for (const k of Object.keys(headers)) h.set(k, headers[k]);
  return new Response([204, 205, 304].includes(status) ? null : body, { status, headers: h });
}
async function handleFetch(request) {
  const env = process.env;
    ALLOW_PRIVATE = !!(env && env.ALLOW_PRIVATE === '1');
    const R = (status, headers, body) => reply(request, status, headers, body);
    try {
      const reqUrl = new URL(request.url);
      SELF_HOST = reqUrl.hostname.toLowerCase();
      const params = reqUrl.searchParams;
      const target = (params.get('url') || '').trim();
      if (request.method === 'OPTIONS') return R(204, {}, null);

      if (reqUrl.pathname !== '/api/proxy' && !params.has('url')) {
        const real = realFromReferer(request, reqUrl);
        if (real) {
          try { return R(307, { location: PROXY + encodeURIComponent(new URL(reqUrl.pathname + reqUrl.search, real).href), 'cache-control': 'no-store' }, null); } catch {}
        }
      }
      if (!METHODS.includes(request.method)) return R(405, { 'content-type': 'text/plain' }, 'Method not allowed');

      const q = (params.get('q') || '').trim().slice(0, 300);
      if (q) {
        const eg = String(params.get('engine') || '').toLowerCase();
        const engine = eg === 'wikipedia' ? 'wikipedia' : (eg === 'venom' || eg === 'paradox') ? 'venom' : 'bing';
        const { label, results } = await runSearch(q, engine);
        return R(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=300' }, searchPage(q, engine, label, results));
      }
      if (!target && reqUrl.pathname !== '/api/proxy' && reqUrl.pathname !== '/') throw httpErr(404, 'Nothing here.');
      if (!target) {
        return R(200, { 'content-type': 'text/html; charset=utf-8' },
          searchPage('', 'bing', 'Search', [], '<p class="note">Venom server is running. Type a search above, or call /api/proxy?url=https://example.com</p>'));
      }

      if (request.method === 'GET' && params.get('raw') !== '1') {
        const yv = ytParse(target);
        if (yv) return R(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }, ytPage(yv));
      }
      const hasBody = request.method !== 'GET' && request.method !== 'HEAD';
      let body;
      if (hasBody) {
        const ab = await request.arrayBuffer();
        if (ab.byteLength > MAX_BYTES) throw httpErr(413, 'That request is too large to proxy (limit 10 MB).');
        if (ab.byteLength) body = ab;
      }
      const { res: up, url: finalUrl } = await fetchFollow(target, {
        method: request.method, body, headers: forwardHeaders(request.headers), referrer: realFromReferer(request, reqUrl),
      });
      if (/(^|\.)google\.[a-z.]+$/i.test(new URL(finalUrl).hostname) && /^\/sorry\//.test(new URL(finalUrl).pathname)) throw httpErr(429, 'Google is rejecting this server with an unusual-traffic check, so this page cannot be loaded through it.');
      const ctype = up.headers.get('content-type') || 'application/octet-stream';
      const cc = up.headers.get('cache-control') || '';
      const cache = (hasBody || !up.ok || /no-store|no-cache|private/i.test(cc)) ? 'no-store' : 'public, max-age=300';
      const hdr = extra => Object.assign({ 'x-final-url': finalUrl, 'cache-control': cache }, extra);
      const raw = params.get('raw') === '1';
      const isHtml = /text\/html|application\/xhtml/i.test(ctype);
      const isCss = /text\/css/i.test(ctype);
      const isJs = /javascript|ecmascript/i.test(ctype);

      if (!raw && (isHtml || isCss || isJs)) {
        const buf = await readBody(up);
        const status = up.status === 206 ? 200 : up.status;
        if (isHtml) return R(status, hdr({ 'content-type': 'text/html; charset=utf-8' }), rewriteHtml(decodeBody(buf, ctype), finalUrl));
        if (isCss) return R(status, hdr({ 'content-type': 'text/css; charset=utf-8' }), rewriteCss(decodeBody(buf, ctype), finalUrl));
        if (buf.length <= JS_REWRITE_LIMIT) return R(status, hdr({ 'content-type': 'text/javascript; charset=utf-8' }), rewriteJs(decodeBody(buf, ctype), finalUrl));
        return R(status, hdr({ 'content-type': ctype }), buf);
      }

      const pass = { 'content-type': ctype };
      for (const k of ['content-range', 'accept-ranges', 'content-disposition']) { const v = up.headers.get(k); if (v) pass[k] = v; }
      return R(up.status, hdr(pass), up.body);
    } catch (e) {
      const status = e && e.status ? e.status : 500;
      return R(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }, messagePage('Error ' + status, (e && e.message) || 'Something went wrong.'));
    }
}

// ---------- HTML rewriting (replaces Cloudflare HTMLRewriter) ----------
function rewriteHtml(html, finalUrl) {
  const $ = cheerio.load(html);
  let base = finalUrl;
  const shim = '<script>' + CLIENT_SHIM + '(' + JSON.stringify(finalUrl).replace(/</g, '\\u003c') + ')</script>';

  $('meta[name="referrer"]').remove();
  $('base').each((_, el) => {
    const h = $(el).attr('href');
    if (h) { try { base = new URL(h, finalUrl).href; } catch {} }
    $(el).remove();
  });
  $('meta[http-equiv]').each((_, el) => {
    const he = ($(el).attr('http-equiv') || '').toLowerCase();
    if (['content-security-policy', 'content-security-policy-report-only', 'x-frame-options', 'refresh'].includes(he)) $(el).remove();
  });

  const attr = (sel, name) => $(sel).each((_, el) => {
    const v = $(el).attr(name);
    if (v != null) $(el).attr(name, proxify(v, base));
  });
  attr('a[href], area[href], link[href]', 'href');
  attr('script[src], img[src], source[src], video[src], audio[src], track[src], embed[src], iframe[src], frame[src], input[src]', 'src');
  attr('video[poster]', 'poster');
  attr('object[data]', 'data');
  $('[srcset]').each((_, el) => { $(el).attr('srcset', proxifySrcset($(el).attr('srcset'), base)); });
  $('[style]').each((_, el) => {
    const s = $(el).attr('style');
    if (s && s.includes('url(')) $(el).attr('style', rewriteCss(s, base));
  });
  $('link[integrity], script[integrity]').removeAttr('integrity');
  $('style').each((_, el) => { $(el).text(rewriteCss($(el).html() || '', base)); });
  $('script:not([src])').each((_, el) => {
    const ty = ($(el).attr('type') || '').toLowerCase();
    if (ty && !/module|javascript|ecmascript/.test(ty)) return;
    $(el).text(rewriteJs($(el).html() || '', base));
  });

  $('head').prepend('<meta name="referrer" content="same-origin">' + shim);
  return $.html();
}

// ---------- WebSocket proxy (replaces Cloudflare WebSocketPair) ----------
const okCode = c => c >= 1000 && c <= 4999 && ![1004, 1005, 1006, 1015].includes(c);
function relay(from, to) {
  from.on('message', (data, isBinary) => { try { to.send(data, { binary: isBinary }); } catch {} });
  from.on('close', (code, reason) => { try { to.close(okCode(code) ? code : 1000, reason); } catch {} });
  from.on('error', () => { try { to.close(1011, 'error'); } catch {} });
}
function handleUpgrade(req, socket, head) {
  const fail = (status, msg) => { try { socket.write('HTTP/1.1 ' + status + ' ' + msg + '\r\nConnection: close\r\n\r\n'); } catch {} socket.destroy(); };
  try {
    const reqUrl = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
    SELF_HOST = reqUrl.hostname.toLowerCase();
    ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === '1';
    const target = (reqUrl.searchParams.get('url') || '').trim();
    if (!target) return fail(400, 'Bad Request');
    const t = new URL(target);
    const probe = new URL(t.href);
    if (probe.protocol === 'ws:') probe.protocol = 'http:'; else if (probe.protocol === 'wss:') probe.protocol = 'https:';
    checkTarget(probe.href);
    const wsUrl = new URL(probe.href);
    wsUrl.protocol = probe.protocol === 'https:' ? 'wss:' : 'ws:';
    const protos = (req.headers['sec-websocket-protocol'] || '').split(',').map(s => s.trim()).filter(Boolean);
    const up = new WebSocket(wsUrl.href, protos, { headers: { 'user-agent': UA, origin: probe.origin } });
    let opened = false;
    up.on('open', () => {
      opened = true;
      const wss = new WebSocketServer({ noServer: true, handleProtocols: () => up.protocol || false });
      wss.handleUpgrade(req, socket, head, client => { relay(client, up); relay(up, client); });
    });
    up.on('error', () => { if (!opened) fail(502, 'Bad Gateway'); });
  } catch (e) { fail(e && e.status ? e.status : 400, 'Bad Request'); }
}

// ---------- Node HTTP server ----------
function toRequest(req) {
  const proto = req.headers['x-forwarded-proto'] || 'http';
  const url = new URL(req.url, proto + '://' + (req.headers.host || 'localhost'));
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (Array.isArray(v)) v.forEach(x => headers.append(k, x)); else if (v != null) headers.set(k, v);
  }
  return {
    method: req.method, url: url.href, headers,
    async arrayBuffer() {
      const chunks = []; let n = 0;
      for await (const c of req) { n += c.length; if (n > MAX_BYTES) break; chunks.push(c); }
      const b = Buffer.concat(chunks);
      return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
    },
  };
}

const server = http.createServer(async (req, res) => {
  try {
    const out = await handleFetch(toRequest(req));
    const headers = {};
    out.headers.forEach((v, k) => { headers[k] = v; });
    res.writeHead(out.status, headers);
    if (!out.body || req.method === 'HEAD') return res.end();
    Readable.fromWeb(out.body).on('error', () => res.destroy()).pipe(res);
  } catch (e) {
    if (!res.headersSent) res.writeHead(500, { 'content-type': 'text/plain' });
    res.end('Internal error');
  }
});
server.on('upgrade', handleUpgrade);
const PORT = Number(process.env.PORT) || 8080;
server.listen(PORT, '0.0.0.0', () => console.log('Venom proxy listening on ' + PORT));
