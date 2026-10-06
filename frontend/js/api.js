// frontend/js/api.js
const API = "";  // same origin

async function apiGet(path){
  const r = await fetch(API + path);
  if(!r.ok) throw new Error(await r.text());
  return r.json();
}
async function apiPost(path, body){
  const r = await fetch(API + path, {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify(body||{})
  });
  if(!r.ok) throw new Error(await r.text());
  return r.json();
}