"use strict";

const b64u = {
  enc(buf) {
    const s = String.fromCharCode(...new Uint8Array(buf));
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  dec(str) {
    const s = atob(str.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(s, (c) => c.charCodeAt(0));
  },
};

const status = (msg) => { document.getElementById("status").textContent = msg; };

async function post(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

// PRF output from a create() or get() result, if the authenticator gave one.
function prfOutput(cred) {
  const ext = cred.getClientExtensionResults();
  const first = ext && ext.prf && ext.prf.results && ext.prf.results.first;
  return first ? b64u.enc(first) : "";
}

async function approve(req) {
  status("Waiting for your passkey…");
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: b64u.dec(req.challenge),
      rpId: "localhost",
      userVerification: "required",
      allowCredentials: req.allow.map((a) => ({ type: "public-key", id: b64u.dec(a.id) })),
      extensions: { prf: { evalByCredential: Object.fromEntries(req.allow.map((a) => [a.id, { first: b64u.dec(a.salt) }])) } },
      timeout: 60000,
    },
  });
  await post("/api/decide", {
    id: req.id, approve: true,
    credential_id: b64u.enc(cred.rawId),
    client_data: b64u.enc(cred.response.clientDataJSON),
    authenticator_data: b64u.enc(cred.response.authenticatorData),
    signature: b64u.enc(cred.response.signature),
    prf: prfOutput(cred),
  });
  status("Approved.");
}

async function deny(req) {
  await post("/api/decide", { id: req.id, approve: false });
  status("Denied.");
}

async function refresh() {
  const r = await fetch("/api/pending");
  const list = await r.json();
  const box = document.getElementById("pending");
  box.replaceChildren();
  if (list.length === 0) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "Nothing is waiting for approval.";
    box.append(p);
  }
  for (const req of list) {
    const div = document.createElement("div");
    div.className = "req";
    const pre = document.createElement("pre");
    pre.textContent = req.display;
    const yes = document.createElement("button");
    yes.className = "approve";
    yes.textContent = "Approve with passkey";
    yes.onclick = () => approve(req).then(refresh).catch((e) => status("Not approved: " + e.message));
    const no = document.createElement("button");
    no.textContent = "Deny";
    no.onclick = () => deny(req).then(refresh).catch((e) => status(e.message));
    div.append(pre, yes, " ", no);
    box.append(div);
  }
}

async function enroll(token) {
  const opts = await (await fetch("/api/enroll?t=" + encodeURIComponent(token))).json();
  if (opts.error) throw new Error(opts.error);
  status("Create the passkey on your phone or security key…");
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: b64u.dec(opts.challenge),
      rp: { id: "localhost", name: "Vogt" },
      user: { id: b64u.dec(opts.user_id), name: "vogt", displayName: "Vogt approvals" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }],
      authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
      attestation: "none",
      extensions: { prf: { eval: { first: b64u.dec(opts.prf_salt) } } },
      timeout: 120000,
    },
  });
  let prf = prfOutput(cred);
  if (!prf) {
    // Some authenticators only evaluate PRF during get().
    status("Confirm once more so the passkey can protect your secrets…");
    const again = await navigator.credentials.get({
      publicKey: {
        challenge: b64u.dec(opts.challenge),
        rpId: "localhost",
        userVerification: "required",
        allowCredentials: [{ type: "public-key", id: cred.rawId }],
        extensions: { prf: { eval: { first: b64u.dec(opts.prf_salt) } } },
      },
    });
    prf = prfOutput(again);
  }
  if (!prf) throw new Error("this authenticator does not support the PRF extension");
  await post("/api/enroll", {
    t: token,
    name: document.getElementById("enroll-name").value,
    client_data: b64u.enc(cred.response.clientDataJSON),
    authenticator_data: b64u.enc(cred.response.getAuthenticatorData()),
    public_key: b64u.enc(cred.response.getPublicKey()),
    alg: cred.response.getPublicKeyAlgorithm(),
    prf,
  });
  status("Passkey added. You can close this page.");
}

document.addEventListener("DOMContentLoaded", () => {
  const token = new URLSearchParams(location.hash.slice(1)).get("t");
  if (token) {
    document.getElementById("enroll").hidden = false;
    document.getElementById("enroll-go").onclick = () => enroll(token).catch((e) => status("Failed: " + e.message));
    return;
  }
  refresh();
  setInterval(refresh, 3000);
});
