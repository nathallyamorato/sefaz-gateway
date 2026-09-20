// Gateway da SEFAZ. Existe porque a SEFAZ autentica o certificado do cliente por
// renegociação TLS, que as funções de backend do Lovable (Deno/rustls) e os
// Workers da Cloudflare não suportam — o Node (OpenSSL) suporta.
//
// Stateless: recebe o pedido SOAP + certificado (PEM) do backend, repassa à SEFAZ
// e devolve a resposta. Nada é gravado nem registrado em log.
//
// Variáveis de ambiente:
//   GATEWAY_SECRET  senha que o backend envia em "Authorization: Bearer ..." (mín. 24 caracteres)
//   PORT            porta HTTP (padrão 8080)
import crypto from "node:crypto";
import http from "node:http";
import https from "node:https";

const SECRET = process.env.GATEWAY_SECRET ?? "";
const PORT = Number(process.env.PORT ?? 8080);

if (SECRET.length < 24) {
  console.error("Defina GATEWAY_SECRET com pelo menos 24 caracteres.");
  process.exit(1);
}

// Só os serviços da NF-e no Ambiente Nacional; qualquer outro destino é recusado.
const ALLOWED_HOSTS = new Set([
  "www1.nfe.fazenda.gov.br",
  "www.nfe.fazenda.gov.br",
  "hom1.nfe.fazenda.gov.br",
  "hom.nfe.fazenda.gov.br",
]);
const MAX_REQUEST_BYTES = 1_000_000;
const MAX_RESPONSE_BYTES = 20_000_000;
const UPSTREAM_TIMEOUT_MS = 45_000;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const digest = (s) => crypto.createHash("sha256").update(s).digest();

function authorized(header) {
  const m = /^Bearer (.+)$/.exec(header ?? "");
  return !!m && crypto.timingSafeEqual(digest(m[1]), digest(SECRET));
}

function send(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json", Connection: "close" });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooBig = false;
    req.on("data", (c) => {
      if (tooBig) return;
      size += c.length;
      if (size > MAX_REQUEST_BYTES) {
        tooBig = true;
        chunks.length = 0;
        reject(new HttpError(413, "Pedido grande demais"));
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function parseTarget(rawUrl) {
  let u;
  try {
    u = new URL(String(rawUrl));
  } catch {
    throw new HttpError(400, "URL inválida");
  }
  if (u.protocol !== "https:" || !ALLOWED_HOSTS.has(u.hostname) || (u.port && u.port !== "443")) {
    throw new HttpError(400, "Destino não permitido");
  }
  if (!u.pathname.startsWith("/NFe")) throw new HttpError(400, "Serviço não permitido");
  return u;
}

function callSefaz({ url, contentType, body, certPem, keyPem }) {
  const u = parseTarget(url);
  return new Promise((resolve, reject) => {
    let req;
    try {
      req = https.request(
        {
          host: u.hostname,
          port: 443,
          path: u.pathname,
          method: "POST",
          agent: false,
          minVersion: "TLSv1.2",
          cert: certPem,
          key: keyPem,
          timeout: UPSTREAM_TIMEOUT_MS,
          headers: { "Content-Type": contentType, "Content-Length": Buffer.byteLength(body) },
        },
        (res) => {
          const chunks = [];
          let size = 0;
          res.on("data", (c) => {
            size += c.length;
            if (size > MAX_RESPONSE_BYTES) {
              req.destroy(new Error("Resposta da SEFAZ grande demais"));
              return;
            }
            chunks.push(c);
          });
          res.on("end", () => resolve({ status: res.statusCode ?? 502, body: Buffer.concat(chunks).toString("utf8") }));
        },
      );
    } catch {
      reject(new HttpError(400, "Certificado ou chave inválidos"));
      return;
    }
    req.on("timeout", () => req.destroy(new Error("Tempo esgotado aguardando a SEFAZ")));
    req.on("error", (e) => reject(new HttpError(502, `Falha ao conectar na SEFAZ: ${e.message}`)));
    req.write(body);
    req.end();
  });
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/health") return send(res, 200, { ok: true });
    if (req.method !== "POST" || req.url !== "/sefaz") return send(res, 404, { error: "Não encontrado" });
    if (!authorized(req.headers.authorization)) return send(res, 401,  { error: "Senha do gateway incorreta" });

    let payload;
    try {
      payload = JSON.parse(await readBody(req));
    } catch (e) {
      if (e instanceof HttpError) throw e;
      throw new HttpError(400, "JSON inválido");
    }

    const { url, content_type: contentType, body, cert_pem: certPem, key_pem: keyPem } = payload ?? {};
    if (![url, contentType, body, certPem, keyPem].every((v) => typeof v === "string" && v)) {
      throw new HttpError(400, "Campos obrigatórios ausentes");
    }
    if (!/^application\/soap\+xml[^\r\n]{0,250}$/.test(contentType)) {
      throw new HttpError(400, "Content-Type não permitido");
    }
    if (!certPem.includes("BEGIN CERTIFICATE") || !keyPem.includes("PRIVATE KEY")) {
      throw new HttpError(400, "Certificado ou chave inválidos");
    }

    send(res, 200, await callSefaz({ url, contentType, body, certPem, keyPem }));
  } catch (e) {
    send(res, e instanceof HttpError ? e.status : 500, { error: e instanceof Error ? e.message : "Erro interno" });
  }
});

server.listen(PORT, () => console.log(`Gateway da SEFAZ ouvindo na porta ${PORT}`));
