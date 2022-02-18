import Crypto from 'crypto-js';

const ALGO_PRE = 'KT1'
const ALGO = `${ALGO_PRE}-HMAC-SHA256`
const AUTH_TYPE = `${ALGO_PRE.toLowerCase()}_request`
const REGION = 'us';

const EQUALS_EXPR = /=/g;
const EQUALS_ENC = encodeURIComponent('=');
const MULTI_WS_EXPR = /[ ][ ]+/g;
const SLASH_EXPR = /\//;

const hmacSHA256 = (str, key) => Crypto.HmacSHA256(str, key, {asBytes: true});
const sha256 = (str) => Crypto.SHA256(str, {asBytes: true});

const leftPad = (base, pad='0', count=2) => {
  const thePad = Array.from({ length: count }, () => pad).join('');
  return `${thePad}${base}`.slice(-count);
};

const sortByCodePoint = (a, b) => {
  const aCode = (Array.isArray(a) ? a[0] : a).charCodeAt(0);
  const bCode = (Array.isArray(b) ? b[0] : b).charCodeAt(0);
  if (aCode < bCode) return -1;
  if (bCode > aCode) return 1;
  return 0;
};

export const stringifyDate = (date, full=true) => {
  const Y = date.getUTCFullYear();
  const m = leftPad(date.getUTCMonth() + 1);
  const d = leftPad(date.getUTCDate());
  if (!full) return `${Y}${m}${d}`;
  const H = leftPad(date.getUTCHours());
  const M = leftPad(date.getUTCMinutes());
  const S = leftPad(date.getUTCSeconds());
  return `${Y}${m}${d}T${H}${M}${S}Z`;
};

export const stringifyUTCDate = (date, full=true) => {
  const Y = date.getFullYear();
  const m = leftPad(date.getMonth() + 1);
  const d = leftPad(date.getDate());
  if (!full) return `${Y}${m}${d}`;
  const H = leftPad(date.getHours());
  const M = leftPad(date.getMinutes());
  const S = leftPad(date.getSeconds());
  return `${Y}${m}${d}T${H}${M}${S}Z`;
};

const _buildCanonHeaders = (headers) => {
  const h_pre = Object.keys(headers).map((k) => [ k.toLowerCase(), `${headers[k]}`.trim() ]);
  h_pre.sort(sortByCodePoint);
  return h_pre.map(
    (h) => `${h[0]}:${h[1].replace(MULTI_WS_EXPR, ' ')}`
  ).join('\n') + '\n';
};

const _buildCanonQuery = (params) => {
  const p_pre = Object.keys(params).map((k) => [ k, params[k] ]);
  p_pre.sort(sortByCodePoint);
  return p_pre.map((p) => {
    const p_key = encodeURIComponent(p[0]);
    const p_value = encodeURIComponent(`${p[1]}`.replace(EQUALS_EXPR, EQUALS_ENC));
    return `${p_key}=${p_value}`;
  }).join('&');
};

const _buildCanonURI = (uri) => {
  const pathParts = uri.split(SLASH_EXPR).filter((p) => !!p);
  if (pathParts.length === 0) return '/';
  return `/${pathParts.map((p) => encodeURIComponent(encodeURIComponent(p))).join('/')}/`;
};

const _buildSignedHeaders = (headers) => {
  const h_pre = Object.keys(headers).map((k) => k.toLowerCase());
  h_pre.sort(sortByCodePoint);
  return h_pre.join(';');
};

const generateSignatureV1 = (
  service,
  clientSecret,
  reqMethod,
  reqURI,
  reqDate,
  reqHeaders,
  reqBody,
  reqParams,
) => {
  const canonHeaders = _buildCanonHeaders(reqHeaders);
  const canonQuery = _buildCanonQuery(reqParams);
  const canonURI = _buildCanonURI(reqURI);
  const signedHeaders = _buildSignedHeaders(reqHeaders);

  const canonRequest = [
    reqMethod.toUpperCase(),
    canonURI,
    canonQuery,
    canonHeaders,
    signedHeaders,
    sha256(reqBody),
  ].join('\n');
  //console.log(`Canonical Request:\n${canonRequest}`);
  const canonRequestHash = sha256(canonRequest);
  //console.log(`Canonical Request Hash:${canonRequestHash}`);

  const credDate = stringifyDate(reqDate, false);
  const credScope = `${credDate}/${REGION}/${service}/${AUTH_TYPE}`;

  const msgToSign = [
    ALGO,
    stringifyDate(reqDate),
    credScope,
    canonRequestHash,
  ].join('\n');
  //console.log(`Message to Sign:\n${msgToSign}`);

  const k0 = hmacSHA256(credDate, `${ALGO_PRE}${clientSecret}`);
  const k1 = hmacSHA256(REGION, k0);
  const k2 = hmacSHA256(service, k1);
  const k3 = hmacSHA256(AUTH_TYPE, k2);

  const signature = hmacSHA256(msgToSign, k3);
  //console.log(`Signature: ${signature}`);

  return signature;
};

export const generateSignedAuthHeader = (
  service,
  clientKey,
  clientSecret,
  reqMethod,
  reqURI,
  reqDate,
  reqHeaders,
  reqBody,
  reqParams,
) => {
  const credDate = stringifyDate(reqDate, false);
  const credScope = `${credDate}/${REGION}/${service}/${AUTH_TYPE}`;

  const signedHeaders = _buildSignedHeaders(reqHeaders);

  const signature = generateSignatureV1(
    service,
    clientSecret,
    reqMethod,
    reqURI,
    reqDate,
    reqHeaders,
    reqBody,
    reqParams,
  );

  const auth = `${ALGO} Credential=${clientKey}/${credScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  //console.log(`Authorization: ${auth}`);

  return auth;
};
