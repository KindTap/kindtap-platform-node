"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.stringifyUTCDate = exports.stringifyDate = exports.generateSignedAuthHeader = void 0;

var _cryptoJs = _interopRequireDefault(require("crypto-js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { "default": obj }; }

var ALGO_PRE = 'KT1';
var ALGO = "".concat(ALGO_PRE, "-HMAC-SHA256");
var AUTH_TYPE = "".concat(ALGO_PRE.toLowerCase(), "_request");
var REGION = 'us';
var EQUALS_EXPR = /=/g;
var EQUALS_ENC = encodeURIComponent('=');
var MULTI_WS_EXPR = /[ ][ ]+/g;
var SLASH_EXPR = /\//;

var hmacSHA256 = function hmacSHA256(str, key) {
  return _cryptoJs["default"].HmacSHA256(str, key, {
    asBytes: true
  });
};

var sha256 = function sha256(str) {
  return _cryptoJs["default"].SHA256(str, {
    asBytes: true
  });
};

var leftPad = function leftPad(base) {
  var pad = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '0';
  var count = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 2;
  var thePad = Array.from({
    length: count
  }, function () {
    return pad;
  }).join('');
  return "".concat(thePad).concat(base).slice(-count);
};

var sortByCodePoint = function sortByCodePoint(a, b) {
  var aCode = (Array.isArray(a) ? a[0] : a).charCodeAt(0);
  var bCode = (Array.isArray(b) ? b[0] : b).charCodeAt(0);
  if (aCode < bCode) return -1;
  if (bCode > aCode) return 1;
  return 0;
};

var stringifyDate = function stringifyDate(date) {
  var full = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
  var Y = date.getUTCFullYear();
  var m = leftPad(date.getUTCMonth() + 1);
  var d = leftPad(date.getUTCDate());
  if (!full) return "".concat(Y).concat(m).concat(d);
  var H = leftPad(date.getUTCHours());
  var M = leftPad(date.getUTCMinutes());
  var S = leftPad(date.getUTCSeconds());
  return "".concat(Y).concat(m).concat(d, "T").concat(H).concat(M).concat(S, "Z");
};

exports.stringifyDate = stringifyDate;

var stringifyUTCDate = function stringifyUTCDate(date) {
  var full = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
  var Y = date.getFullYear();
  var m = leftPad(date.getMonth() + 1);
  var d = leftPad(date.getDate());
  if (!full) return "".concat(Y).concat(m).concat(d);
  var H = leftPad(date.getHours());
  var M = leftPad(date.getMinutes());
  var S = leftPad(date.getSeconds());
  return "".concat(Y).concat(m).concat(d, "T").concat(H).concat(M).concat(S, "Z");
};

exports.stringifyUTCDate = stringifyUTCDate;

var _buildCanonHeaders = function _buildCanonHeaders(headers) {
  var h_pre = Object.keys(headers).map(function (k) {
    return [k.toLowerCase(), "".concat(headers[k]).trim()];
  });
  h_pre.sort(sortByCodePoint);
  return h_pre.map(function (h) {
    return "".concat(h[0], ":").concat(h[1].replace(MULTI_WS_EXPR, ' '));
  }).join('\n') + '\n';
};

var _buildCanonQuery = function _buildCanonQuery(params) {
  var p_pre = Object.keys(params).map(function (k) {
    return [k, params[k]];
  });
  p_pre.sort(sortByCodePoint);
  return p_pre.map(function (p) {
    var p_key = encodeURIComponent(p[0]);
    var p_value = encodeURIComponent("".concat(p[1]).replace(EQUALS_EXPR, EQUALS_ENC));
    return "".concat(p_key, "=").concat(p_value);
  }).join('&');
};

var _buildCanonURI = function _buildCanonURI(uri) {
  var pathParts = uri.split(SLASH_EXPR).filter(function (p) {
    return !!p;
  });
  if (pathParts.length === 0) return '/';
  return "/".concat(pathParts.map(function (p) {
    return encodeURIComponent(encodeURIComponent(p));
  }).join('/'), "/");
};

var _buildSignedHeaders = function _buildSignedHeaders(headers) {
  var h_pre = Object.keys(headers).map(function (k) {
    return k.toLowerCase();
  });
  h_pre.sort(sortByCodePoint);
  return h_pre.join(';');
};

var generateSignatureV1 = function generateSignatureV1(service, clientSecret, reqMethod, reqURI, reqDate, reqHeaders, reqBody, reqParams) {
  var canonHeaders = _buildCanonHeaders(reqHeaders);

  var canonQuery = _buildCanonQuery(reqParams);

  var canonURI = _buildCanonURI(reqURI);

  var signedHeaders = _buildSignedHeaders(reqHeaders);

  var canonRequest = [reqMethod.toUpperCase(), canonURI, canonQuery, canonHeaders, signedHeaders, sha256(reqBody)].join('\n'); //console.log(`Canonical Request:\n${canonRequest}`);

  var canonRequestHash = sha256(canonRequest); //console.log(`Canonical Request Hash:${canonRequestHash}`);

  var credDate = stringifyDate(reqDate, false);
  var credScope = "".concat(credDate, "/").concat(REGION, "/").concat(service, "/").concat(AUTH_TYPE);
  var msgToSign = [ALGO, stringifyDate(reqDate), credScope, canonRequestHash].join('\n'); //console.log(`Message to Sign:\n${msgToSign}`);

  var k0 = hmacSHA256(credDate, "".concat(ALGO_PRE).concat(clientSecret));
  var k1 = hmacSHA256(REGION, k0);
  var k2 = hmacSHA256(service, k1);
  var k3 = hmacSHA256(AUTH_TYPE, k2);
  var signature = hmacSHA256(msgToSign, k3); //console.log(`Signature: ${signature}`);

  return signature;
};

var generateSignedAuthHeader = function generateSignedAuthHeader(service, clientKey, clientSecret, reqMethod, reqURI, reqDate, reqHeaders, reqBody, reqParams) {
  var credDate = stringifyDate(reqDate, false);
  var credScope = "".concat(credDate, "/").concat(REGION, "/").concat(service, "/").concat(AUTH_TYPE);

  var signedHeaders = _buildSignedHeaders(reqHeaders);

  var signature = generateSignatureV1(service, clientSecret, reqMethod, reqURI, reqDate, reqHeaders, reqBody, reqParams);
  var auth = "".concat(ALGO, " Credential=").concat(clientKey, "/").concat(credScope, ", SignedHeaders=").concat(signedHeaders, ", Signature=").concat(signature); //console.log(`Authorization: ${auth}`);

  return auth;
};

exports.generateSignedAuthHeader = generateSignedAuthHeader;