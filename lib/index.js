"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
Object.defineProperty(exports, "generateSignedAuthHeader", {
  enumerable: true,
  get: function get() {
    return _signatureV.generateSignedAuthHeader;
  }
});
Object.defineProperty(exports, "stringifyDate", {
  enumerable: true,
  get: function get() {
    return _signatureV.stringifyDate;
  }
});
Object.defineProperty(exports, "stringifyUTCDate", {
  enumerable: true,
  get: function get() {
    return _signatureV.stringifyUTCDate;
  }
});

var _signatureV = require("./signatureV1");