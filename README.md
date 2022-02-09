## KindTap Platform Library for NodeJS

#### This library currently supports generating a signed authorization header which is required to make requests to KindTap Platform APIs.

### Installation

`npm i --save https://github.com/KindTap/kindtap-platform-node.git#0.1.2`

### Example using node-fetch

#### Note that the `host` and `x-kt-date` headers are required.

```JavaScript
import fetch from "node-fetch";
import { generateSignedAuthHeader, stringifyDate } from "kindtap-platform-node";

const host = 'kindtap-platform-host';
const path = '/path/to/api/endpoint/';
const query = { key1: 'value1', key2: 1 };
const querystring = new URLSearchParams(query);
const date = new Date();

const request = {
  method: 'post',
  body: JSON.stringify({
    someKey: 'someValue',
  }),
  headers: {
    'Content-Type': 'application/json',
    'Host': host,
    'X-KT-Date': stringifyDate(date),
  },
};

request.headers['Authorization'] = generateSignedAuthHeader(
  'kindtap-platform-service-name',
  'kindtap-client-key',
  'kindtap-client-secret',
  request.method,
  path,
  date,
  request.headers,
  request.body,
  query,
);

fetch(
  `https://${host}${path}?${querystring}`, request,
).then((response) => {
  response.json().then((content) => {
    console.log(
      `https://${host}${path}?${querystring} ${response.status}`, {
        request,
        response,
        content,
      },
    );
  })
});
```

### Valid signature will allow request

```
https://kindtap-platform-host/path/to/api/endpoint/?key1=value1&key2=1 200 {
  request: {
    method: 'post',
    body: '{"someKey":"someValue"}',
    headers: {
      'Content-Type': 'application/json',
      Host: 'kindtap-platform-host',
      'X-KT-Date': '20220209T212523Z',
      Authorization: 'KT1-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...'
    }
  },
  response: Response {
    ...
    [Symbol(Response internals)]: {
      ...
      status: 200,
      statusText: 'OK',
      ...
    }
  },
  content: { ... }
}
```

### Invalid signature will block request

```
https://kindtap-platform-host/path/to/api/endpoint/?key1=value1&key2=1 401 {
  request: {
    method: 'post',
    body: '{"someKey":"someValue"}',
    headers: {
      'Content-Type': 'application/json',
      Host: 'kindtap-platform-host',
      'X-KT-Date': '20220209T212523Z',
      Authorization: 'KT1-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...'
    }
  },
  response: Response {
    ...
    [Symbol(Response internals)]: {
      ...
      status: 401,
      statusText: 'Unauthorized',
      ...
    }
  },
  content: { error: 'Unauthorized.' }
}
```
