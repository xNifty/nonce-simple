# nonce-simple

> **Preview branch:** This branch contains the full **2.0.0** breaking-change release for local testing. It is not yet on `main`. Install from GitHub with:
>
> ```bash
> npm install github:xNifty/nonce-simple#cursor/v2-0-0-breaking-preview-fed1
> ```
>
> See [CHANGELOG.md](./CHANGELOG.md) for breaking changes before upgrading from 1.x.

Generate per-request nonces and build modern [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) directive objects for [Helmet](https://helmetjs.github.io/).

`nonce-simple` focuses on two jobs:

1. Create a fresh cryptographic nonce on every request.
2. Turn that nonce plus your allowlists into a Helmet-compatible `directives` object.

It is intentionally small, but version 2 adds coverage for modern CSP directives, policy presets, reporting helpers, and TypeScript types.

## Install

```bash
npm install nonce-simple helmet
```

Requires Node.js 18 or newer.

## Quick start

```javascript
const express = require("express");
const helmet = require("helmet");
const {
  createNonceMiddleware,
  getDirectives,
  nonceDirective,
} = require("nonce-simple");

const app = express();

app.use(createNonceMiddleware());

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: getDirectives(nonceDirective(), {
        scripts: ["https://cdn.jsdelivr.net"],
        styles: ["https://fonts.googleapis.com"],
        fonts: ["https://fonts.gstatic.com"],
      }),
    },
  })
);

app.get("/", (req, res) => {
  res.send(`<script nonce="${res.locals.cspNonce}">console.log("allowed")</script>`);
});
```

Important details:

- Use the **raw** nonce value from `res.locals.cspNonce` or `res.locals.nonce` in your HTML `nonce` attribute.
- Pass `nonceDirective()` to `getDirectives()` so Helmet receives a quoted `'nonce-…'` source expression per request.

## Helmet integration

Helmet accepts camelCase directive names and per-request resolver functions. `getDirectives()` returns an object you can pass directly to `helmet({ contentSecurityPolicy: { directives } })`.

### Recommended production setup

```javascript
const helmet = require("helmet");
const {
  createNonceMiddleware,
  getDirectives,
  getReportingEndpointsHeader,
  nonceDirective,
} = require("nonce-simple");

const cspOptions = {
  profile: "strict-dynamic",
  connect: ["https://api.example.com"],
  frame: ["https://www.google.com/recaptcha/"],
  reportTo: ["csp-endpoint"],
};

app.use(createNonceMiddleware());

app.use((req, res, next) => {
  res.setHeader(
    "Reporting-Endpoints",
    getReportingEndpointsHeader({
      "csp-endpoint": "https://reports.example.com/csp",
    })
  );
  next();
});

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: getDirectives(nonceDirective(), cspOptions),
    },
  })
);
```

### Report-only mode

Use Helmet's built-in report-only support while testing a policy:

```javascript
app.use(
  helmet({
    contentSecurityPolicy: {
      reportOnly: true,
      directives: getDirectives(nonceDirective(), {
        profile: "strict-dynamic",
        reportTo: ["csp-endpoint"],
      }),
    },
  })
);
```

### Working with Helmet defaults

Helmet merges your directives with its own defaults when `useDefaults` is `true` (the default). That means Helmet may still add values such as `script-src-attr` and `upgrade-insecure-requests` unless you override them.

If you want full control, disable Helmet defaults:

```javascript
helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: getDirectives(nonceDirective(), {
      upgradeInsecureRequests: true,
    }),
  },
});
```

## API

### `generateNonce(byteLength?)`

Returns a hex-encoded nonce. Defaults to 16 bytes (32 hex characters).

```javascript
const nonce = generateNonce();
const shorterNonce = generateNonce(8);
```

### `formatNonce(nonce)`

Converts a raw nonce into a quoted CSP source expression.

```javascript
formatNonce("abc123"); // "'nonce-abc123'"
```

### `hashSource(content, algorithm?)`

Builds a quoted CSP hash source for inline script/style content. Supports `sha256`, `sha384`, and `sha512`.

```javascript
const inlineScriptHash = hashSource("console.log('hello')");
```

### `getDirectives(nonce, options?)`

Builds the directive map for Helmet.

The first argument can be:

- a raw nonce string
- an already quoted `'nonce-…'` value
- a Helmet resolver such as `nonceDirective()`

### `createNonceMiddleware(options?)`

Express middleware that stores a nonce on `res.locals`.

| Option | Default | Description |
| --- | --- | --- |
| `localKey` | `cspNonce` | Primary locals key |
| `rawKey` | `nonce` | Secondary locals key |
| `byteLength` | `16` | Random bytes to generate |

### `nonceDirective(localKey?)`

Returns a Helmet-compatible `(req, res) => string` resolver for the current request nonce.

### `getReportingEndpointsHeader(endpoints)`

Builds a `Reporting-Endpoints` header value for use with the modern `report-to` directive.

```javascript
getReportingEndpointsHeader({
  "csp-endpoint": "https://reports.example.com/csp",
});
```

## `getDirectives()` options

### Policy presets

| Profile | Purpose |
| --- | --- |
| `strict` | Default secure baseline |
| `strict-dynamic` | Appends `'strict-dynamic'` to `script-src` for modern bundler workflows |
| `development` | Adds localhost/WebSocket `connect-src` sources and relaxed inline style attributes |

You can also set `strictDynamic: true` without using the profile.

### Source allowlists

| Option | CSP directive |
| --- | --- |
| `scripts` | `script-src` |
| `styles` | `style-src` |
| `fonts` | `font-src` |
| `connect` | `connect-src` |
| `frame` | `frame-src` |
| `images` | `img-src` |
| `workers` | `worker-src` |
| `manifests` | `manifest-src` |
| `media` | `media-src` |
| `children` | `child-src` |
| `scriptElems` | `script-src-elem` |
| `scriptAttrs` | `script-src-attr` |
| `styleElems` | `style-src-elem` |
| `styleAttrs` | `style-src-attr` |

### Other directives

| Option | CSP directive |
| --- | --- |
| `webrtc` | `webrtc` |
| `trustedTypes` | `trusted-types` |
| `requireTrustedTypesFor` | `require-trusted-types-for` |
| `sandbox` | `sandbox` |
| `reportUri` | `report-uri` (legacy) |
| `reportTo` | `report-to` (modern) |
| `upgradeInsecureRequests` | `upgrade-insecure-requests` when `true` |

### Default overrides

| Option | Default |
| --- | --- |
| `defaultSrc` | `'self'` |
| `objectSrc` | `'none'` |
| `baseUri` | `'none'` |
| `formAction` | `'self'` |
| `frameAncestors` | `'none'` |

## Default policy shape

With no options, `getDirectives()` returns a strict baseline:

```text
default-src 'self';
script-src 'self' 'nonce-…';
style-src 'self' 'nonce-…';
font-src 'self';
connect-src 'self';
frame-src 'self';
img-src 'self';
object-src 'none';
base-uri 'none';
form-action 'self';
frame-ancestors 'none';
```

Optional directives such as `worker-src`, `manifest-src`, and `report-to` are only included when you configure them.

## Examples

### Allow CDN assets

```javascript
getDirectives(nonceDirective(), {
  scripts: [
    "https://cdn.jsdelivr.net",
    "https://www.google.com/recaptcha/",
    "https://www.gstatic.com/recaptcha/",
  ],
  styles: [
    "https://fonts.googleapis.com",
    "https://cdn.jsdelivr.net",
  ],
  fonts: ["https://fonts.gstatic.com"],
  connect: ["https://cdn.jsdelivr.net"],
  frame: ["https://www.google.com/recaptcha/"],
});
```

### Trusted Types

```javascript
getDirectives(nonceDirective(), {
  trustedTypes: ["default"],
  requireTrustedTypesFor: ["'script'"],
});
```

### Split script and style controls

```javascript
getDirectives(nonceDirective(), {
  scriptElems: ["'strict-dynamic'"],
  scriptAttrs: ["'none'"],
  styleElems: ["'unsafe-inline'"],
  styleAttrs: ["'unsafe-hashes'"],
});
```

### Local development

```javascript
getDirectives(nonceDirective(), {
  profile: "development",
});
```

## Migrating from 1.x

Version 2 is a breaking release.

| 1.x | 2.x |
| --- | --- |
| `reportTo: "https://…"` mapped to `reportUri` | `reportUri` is legacy; use `reportTo: ["endpoint-name"]` plus `Reporting-Endpoints` |
| Manual nonce formatting in middleware | `createNonceMiddleware()` and `nonceDirective()` |
| Limited directive coverage | Full CSP3-style fetch/document/reporting options |
| `helmet-csp` examples | Use `helmet` with `contentSecurityPolicy` |
| Unquoted nonce strings in directives | `getDirectives()` emits quoted `'nonce-…'` values |

## Testing your policy

Validate policies before production:

- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- Browser devtools security panels
- Helmet `reportOnly: true` during rollout

## TypeScript

Type declarations are published in `dist/index.d.ts`:

```typescript
import {
  createNonceMiddleware,
  getDirectives,
  nonceDirective,
  type DirectivesOptions,
} from "nonce-simple";
```

## License

MIT
