/*
  nonce-simple

  Generate per-request nonces and build Helmet-compatible CSP directive objects.
*/

/**
 * @typedef {'strict' | 'strict-dynamic' | 'development'} CspProfile
 */

/**
 * @typedef {'sha256' | 'sha384' | 'sha512'} HashAlgorithm
 */

/**
 * @typedef {Object} DirectivesOptions
 * @property {CspProfile} [profile='strict'] Built-in policy preset.
 * @property {boolean} [strictDynamic] Append `'strict-dynamic'` to `script-src`.
 * @property {string[]} [scripts] Additional `script-src` sources.
 * @property {string[]} [styles] Additional `style-src` sources.
 * @property {string[]} [fonts] Additional `font-src` sources.
 * @property {string[]} [connect] Additional `connect-src` sources.
 * @property {string[]} [frame] Additional `frame-src` sources.
 * @property {string[]} [images] Additional `img-src` sources.
 * @property {string[]} [workers] Additional `worker-src` sources.
 * @property {string[]} [manifests] Additional `manifest-src` sources.
 * @property {string[]} [media] Additional `media-src` sources.
 * @property {string[]} [children] Additional `child-src` sources.
 * @property {string[]} [scriptElems] Additional `script-src-elem` sources.
 * @property {string[]} [scriptAttrs] Additional `script-src-attr` sources.
 * @property {string[]} [styleElems] Additional `style-src-elem` sources.
 * @property {string[]} [styleAttrs] Additional `style-src-attr` sources.
 * @property {string[]} [webrtc] `webrtc` directive values.
 * @property {string[]} [requireTrustedTypesFor] Trusted Types enforcement targets.
 * @property {string[]} [trustedTypes] Allowed Trusted Types policy names.
 * @property {string[]} [sandbox] Sandbox tokens for embedded content.
 * @property {string[]} [reportUri] Deprecated `report-uri` endpoints.
 * @property {string[]} [reportTo] Modern `report-to` endpoint names.
 * @property {boolean} [upgradeInsecureRequests] Enable `upgrade-insecure-requests`.
 * @property {string} [defaultSrc] Override `default-src`.
 * @property {string} [baseUri] Override `base-uri`.
 * @property {string} [formAction] Override `form-action`.
 * @property {string} [frameAncestors] Override `frame-ancestors`.
 * @property {string} [objectSrc] Override `object-src`.
 */

/**
 * @typedef {Object} NonceMiddlewareOptions
 * @property {string} [localKey='cspNonce'] `res.locals` key for the raw nonce.
 * @property {string} [rawKey='nonce'] Secondary `res.locals` key for the raw nonce.
 * @property {number} [byteLength] Number of random bytes to generate.
 */

/**
 * @typedef {import('http').IncomingMessage} IncomingMessage
 * @typedef {import('http').ServerResponse} ServerResponse
 */

/**
 * @typedef {Record<string, string[] | boolean | null | ((req: IncomingMessage, res: ServerResponse) => string)>} CspDirectives
 */

/**
 * @typedef {(req: IncomingMessage, res: ServerResponse) => string} HelmetDirectiveFunction
 */

/**
 * @typedef {(req: IncomingMessage, res: ServerResponse, next: (error?: Error) => void) => void} ExpressMiddleware
 */

"use strict";

var crypto = require("crypto");

var SELF = "'self'";
var NONE = "'none'";
var STRICT_DYNAMIC = "'strict-dynamic'";

var SUPPORTED_PROFILES = ["strict", "strict-dynamic", "development"];
var SUPPORTED_HASH_ALGORITHMS = ["sha256", "sha384", "sha512"];

var DEFAULT_OPTION_ARRAYS = [
  "scripts",
  "styles",
  "fonts",
  "connect",
  "frame",
  "images",
  "workers",
  "manifests",
  "media",
  "children",
  "scriptElems",
  "scriptAttrs",
  "styleElems",
  "styleAttrs",
  "webrtc",
  "requireTrustedTypesFor",
  "trustedTypes",
  "sandbox",
  "reportUri",
  "reportTo",
];

var DEVELOPMENT_CONNECT_SOURCES = [
  "ws:",
  "wss:",
  "http://localhost:*",
  "https://localhost:*",
];

module.exports = {
  generateNonce: generateNonce,
  formatNonce: formatNonce,
  hashSource: hashSource,
  getDirectives: getDirectives,
  getReportingEndpointsHeader: getReportingEndpointsHeader,
  createNonceMiddleware: createNonceMiddleware,
  nonceDirective: nonceDirective,
};

/**
 * Generate a cryptographically secure nonce.
 * @param {number} [byteLength=16] Number of random bytes to generate.
 * @returns {string} Hex-encoded nonce value.
 */
function generateNonce(byteLength) {
  var length = byteLength === undefined ? 16 : byteLength;
  return crypto.randomBytes(length).toString("hex");
}

/**
 * Format a raw nonce value for use in a CSP source list.
 * @param {string} nonce Raw or already quoted nonce value.
 * @returns {string} Quoted `'nonce-…'` source expression.
 */
function formatNonce(nonce) {
  if (nonce === undefined || nonce === null || nonce === "") {
    throw new TypeError("nonce is required");
  }

  if (nonce.charAt(0) === "'" && nonce.charAt(nonce.length - 1) === "'") {
    return nonce;
  }

  var value = String(nonce).replace(/^nonce-/, "");
  return "'nonce-" + value + "'";
}

/**
 * Create a CSP hash source expression for inline content.
 * @param {string} content Inline script or style content to hash.
 * @param {HashAlgorithm} [algorithm='sha256'] Hash algorithm to use.
 * @returns {string} Quoted hash source expression.
 */
function hashSource(content, algorithm) {
  var algo = algorithm || "sha256";

  if (SUPPORTED_HASH_ALGORITHMS.indexOf(algo) === -1) {
    throw new Error("Unsupported hash algorithm: " + algo);
  }

  if (typeof content !== "string") {
    throw new TypeError("content must be a string");
  }

  var digest = crypto.createHash(algo).update(content, "utf8").digest("base64");
  return "'" + algo + "-" + digest + "'";
}

/**
 * Build a `Reporting-Endpoints` header value.
 * @param {Record<string, string>} endpoints Map of endpoint name to URL.
 * @returns {string} Header value for Express/Node `res.setHeader`.
 */
function getReportingEndpointsHeader(endpoints) {
  if (!endpoints || typeof endpoints !== "object" || Array.isArray(endpoints)) {
    throw new TypeError("endpoints must be an object");
  }

  return Object.keys(endpoints)
    .map(function (name) {
      return name + '="' + endpoints[name] + '"';
    })
    .join(", ");
}

/**
 * Create Express middleware that stores a per-request nonce on `res.locals`.
 * @param {NonceMiddlewareOptions} [options]
 * @returns {ExpressMiddleware}
 */
function createNonceMiddleware(options) {
  options = options || {};
  var localKey = options.localKey || "cspNonce";
  var rawKey = options.rawKey || "nonce";
  var byteLength = options.byteLength;

  return function nonceMiddleware(req, res, next) {
    var nonce = generateNonce(byteLength);
    res.locals[rawKey] = nonce;
    res.locals[localKey] = nonce;
    next();
  };
}

/**
 * Create a Helmet-compatible directive resolver for the current request nonce.
 * @param {string} [localKey='cspNonce'] `res.locals` key containing the raw nonce.
 * @returns {HelmetDirectiveFunction}
 */
function nonceDirective(localKey) {
  var key = localKey || "cspNonce";

  return function resolveNonce(req, res) {
    var value = res.locals[key];

    if (value === undefined || value === null || value === "") {
      throw new Error("Missing nonce in res.locals." + key);
    }

    return formatNonce(value);
  };
}

function appendUnique(existing, additions) {
  var values = existing.slice();

  additions.forEach(function (entry) {
    if (values.indexOf(entry) === -1) {
      values.push(entry);
    }
  });

  return values;
}

function resolveProfileOptions(options) {
  options = options || {};
  var resolved = Object.assign({}, options);
  var profile = resolved.profile || "strict";

  if (SUPPORTED_PROFILES.indexOf(profile) === -1) {
    throw new Error(
      "Unknown CSP profile: " + profile + ". Expected one of: " + SUPPORTED_PROFILES.join(", ")
    );
  }

  delete resolved.profile;

  if (profile === "strict-dynamic" || resolved.strictDynamic === true) {
    resolved.scripts = appendUnique(normalizeOptionArray(resolved, "scripts"), [
      STRICT_DYNAMIC,
    ]);
    delete resolved.strictDynamic;
  }

  if (profile === "development") {
    resolved.connect = appendUnique(
      normalizeOptionArray(resolved, "connect"),
      DEVELOPMENT_CONNECT_SOURCES
    );

    if (resolved.scriptAttrs === undefined) {
      resolved.scriptAttrs = [NONE];
    }

    if (resolved.styleAttrs === undefined) {
      resolved.styleAttrs = ["'unsafe-inline'"];
    }
  }

  return resolved;
}

function normalizeOptionArray(options, key) {
  if (!options || options[key] === undefined || options[key] === null) {
    return [];
  }

  if (!Array.isArray(options[key])) {
    throw new TypeError("options." + key + " must be an array when provided");
  }

  return options[key];
}

function withSelfAndNonce(sources, nonce, includeNonce) {
  var values = [SELF];

  if (includeNonce && nonce !== undefined && nonce !== null && nonce !== "") {
    values.push(typeof nonce === "function" ? nonce : formatNonceValue(nonce));
  }

  return values.concat(sources);
}

function formatNonceValue(nonce) {
  if (typeof nonce === "function") {
    return nonce;
  }

  return formatNonce(nonce);
}

function assignFetchDirective(
  directives,
  key,
  sources,
  nonce,
  includeNonce,
  alwaysInclude
) {
  if (!alwaysInclude && sources.length === 0) {
    return;
  }

  var values = [SELF];

  if (includeNonce && nonce !== undefined && nonce !== null && nonce !== "") {
    if (typeof nonce === "function") {
      values.push(nonce);
    } else {
      values.push(formatNonce(nonce));
    }
  }

  directives[key] = values.concat(sources);
}

/*
  Build a Helmet-compatible directives object for contentSecurityPolicy.
*/
/**
 * Build a Helmet-compatible CSP directives object.
 * @param {string | HelmetDirectiveFunction} nonce Raw nonce, quoted nonce, or Helmet resolver.
 * @param {DirectivesOptions} [options]
 * @returns {CspDirectives}
 */
function getDirectives(nonce, options) {
  options = resolveProfileOptions(options);

  DEFAULT_OPTION_ARRAYS.forEach(function (key) {
    if (
      options[key] !== undefined &&
      options[key] !== null &&
      !Array.isArray(options[key])
    ) {
      throw new TypeError("options." + key + " must be an array when provided");
    }
  });

  var scripts = normalizeOptionArray(options, "scripts");
  var styles = normalizeOptionArray(options, "styles");
  var fonts = normalizeOptionArray(options, "fonts");
  var connect = normalizeOptionArray(options, "connect");
  var frame = normalizeOptionArray(options, "frame");
  var images = normalizeOptionArray(options, "images");
  var workers = normalizeOptionArray(options, "workers");
  var manifests = normalizeOptionArray(options, "manifests");
  var media = normalizeOptionArray(options, "media");
  var children = normalizeOptionArray(options, "children");
  var scriptElems = normalizeOptionArray(options, "scriptElems");
  var scriptAttrs = normalizeOptionArray(options, "scriptAttrs");
  var styleElems = normalizeOptionArray(options, "styleElems");
  var styleAttrs = normalizeOptionArray(options, "styleAttrs");
  var webrtc = normalizeOptionArray(options, "webrtc");
  var requireTrustedTypesFor = normalizeOptionArray(
    options,
    "requireTrustedTypesFor"
  );
  var trustedTypes = normalizeOptionArray(options, "trustedTypes");
  var sandbox = normalizeOptionArray(options, "sandbox");
  var reportUri = normalizeOptionArray(options, "reportUri");
  var reportTo = normalizeOptionArray(options, "reportTo");

  var directives = {
    defaultSrc: [options.defaultSrc !== undefined ? options.defaultSrc : SELF],
    objectSrc: [options.objectSrc !== undefined ? options.objectSrc : NONE],
    baseUri: [options.baseUri !== undefined ? options.baseUri : NONE],
    formAction: [options.formAction !== undefined ? options.formAction : SELF],
    frameAncestors: [
      options.frameAncestors !== undefined ? options.frameAncestors : NONE,
    ],
  };

  assignFetchDirective(directives, "scriptSrc", scripts, nonce, true, true);
  assignFetchDirective(directives, "styleSrc", styles, nonce, true, true);
  assignFetchDirective(directives, "fontSrc", fonts, nonce, false, true);
  assignFetchDirective(directives, "connectSrc", connect, nonce, false, true);
  assignFetchDirective(directives, "frameSrc", frame, nonce, false, true);
  assignFetchDirective(directives, "imgSrc", images, nonce, false, true);
  assignFetchDirective(directives, "workerSrc", workers, nonce, false, false);
  assignFetchDirective(directives, "manifestSrc", manifests, nonce, false, false);
  assignFetchDirective(directives, "mediaSrc", media, nonce, false, false);
  assignFetchDirective(directives, "childSrc", children, nonce, false, false);
  assignFetchDirective(directives, "scriptSrcElem", scriptElems, nonce, true, false);
  assignFetchDirective(directives, "scriptSrcAttr", scriptAttrs, nonce, false, false);
  assignFetchDirective(directives, "styleSrcElem", styleElems, nonce, true, false);
  assignFetchDirective(directives, "styleSrcAttr", styleAttrs, nonce, false, false);

  if (webrtc.length > 0) {
    directives.webrtc = webrtc;
  }

  if (requireTrustedTypesFor.length > 0) {
    directives.requireTrustedTypesFor = requireTrustedTypesFor;
  }

  if (trustedTypes.length > 0) {
    directives.trustedTypes = trustedTypes;
  }

  if (sandbox.length > 0) {
    directives.sandbox = sandbox;
  }

  if (reportUri.length > 0) {
    directives.reportUri = reportUri;
  }

  if (reportTo.length > 0) {
    directives.reportTo = reportTo;
  }

  if (options.upgradeInsecureRequests === true) {
    directives.upgradeInsecureRequests = [];
  }

  return directives;
}
