/*
  nonce-simple

  Generate per-request nonces and build Helmet-compatible CSP directive objects.
*/
"use strict";

var crypto = require("crypto");

var SELF = "'self'";
var NONE = "'none'";

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

module.exports = {
  generateNonce: generateNonce,
  getDirectives: getDirectives,
};

function generateNonce(byteLength) {
  var length = byteLength === undefined ? 16 : byteLength;
  return crypto.randomBytes(length).toString("hex");
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
    values.push(nonce);
  }

  return values.concat(sources);
}

function assignDirective(directives, key, value) {
  if (value === undefined || value === null) {
    return;
  }

  directives[key] = value;
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

  directives[key] = withSelfAndNonce(sources, nonce, includeNonce);
}

/*
  Build a Helmet-compatible directives object for contentSecurityPolicy.
*/
function getDirectives(nonce, options) {
  options = options || {};

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
