/*
    nonce.js

    This is a piece of middleware that we can use to generate a nonce on a page load
    The nonce is regenerated on every page load so that we don't reuse nonces across different pages
*/
"use strict";
var crypto = require("crypto");

module.exports.generateNonce = generateNonce;
module.exports.getDirectives = getDirectives;

/*
    Generate nonce
*/
function generateNonce() {
  return crypto.randomBytes(16).toString("hex");
}

/*
    Setup the directives for use in CSP and then return it
*/
function getDirectives(nonce, options = {}) {
  var self = `'self'`;
  var none = `'none'`;
  var scripts = options.scripts ? options.scripts : [];
  var styles = options.styles ? options.styles : [];
  var fonts = options.fonts ? options.fonts : [];
  var connect = options.connect ? options.connect : [];
  var frame = options.frame ? options.frame : [];
  var reportTo = options.reportTo ? options.reportTo : [];
  return {
    defaultSrc: [self],
    scriptSrc: [self, nonce, ...scripts],
    styleSrc: [self, nonce, ...styles],
    fontSrc: [self, ...fonts],
    connectSrc: [self, ...connect],
    frameSrc: [self, ...frame],
    objectSrc: [none],
    baseUri: [none],
    formAction: [self],
    frameAncestors: [none],
    reportUri: reportTo,
  };
}
