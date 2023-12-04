/*
    nonce.js

    This is a piece of middleware that we can use to generate a nonce on a page load
    The nonce is regenerated on every page load so that we don't reuse nonces across different pages
*/
import { v4 } from "uuid";

/*
    Generate nonce
*/
export function generateNonce() {
  const rhyphen = /-/g;
  return v4().replace(rhyphen, ``);
}

/*
    Setup the directives for use in CSP and then return it
*/
export function getDirectives(nonce, options) {
  var self = `'self'`;
  var none = `'none'`;
  var scripts = options.scripts;
  var styles = options.styles;
  var fonts = options.fonts;
  var connect = options.connect;
  var frame = options.frame;
  var reportTo = options.reportTo;
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

export default {
  generateNonce,
  getDirectives,
};
