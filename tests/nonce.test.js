import {
  generateNonce,
  getDirectives,
} from "../index.js";

describe("generateNonce", () => {
  it("should generate a hex nonce", () => {
    const nonce = generateNonce();

    expect(nonce).toMatch(/^[0-9a-f]+$/i);
    expect(nonce).toHaveLength(32);
  });

  it("should generate different nonces for different runs", () => {
    const nonce1 = generateNonce();
    const nonce2 = generateNonce();

    expect(nonce1).not.toBe(nonce2);
  });

  it("should support a custom byte length", () => {
    const nonce = generateNonce(8);

    expect(nonce).toHaveLength(16);
  });
});

describe("getDirectives", () => {
  it("should return secure defaults when no options are provided", () => {
    const directives = getDirectives("test-nonce");

    expect(directives).toEqual({
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "test-nonce"],
      styleSrc: ["'self'", "test-nonce"],
      fontSrc: ["'self'"],
      connectSrc: ["'self'"],
      frameSrc: ["'self'"],
      imgSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
    });
  });

  it("should return directives with custom source lists", () => {
    const options = {
      scripts: ["https://cdn.example.com"],
      styles: ["https://fonts.googleapis.com"],
      fonts: ["https://fonts.gstatic.com"],
      connect: ["https://api.example.com"],
      frame: ["https://www.google.com/recaptcha/"],
      images: ["https://images.example.com"],
      workers: ["blob:"],
      manifests: ["https://cdn.example.com"],
      media: ["https://media.example.com"],
      children: ["https://child.example.com"],
      scriptElems: ["'strict-dynamic'"],
      scriptAttrs: ["'none'"],
      styleElems: ["'unsafe-inline'"],
      styleAttrs: ["'unsafe-hashes'"],
      webrtc: ["'self'"],
      trustedTypes: ["default"],
      requireTrustedTypesFor: ["'script'"],
      sandbox: ["allow-forms", "allow-scripts"],
      reportUri: ["https://legacy.example.com/report"],
      reportTo: ["csp-endpoint"],
      upgradeInsecureRequests: true,
    };

    const directives = getDirectives("test-nonce", options);

    expect(directives).toEqual({
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "test-nonce", "https://cdn.example.com"],
      styleSrc: ["'self'", "test-nonce", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "https://api.example.com"],
      frameSrc: ["'self'", "https://www.google.com/recaptcha/"],
      imgSrc: ["'self'", "https://images.example.com"],
      workerSrc: ["'self'", "blob:"],
      manifestSrc: ["'self'", "https://cdn.example.com"],
      mediaSrc: ["'self'", "https://media.example.com"],
      childSrc: ["'self'", "https://child.example.com"],
      scriptSrcElem: ["'self'", "test-nonce", "'strict-dynamic'"],
      scriptSrcAttr: ["'self'", "'none'"],
      styleSrcElem: ["'self'", "test-nonce", "'unsafe-inline'"],
      styleSrcAttr: ["'self'", "'unsafe-hashes'"],
      webrtc: ["'self'"],
      trustedTypes: ["default"],
      requireTrustedTypesFor: ["'script'"],
      sandbox: ["allow-forms", "allow-scripts"],
      reportUri: ["https://legacy.example.com/report"],
      reportTo: ["csp-endpoint"],
      objectSrc: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    });
  });

  it("should reject non-array option values", () => {
    expect(() => getDirectives("test-nonce", { scripts: "bad" })).toThrow(
      "options.scripts must be an array when provided"
    );
  });
});
