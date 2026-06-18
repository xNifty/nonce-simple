import {
  createNonceMiddleware,
  formatNonce,
  generateNonce,
  getDirectives,
  getReportingEndpointsHeader,
  hashSource,
  nonceDirective,
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

describe("formatNonce", () => {
  it("should wrap a raw nonce in single quotes", () => {
    expect(formatNonce("abc123")).toBe("'nonce-abc123'");
  });

  it("should accept an already quoted nonce", () => {
    expect(formatNonce("'nonce-abc123'")).toBe("'nonce-abc123'");
  });
});

describe("hashSource", () => {
  it("should generate a sha256 source expression", () => {
    const hash = hashSource("console.log('hi')");

    expect(hash).toMatch(/^'sha256-[A-Za-z0-9+/]+='$/);
    expect(hashSource("console.log('hi')")).toBe(hash);
  });
});

describe("getReportingEndpointsHeader", () => {
  it("should format reporting endpoints for the Reporting-Endpoints header", () => {
    expect(
      getReportingEndpointsHeader({
        csp: "https://example.com/csp-report",
        default: "https://example.com/default-report",
      })
    ).toBe(
      'csp="https://example.com/csp-report", default="https://example.com/default-report"'
    );
  });
});

describe("createNonceMiddleware and nonceDirective", () => {
  it("should attach a nonce to res.locals and resolve a Helmet directive", () => {
    const middleware = createNonceMiddleware();
    const req = {};
    const res = { locals: {} };

    middleware(req, res, () => {});

    const directive = nonceDirective()(req, res);

    expect(res.locals.nonce).toMatch(/^[0-9a-f]+$/i);
    expect(res.locals.cspNonce).toBe(res.locals.nonce);
    expect(directive).toBe(formatNonce(res.locals.nonce));
  });
});

describe("getDirectives", () => {
  it("should return secure defaults when no options are provided", () => {
    const directives = getDirectives("abc123");

    expect(directives).toEqual({
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'nonce-abc123'"],
      styleSrc: ["'self'", "'nonce-abc123'"],
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

    const directives = getDirectives("abc123", options);

    expect(directives).toEqual({
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'nonce-abc123'", "https://cdn.example.com"],
      styleSrc: ["'self'", "'nonce-abc123'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "https://api.example.com"],
      frameSrc: ["'self'", "https://www.google.com/recaptcha/"],
      imgSrc: ["'self'", "https://images.example.com"],
      workerSrc: ["'self'", "blob:"],
      manifestSrc: ["'self'", "https://cdn.example.com"],
      mediaSrc: ["'self'", "https://media.example.com"],
      childSrc: ["'self'", "https://child.example.com"],
      scriptSrcElem: ["'self'", "'nonce-abc123'", "'strict-dynamic'"],
      scriptSrcAttr: ["'self'", "'none'"],
      styleSrcElem: ["'self'", "'nonce-abc123'", "'unsafe-inline'"],
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

  it("should apply the strict-dynamic profile", () => {
    const directives = getDirectives("abc123", { profile: "strict-dynamic" });

    expect(directives.scriptSrc).toEqual([
      "'self'",
      "'nonce-abc123'",
      "'strict-dynamic'",
    ]);
  });

  it("should apply the development profile", () => {
    const directives = getDirectives("abc123", { profile: "development" });

    expect(directives.connectSrc).toEqual([
      "'self'",
      "ws:",
      "wss:",
      "http://localhost:*",
      "https://localhost:*",
    ]);
    expect(directives.scriptSrcAttr).toEqual(["'self'", "'none'"]);
    expect(directives.styleSrcAttr).toEqual(["'self'", "'unsafe-inline'"]);
  });

  it("should reject non-array option values", () => {
    expect(() => getDirectives("abc123", { scripts: "bad" })).toThrow(
      "options.scripts must be an array when provided"
    );
  });
});
