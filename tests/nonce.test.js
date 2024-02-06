import { generateNonce, getDirectives } from "../index.js";

describe("generateNonce", () => {
  it("should generate a nonce", () => {
    const nonce = generateNonce();

    expect(nonce).toMatch(/^[0-9a-f]+$/i);
  });

  it("should generate different nonces for different runs", () => {
    const nonce1 = generateNonce();
    const nonce2 = generateNonce();

    expect(nonce1).not.toBe(nonce2);
  });
});

describe("getDirectives", () => {
  it("should return the directives for CSP when no options are provided", () => {
    const directives = getDirectives("test-nonce");

    expect(directives).toEqual({
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "test-nonce"],
      styleSrc: ["'self'", "test-nonce"],
      fontSrc: ["'self'"],
      connectSrc: ["'self'"],
      frameSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      reportUri: [],
      requireTrustedTypesFor: [],
    });
  });

  it("should return directions with custom options", () => {
    const options = {
      scripts: ["script1.com", "script2.com"],
      styles: ["style1.com", "style2.com"],
      fonts: ["font1.com", "font2.com"],
      connect: ["connect1.com", "connect2.com"],
      frame: ["frame1.com", "frame2.com"],
      reportTo: ["report1.com", "report2.com"],
    };

    const directives = getDirectives("test-nonce", options);

    expect(directives).toEqual({
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "test-nonce", "script1.com", "script2.com"],
      styleSrc: ["'self'", "test-nonce", "style1.com", "style2.com"],
      fontSrc: ["'self'", "font1.com", "font2.com"],
      connectSrc: ["'self'", "connect1.com", "connect2.com"],
      frameSrc: ["'self'", "frame1.com", "frame2.com"],
      objectSrc: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      reportUri: ["report1.com", "report2.com"],
      requireTrustedTypesFor: [],
    });
  });
});
