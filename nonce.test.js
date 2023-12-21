import { generateNonce, getDirectives } from "./index.js";
import { v4 as uuidv4 } from "uuid";

jest.mock("uuid", () => ({
  v4: jest.fn(),
}));

describe("generateNonce", () => {
  beforeEach(() => {
    uuidv4.mockReset();
  });

  it("should generate a nonce using uuid.v4", () => {
    const mockedNonce = "0827173965164027ae518b98122bf079";
    uuidv4.mockReturnValueOnce(mockedNonce);

    const nonce = generateNonce();

    expect(uuidv4).toHaveBeenCalled();
    expect(nonce).toBe(mockedNonce);
  });

  it("should generate different nonces for different runs", () => {
    // Mock uuid.v4 to return two different values
    const mockedUuid1 = "0827173965164027ae518b98122bf079";
    const mockedUuid2 = "0827173965164027ae518b98122bf080";
    uuidv4.mockReturnValueOnce(mockedUuid1).mockReturnValueOnce(mockedUuid2);

    // Call the generateNonce function twice
    const nonce1 = generateNonce();
    const nonce2 = generateNonce();

    // Check that uuid.v4 was called twice
    expect(uuidv4).toHaveBeenCalledTimes(2);

    // Check that the generated nonces are different
    expect(nonce1).toBe(mockedUuid1);
    expect(nonce2).toBe(mockedUuid2);

    // If you want to ensure they are not equal, you can use:
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
    });
  });
});
