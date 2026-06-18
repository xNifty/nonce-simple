declare namespace _exports {
    export { CspProfile, HashAlgorithm, DirectivesOptions, NonceMiddlewareOptions, IncomingMessage, ServerResponse, CspDirectives, HelmetDirectiveFunction, ExpressMiddleware };
}
declare namespace _exports {
    export { generateNonce };
    export { formatNonce };
    export { hashSource };
    export { getDirectives };
    export { getReportingEndpointsHeader };
    export { createNonceMiddleware };
    export { nonceDirective };
}
export = _exports;
type CspProfile = "strict" | "strict-dynamic" | "development";
type HashAlgorithm = "sha256" | "sha384" | "sha512";
type DirectivesOptions = {
    /**
     * Built-in policy preset.
     */
    profile?: CspProfile;
    /**
     * Append `'strict-dynamic'` to `script-src`.
     */
    strictDynamic?: boolean;
    /**
     * Additional `script-src` sources.
     */
    scripts?: string[];
    /**
     * Additional `style-src` sources.
     */
    styles?: string[];
    /**
     * Additional `font-src` sources.
     */
    fonts?: string[];
    /**
     * Additional `connect-src` sources.
     */
    connect?: string[];
    /**
     * Additional `frame-src` sources.
     */
    frame?: string[];
    /**
     * Additional `img-src` sources.
     */
    images?: string[];
    /**
     * Additional `worker-src` sources.
     */
    workers?: string[];
    /**
     * Additional `manifest-src` sources.
     */
    manifests?: string[];
    /**
     * Additional `media-src` sources.
     */
    media?: string[];
    /**
     * Additional `child-src` sources.
     */
    children?: string[];
    /**
     * Additional `script-src-elem` sources.
     */
    scriptElems?: string[];
    /**
     * Additional `script-src-attr` sources.
     */
    scriptAttrs?: string[];
    /**
     * Additional `style-src-elem` sources.
     */
    styleElems?: string[];
    /**
     * Additional `style-src-attr` sources.
     */
    styleAttrs?: string[];
    /**
     * `webrtc` directive values.
     */
    webrtc?: string[];
    /**
     * Trusted Types enforcement targets.
     */
    requireTrustedTypesFor?: string[];
    /**
     * Allowed Trusted Types policy names.
     */
    trustedTypes?: string[];
    /**
     * Sandbox tokens for embedded content.
     */
    sandbox?: string[];
    /**
     * Deprecated `report-uri` endpoints.
     */
    reportUri?: string[];
    /**
     * Modern `report-to` endpoint names.
     */
    reportTo?: string[];
    /**
     * Enable `upgrade-insecure-requests`.
     */
    upgradeInsecureRequests?: boolean;
    /**
     * Override `default-src`.
     */
    defaultSrc?: string;
    /**
     * Override `base-uri`.
     */
    baseUri?: string;
    /**
     * Override `form-action`.
     */
    formAction?: string;
    /**
     * Override `frame-ancestors`.
     */
    frameAncestors?: string;
    /**
     * Override `object-src`.
     */
    objectSrc?: string;
};
type NonceMiddlewareOptions = {
    /**
     * `res.locals` key for the raw nonce.
     */
    localKey?: string;
    /**
     * Secondary `res.locals` key for the raw nonce.
     */
    rawKey?: string;
    /**
     * Number of random bytes to generate.
     */
    byteLength?: number;
};
type IncomingMessage = import("http").IncomingMessage;
type ServerResponse = import("http").ServerResponse;
type CspDirectives = Record<string, string[] | boolean | null | ((req: IncomingMessage, res: ServerResponse) => string)>;
type HelmetDirectiveFunction = (req: IncomingMessage, res: ServerResponse) => string;
type ExpressMiddleware = (req: IncomingMessage, res: ServerResponse, next: (error?: Error) => void) => void;
/**
 * Generate a cryptographically secure nonce.
 * @param {number} [byteLength=16] Number of random bytes to generate.
 * @returns {string} Hex-encoded nonce value.
 */
declare function generateNonce(byteLength?: number): string;
/**
 * Format a raw nonce value for use in a CSP source list.
 * @param {string} nonce Raw or already quoted nonce value.
 * @returns {string} Quoted `'nonce-…'` source expression.
 */
declare function formatNonce(nonce: string): string;
/**
 * Create a CSP hash source expression for inline content.
 * @param {string} content Inline script or style content to hash.
 * @param {HashAlgorithm} [algorithm='sha256'] Hash algorithm to use.
 * @returns {string} Quoted hash source expression.
 */
declare function hashSource(content: string, algorithm?: HashAlgorithm): string;
/**
 * Build a Helmet-compatible CSP directives object.
 * @param {string | HelmetDirectiveFunction} nonce Raw nonce, quoted nonce, or Helmet resolver.
 * @param {DirectivesOptions} [options]
 * @returns {CspDirectives}
 */
declare function getDirectives(nonce: string | HelmetDirectiveFunction, options?: DirectivesOptions): CspDirectives;
/**
 * Build a `Reporting-Endpoints` header value.
 * @param {Record<string, string>} endpoints Map of endpoint name to URL.
 * @returns {string} Header value for Express/Node `res.setHeader`.
 */
declare function getReportingEndpointsHeader(endpoints: Record<string, string>): string;
/**
 * Create Express middleware that stores a per-request nonce on `res.locals`.
 * @param {NonceMiddlewareOptions} [options]
 * @returns {ExpressMiddleware}
 */
declare function createNonceMiddleware(options?: NonceMiddlewareOptions): ExpressMiddleware;
/**
 * Create a Helmet-compatible directive resolver for the current request nonce.
 * @param {string} [localKey='cspNonce'] `res.locals` key containing the raw nonce.
 * @returns {HelmetDirectiveFunction}
 */
declare function nonceDirective(localKey?: string): HelmetDirectiveFunction;
//# sourceMappingURL=index.d.ts.map