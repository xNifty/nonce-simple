# nonce-simple

This module was originally code within my personal website, but I felt it would be better served as a package I could install into other projects easily. It is very straight forward and simple to use, as that was my intention. This was designed to be used with Helmet-CSP which at the time had no instructions for generating nonces so I made this. This is highly situational to what I wanted it to do.

## Getting Started

Simple install from NPM as normal.

```
$ npm install nonce-simple
```

## Usage

```
import {generateNonce, getDirectives} from "nonce-simple";
import csp from "helmet-csp";

// Example options
const nonceOptions = {
  scripts: [
    `https://cdnjs.cloudflare.com`,
    `https://code.jquery.com`,
    `https://maxcdn.bootstrapcdn.com`,
    `https://cdn.jsdelivr.net`,
    `https://www.google.com/recaptcha/`,
    `https://www.gstatic.com/recaptcha/`,
  ],
  styles: [
    `https://cdnjs.cloudflare.com`,
    `https://fonts.googleapis.com`,
    `https://maxcdn.bootstrapcdn.com`,
    `https://cdn.jsdelivr.net`,
  ],
  fonts: [
    `https://cdnjs.cloudflare.com`,
    `https://fonts.gstatic.com`,
    `https://maxcdn.bootstrapcdn.com`,
  ],
  connect: [`https://cdn.jsdelivr.net`],
  frame: [`https://www.google.com/recaptcha/`],
  reportTo: "https://ryanmalacina.report-uri.com/r/d/csp/enforce",
};

// Add nonce to res.locals
app.use(function (req, res, next) {
  var nonce = generateNonce();
  res.locals.nonce = nonce;
  res.locals.cspNonce = "nonce-" + nonce;
  next();
});

// Use the nonce we generated along with any options we specify.
app.use(
  csp({
    directives: getDirectives(
      (req, res) => `'${res.locals.cspNonce}'`,
      nonceOptions
    ),
  })
);
```

## Options

You can include options of different types for allowed URLs that can be loaded. Anything not provided will default to `self` and script-src and font-src will default to `self` and `nonce`.

```
scripts: [],
styles: [],
fonts: [],
connect: [],
frame: [],
reportTo: []
```

## Testing CSP

I use a Chrome plugin for checking CSP called CSP Evaluator but Google also provides a testing option [here](https://csp-evaluator.withgoogle.com/).
