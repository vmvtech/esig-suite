# Vendored code license — @signpdf/placeholder-plain / @signpdf/placeholder-pdfkit010

The TypeScript sources in this directory are a faithful port of the compiled
JavaScript published as:

- `@signpdf/placeholder-plain@3.3.0` (all of `dist/`)
- `@signpdf/placeholder-pdfkit010@3.3.0` (`dist/pdfkitAddPlaceholder.js` only)

Both packages are part of the node-signpdf project
(https://github.com/vbuch/node-signpdf) by vbuch and contributors, published
under the MIT license reproduced below. They were vendored here to remove the
`@signpdf/placeholder-pdfkit010 -> pdfkit@0.10.0 (peer) -> crypto-js@3.3.0`
dependency chain; no logic was changed — only TypeScript types were added.
`@signpdf/utils` and `@signpdf/signpdf` remain regular dependencies and are
still imported by this vendored code.

---

MIT License

Copyright (c) 2019 The Authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
