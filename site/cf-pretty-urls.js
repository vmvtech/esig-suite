// CloudFront Function (viewer-request event) that gives us pretty URLs
// on top of the S3-backed static site.
//
//   /why-vmv           -> /why-vmv/index.html
//   /why-vmv/          -> /why-vmv/index.html
//   /why-vmv/index.html -> unchanged
//   /assets/pic.png    -> unchanged (has extension)
//
// Runtime: cloudfront-js-2.0
// Association: default cache behavior, viewer-request event.

function handler(event) {
    var request = event.request;
    var uri = request.uri;

    // If it already has an extension (.html, .css, .js, .png, etc.), leave alone.
    // We check the last path segment only so /foo.bar/baz still gets rewritten.
    var lastSlash = uri.lastIndexOf('/');
    var lastSeg = uri.slice(lastSlash + 1);
    var hasExtension = lastSeg.indexOf('.') !== -1;

    if (hasExtension) {
        return request;
    }

    if (uri.endsWith('/')) {
        request.uri = uri + 'index.html';
    } else {
        request.uri = uri + '/index.html';
    }
    return request;
}
