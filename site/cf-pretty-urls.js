// CloudFront Function (viewer-request event) that gives us pretty URLs
// on top of the S3-backed static site.
//
//   /why-esig            -> /why-esig/index.html
//   /why-esig/           -> /why-esig/index.html
//   /why-esig/index.html -> unchanged
//   /assets/pic.png    -> unchanged (has extension)
//
// Runtime: cloudfront-js-2.0
// Association: default cache behavior, viewer-request event.

function handler(event) {
    var request = event.request;
    var uri = request.uri;

    // Preserve old bookmarks while keeping e-sig as the only visible brand.
    if (uri === '/why-vmv' || uri === '/why-vmv/' || uri === '/why-vmv/index.html') {
        return {
            statusCode: 301,
            statusDescription: 'Moved Permanently',
            headers: { location: { value: '/why-esig' } }
        };
    }

    // Deployment helpers are not public site content. Some were uploaded by
    // an older deploy path, so block them at the edge until the bucket is
    // deliberately pruned under a separate recovery-aware operation.
    if (uri === '/README.md' || uri === '/deploy.sh' || uri === '/finish.sh' || uri === '/cf-pretty-urls.js') {
        return {
            statusCode: 404,
            statusDescription: 'Not Found',
            headers: { 'cache-control': { value: 'no-store' } }
        };
    }

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
