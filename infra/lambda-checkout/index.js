// Lambda@Edge — /api/checkout
//
// Paid checkout is deliberately disabled until Cloud provisioning works end to
// end. Keep the edge route in place so old bookmarks and cached pricing links
// fail closed into the waitlist instead of creating a Stripe subscription.

'use strict';

const WAITLIST_URL = 'https://e-sig.org/pricing?waitlist=1#cloud-waitlist';

exports.handler = async () => ({
  status: '302',
  statusDescription: 'Found',
  headers: {
    location: [{ key: 'Location', value: WAITLIST_URL }],
    'cache-control': [{ key: 'Cache-Control', value: 'no-store' }],
  },
});
