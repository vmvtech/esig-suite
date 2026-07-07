/* e-sig.org scroll-reveal (port of RHRF's FadeIn/StaggerChildren).
   Progressive enhancement only: content is fully visible without JS.
   html.anim is added only when IntersectionObserver exists and the
   visitor has not requested reduced motion. */
(function () {
  'use strict';
  if (!('IntersectionObserver' in window)) return;
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  document.documentElement.classList.add('anim');

  // Stagger: children of [data-stagger] get an incremental delay (80ms steps).
  document.querySelectorAll('[data-stagger]').forEach(function (group) {
    var step = parseInt(group.getAttribute('data-stagger'), 10) || 80;
    var i = 0;
    Array.prototype.forEach.call(group.children, function (child) {
      if (child.classList.contains('rv')) {
        child.style.setProperty('--rvd', (i * step) + 'ms');
        i++;
      }
    });
  });

  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add('in');
        io.unobserve(entry.target);
      }
    });
  }, { rootMargin: '0px 0px -60px 0px', threshold: 0.05 });

  document.querySelectorAll('.rv').forEach(function (el) { io.observe(el); });

  // Failsafe: anything already at or near the viewport must never stay hidden
  // (covers headless renderers and observers that miss the initial paint).
  window.addEventListener('load', function () {
    setTimeout(function () {
      document.querySelectorAll('.rv:not(.in)').forEach(function (el) {
        var r = el.getBoundingClientRect();
        if (r.top < (window.innerHeight || 0) + 60) el.classList.add('in');
      });
    }, 1200);
  });
})();
