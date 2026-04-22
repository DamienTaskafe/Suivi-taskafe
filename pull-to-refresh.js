// pull-to-refresh.js — Chrome-style circular pull-to-refresh gesture handler
// Call initPullToRefresh(onRefresh) once the app DOM is ready.
// onRefresh: async function() — called when the user completes a pull gesture

export function initPullToRefresh(onRefresh) {
  let startY = 0, startX = 0;
  let isAtTop = false;
  let isPulling = false;
  let isArmed = false;
  let hasVibrated = false;
  let isRefreshing = false;

  const THRESHOLD = Math.round(window.innerHeight * 0.5);
  const MAX_OFFSET = 68;
  const CIRC = 100.5;
  const RUBBER_BAND_COEFF = 5.2;
  const FADE_IN_DISTANCE = 18;
  const ARC_MAX_RATIO = 0.82;
  const HORIZONTAL_SWIPE_THRESHOLD = 0.9;

  const ind = document.getElementById('pullIndicator');
  const arc = document.getElementById('pullArc');

  function resetGesture() {
    isAtTop = false;
    isPulling = false;
    isArmed = false;
    hasVibrated = false;
  }

  function hideIndicator(animated) {
    if (!ind) return;
    if (animated) {
      ind.style.transition = 'transform 0.28s cubic-bezier(0.4,0,0.2,1), opacity 0.28s ease';
    }
    ind.style.transform = 'translateX(-50%) translateY(-68px)';
    ind.style.opacity = '0';
    setTimeout(() => {
      if (arc) { arc.style.strokeDasharray = `0 ${CIRC}`; arc.setAttribute('transform', 'rotate(-90 22 22)'); }
      if (ind) ind.classList.remove('ptr-refreshing');
    }, animated ? 300 : 0);
  }

  const SCROLL_TOLERANCE = 1;
  function isInsideScrollable(el) {
    let node = el.parentElement;
    while (node && node !== document.documentElement) {
      const s = getComputedStyle(node);
      const ov = s.overflowY || s.overflow;
      if ((ov === 'auto' || ov === 'scroll') &&
          node.scrollHeight > node.clientHeight + SCROLL_TOLERANCE &&
          node.scrollTop > SCROLL_TOLERANCE) {
        return true;
      }
      node = node.parentElement;
    }
    return false;
  }

  document.addEventListener('touchstart', e => {
    resetGesture();
    if (isRefreshing) return;
    const appShell = document.getElementById('appShell');
    if (!appShell || appShell.classList.contains('hidden')) return;
    if (window.scrollY > 2) return;
    if (isInsideScrollable(e.target)) return;
    startY = e.touches[0].clientY;
    startX = e.touches[0].clientX;
    isAtTop = true;
  }, { passive: true });

  document.addEventListener('touchmove', e => {
    if (!isAtTop || isRefreshing) return;

    const dy = e.touches[0].clientY - startY;
    const dx = e.touches[0].clientX - startX;

    if (!isPulling) {
      if (dy < 8) return;
      if (Math.abs(dx) > dy * HORIZONTAL_SWIPE_THRESHOLD) return;
      isPulling = true;
    }
    if (dy <= 0) { resetGesture(); return; }

    if (dy >= THRESHOLD && !hasVibrated) {
      isArmed = true;
      hasVibrated = true;
      if (navigator.vibrate) navigator.vibrate(30);
    }

    const offset = Math.min(Math.sqrt(dy) * RUBBER_BAND_COEFF, MAX_OFFSET);
    if (ind) {
      ind.style.transition = 'none';
      ind.style.transform = `translateX(-50%) translateY(${offset - 52}px)`;
      ind.style.opacity = Math.min(offset / FADE_IN_DISTANCE, 1).toString();
    }
    if (arc) {
      const progress = Math.min(dy / THRESHOLD, 1);
      const arcLen = progress * CIRC * ARC_MAX_RATIO;
      arc.style.strokeDasharray = `${arcLen} ${CIRC}`;
      arc.setAttribute('transform', `rotate(${-90 + progress * 300} 22 22)`);
    }
  }, { passive: true });

  document.addEventListener('touchend', async e => {
    if (!isPulling) { resetGesture(); return; }
    const dy = e.changedTouches[0].clientY - startY;
    const wasArmed = isArmed;
    resetGesture();

    if (wasArmed && dy >= THRESHOLD) {
      isRefreshing = true;
      if (ind) {
        ind.style.transition = 'transform 0.22s cubic-bezier(0.4,0,0.2,1)';
        ind.style.transform = 'translateX(-50%) translateY(14px)';
        ind.style.opacity = '1';
        ind.classList.add('ptr-refreshing');
      }
      if (arc) arc.style.strokeDasharray = `62 38`;
      try {
        await onRefresh();
      } catch(err) {
        // caller handles errors
      }
      if (ind) {
        ind.style.transition = 'transform 0.3s ease, opacity 0.3s ease';
        ind.style.transform = 'translateX(-50%) translateY(-68px)';
        ind.style.opacity = '0';
      }
      setTimeout(() => {
        if (ind) ind.classList.remove('ptr-refreshing');
        if (arc) { arc.style.strokeDasharray = `0 ${CIRC}`; arc.setAttribute('transform', 'rotate(-90 22 22)'); }
        isRefreshing = false;
      }, 320);
    } else {
      hideIndicator(true);
    }
  }, { passive: true });

  document.addEventListener('touchcancel', () => {
    if (isPulling) hideIndicator(true);
    resetGesture();
  }, { passive: true });
}
