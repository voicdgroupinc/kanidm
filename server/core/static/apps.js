// Apps page controls: group toggle and icon size.
//
// This has to be a /pkg file. Kanidm's CSP allows scripts and styles from
// 'self' only, with no 'unsafe-inline', so an inline <script> or <style> in
// the template is silently blocked - which is how these controls shipped dead
// (ARCH-1010).
//
// Grouping and icon size are per-viewer presentation choices, remembered in
// this browser only. The server already renders the apps in group order, so
// everything here is an enhancement: without it the list still renders, in
// order, with working links.
(function () {
	var render = document.getElementById('apps-render');
	if (!render) return;
	var controls = document.getElementById('apps-controls');
	var groupToggle = document.getElementById('apps-groupby');
	var sizeSel = document.getElementById('apps-size');
	if (!controls || !sizeSel) return;

	// localStorage throws in some privacy modes; never let that break the page.
	function load(key, fallback) {
		try {
			var v = localStorage.getItem(key);
			return v === null ? fallback : v;
		} catch (e) {
			return fallback;
		}
	}
	function save(key, value) {
		try {
			localStorage.setItem(key, value);
		} catch (e) { /* not fatal, the choice just will not persist */ }
	}

	var cards = Array.prototype.slice.call(render.querySelectorAll('.app-card'));

	function newRow() {
		var row = document.createElement('div');
		row.className = 'row row-cols-1 row-cols-sm-2 row-cols-md-3 g-3';
		return row;
	}

	function byName(a, b) {
		return a.dataset.name.toLowerCase().localeCompare(b.dataset.name.toLowerCase());
	}

	function sorted(list) {
		return list.slice().sort(byName);
	}

	function heading(text) {
		var h = document.createElement('h5');
		h.className = 'mt-4 mb-2 text-body-secondary';
		h.textContent = text;
		return h;
	}

	function draw() {
		var grouped = groupToggle ? groupToggle.checked : false;
		render.textContent = '';

		if (!grouped) {
			var flat = newRow();
			sorted(cards).forEach(function (c) { flat.appendChild(c); });
			render.appendChild(flat);
			return;
		}

		var order = [];
		var byGroup = {};
		cards.forEach(function (c) {
			var g = c.dataset.group || '';
			if (!Object.prototype.hasOwnProperty.call(byGroup, g)) {
				byGroup[g] = [];
				order.push(g);
			}
			byGroup[g].push(c);
		});
		// Ungrouped apps sort last, under "Other" - but only when there is
		// something to distinguish them from.
		order.sort(function (a, b) {
			if (!a) return 1;
			if (!b) return -1;
			return a.toLowerCase().localeCompare(b.toLowerCase());
		});
		order.forEach(function (g) {
			if (g) {
				render.appendChild(heading(g));
			} else if (order.length > 1) {
				render.appendChild(heading('Other'));
			}
			var row = newRow();
			sorted(byGroup[g]).forEach(function (c) { row.appendChild(c); });
			render.appendChild(row);
		});
	}

	function applySize() {
		render.style.setProperty('--app-icon-size', sizeSel.value + 'px');
	}

	if (groupToggle) groupToggle.checked = load('voicd.apps.groupby', '1') === '1';
	sizeSel.value = load('voicd.apps.size', '104');

	if (groupToggle) {
		groupToggle.addEventListener('change', function () {
			save('voicd.apps.groupby', groupToggle.checked ? '1' : '0');
			draw();
		});
	}
	sizeSel.addEventListener('change', function () {
		save('voicd.apps.size', sizeSel.value);
		applySize();
	});

	controls.classList.remove('d-none');
	applySize();
	draw();
})();
