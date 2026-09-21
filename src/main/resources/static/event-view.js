(function (root) {
    function appendEvent(document, container, attack) {
        const row = document.createElement('div');
        row.className = 'log-row';
        const time = new Date(attack.timestamp || Date.now()).toLocaleTimeString();
        row.textContent = `[${time}] IP:${attack.ipAddress ?? 'Unknown'} PORT:${attack.port ?? '?'} `
            + `${attack.thresholdExceeded ? '[RATE THRESHOLD — NOT BLOCKED] ' : ''}↳ ${attack.payload ?? ''}`;
        container.appendChild(row);
        while (container.children.length > 300) container.firstElementChild.remove();
        container.scrollTop = container.scrollHeight;
        return row;
    }
    root.HoneygridView = { appendEvent };
    if (typeof module !== 'undefined') module.exports = { appendEvent };
})(typeof globalThis !== 'undefined' ? globalThis : window);
