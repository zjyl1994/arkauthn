document.addEventListener('DOMContentLoaded', function () {
    const expireElement = document.getElementById('expire-time');
    const timestamp = parseInt(expireElement.textContent);

    if (!isNaN(timestamp)) {
        const date = new Date(timestamp * 1000);
        expireElement.textContent = date.toLocaleString();
    }
});
