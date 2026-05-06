document.addEventListener('DOMContentLoaded', () => {
    const button = document.getElementById('action-btn');
    const status = document.getElementById('status');

    button.addEventListener('click', () => {
        status.innerText = "Button clicked! JavaScript is working.";
        status.style.color = "green";
        console.log("Hello from the console!");
    });
});
