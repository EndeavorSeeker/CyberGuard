// 1. Block the default browser behavior for the entire window
window.addEventListener('dragover', (e) => {
    e.preventDefault();
}, false);

window.addEventListener('drop', (e) => {
    e.preventDefault();
    const files = e.dataTransfer.files;

    if (files.length > 0) {
        // This line links the dropped file to your hidden input
        document.getElementById('file-input').files = files;
        
        // Optional: Provide visual feedback
        document.getElementById('status').innerText = "File ready: " + files[0].name;
    }
});

function handleGlobalDrop(file) {
    console.log("File received globally:", file.name);
    
    // Example: Update your UI to show the file name
    const status = document.getElementById('status');
    if (status) {
        status.innerText = "Ready to process: " + file.name;
    }

    // Now you can send this 'file' object to your Flask backend
}
