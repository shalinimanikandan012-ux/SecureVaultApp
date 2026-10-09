
"use strict";

// Clear the file picker after a successful form submission/navigation
// only when the page is freshly loaded.
document.addEventListener("DOMContentLoaded", () => {
    const fileInput = document.querySelector('input[type="file"]');

    if (fileInput) {
        fileInput.addEventListener("change", () => {
            const file = fileInput.files[0];

            if (file && file.size > 16 * 1024 * 1024) {
                alert("Please choose a file smaller than 16 MB.");
                fileInput.value = "";
            }
        });
    }

    document.querySelectorAll('form[action*="delete"]').forEach(form => {
        form.addEventListener("submit", event => {
            if (!confirm("Are you sure you want to delete this item?")) {
                event.preventDefault();
            }
        });
    });
});