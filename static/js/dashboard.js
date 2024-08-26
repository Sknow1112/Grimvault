document.addEventListener("DOMContentLoaded", () => {
  const uploadForm = document.getElementById("upload-form");
  const emptyVaultBtn = document.getElementById("empty-vault");
  const fileList = document.getElementById("file-list");

  uploadForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    try {
      const response = await axios.post("/upload", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      alert(response.data.message);
      location.reload();
    } catch (error) {
      alert("Upload failed: " + (error.response?.data?.error || error.message));
    }
  });

  emptyVaultBtn.addEventListener("click", async () => {
    const confirmed = confirm(
      "Are you sure you want to empty your vault? This action cannot be undone.",
    );
    if (confirmed) {
      const password = prompt(
        "Enter your password to confirm emptying your vault:",
      );
      if (password) {
        try {
          const response = await axios.post("/empty", { password });
          alert(response.data.message);
          location.reload();
        } catch (error) {
          alert(
            "Failed to empty vault: " +
              (error.response?.data?.error || error.message),
          );
        }
      }
    }
  });

  fileList.addEventListener("click", async (e) => {
    if (e.target.classList.contains("download-btn")) {
      const filename = e.target.dataset.filename;
      window.location.href = `/download/${filename}`;
    } else if (e.target.classList.contains("delete-btn")) {
      const filename = e.target.dataset.filename;
      if (confirm(`Are you sure you want to delete ${filename}?`)) {
        try {
          const response = await axios.delete(`/delete/${filename}`);
          alert(response.data.message);
          e.target.closest("li").remove();
        } catch (error) {
          alert(
            "Failed to delete file: " +
              (error.response?.data?.error || error.message),
          );
        }
      }
    }
  });
});
