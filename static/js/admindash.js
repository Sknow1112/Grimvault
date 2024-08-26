document.addEventListener("DOMContentLoaded", () => {
  const userAccounts = document.getElementById("user-accounts");

  userAccounts.addEventListener("click", async (e) => {
    const username = e.target.dataset.username;

    if (e.target.classList.contains("update-storage")) {
      const newLimit = prompt("Enter new storage limit in GB:");
      if (newLimit) {
        try {
          const response = await axios.post("/admin/update_storage", {
            username: username,
            new_limit: newLimit,
          });
          alert(response.data.message);
          location.reload();
        } catch (error) {
          alert(
            "Failed to update storage: " +
              (error.response?.data?.error || error.message),
          );
        }
      }
    } else if (e.target.classList.contains("toggle-ban")) {
      const currentStatus = e.target.dataset.banned === "true";
      const newStatus = !currentStatus;
      try {
        const response = await axios.post("/admin/ban_user", {
          username: username,
          ban_status: newStatus,
        });
        alert(response.data.message);
        location.reload();
      } catch (error) {
        alert(
          "Failed to update ban status: " +
            (error.response?.data?.error || error.message),
        );
      }
    } else if (e.target.classList.contains("delete-account")) {
      if (
        confirm(`Are you sure you want to delete the account for ${username}?`)
      ) {
        try {
          const response = await axios.delete(`/admin/delete/${username}`);
          alert(response.data.message);
          location.reload();
        } catch (error) {
          alert(
            "Failed to delete account: " +
              (error.response?.data?.error || error.message),
          );
        }
      }
    }
  });
});
