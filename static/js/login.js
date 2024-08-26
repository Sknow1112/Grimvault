document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("login-form");
  const loginMessage = document.getElementById("login-message");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const formData = new FormData(form);
    try {
      const response = await axios.post("/login", formData);
      loginMessage.textContent = response.data.message;
      loginMessage.style.color = "green";
      window.location.href = response.data.redirect;
    } catch (error) {
      loginMessage.textContent = error.response.data.error;
      loginMessage.style.color = "red";
    }
  });
});
