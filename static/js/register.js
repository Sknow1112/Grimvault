document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("register-form");
  const passwordInput = document.getElementById("password");
  const confirmPasswordInput = document.getElementById("confirm-password");
  const passwordStrength = document.getElementById("password-strength");
  const submitButton = form.querySelector('button[type="submit"]');
  const registerMessage = document.getElementById("register-message");

  function updatePasswordStrength() {
    const password = passwordInput.value;
    let strength = "weak";

    if (
      password.length >= 8 &&
      /[A-Z]/.test(password) &&
      /[a-z]/.test(password) &&
      /\d/.test(password) &&
      /[!@#$%^&*(),.?":{}|<>]/.test(password)
    ) {
      strength = "strong";
    } else if (password.length >= 8) {
      strength = "medium";
    }

    passwordStrength.className = strength;
    submitButton.disabled =
      strength !== "strong" ||
      passwordInput.value !== confirmPasswordInput.value;
  }

  passwordInput.addEventListener("input", updatePasswordStrength);
  confirmPasswordInput.addEventListener("input", updatePasswordStrength);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const formData = new FormData(form);
    try {
      const response = await axios.post("/register", formData);
      registerMessage.textContent = response.data.message;
      registerMessage.style.color = "green";
      setTimeout(() => {
        window.location.href = response.data.redirect;
      }, 2000);
    } catch (error) {
      registerMessage.textContent = error.response.data.error;
      registerMessage.style.color = "red";
    }
  });
});
