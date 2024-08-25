// Loading indicator functions
function showLoading() {
    document.getElementById('loading-indicator').style.display = 'block';
}

function hideLoading() {
    document.getElementById('loading-indicator').style.display = 'none';
}

// Axios interceptors for loading indicator
axios.interceptors.request.use((config) => {
    showLoading();
    return config;
}, (error) => {
    hideLoading();
    return Promise.reject(error);
});

axios.interceptors.response.use((response) => {
    hideLoading();
    return response;
}, (error) => {
    hideLoading();
    return Promise.reject(error);
});

// Logout functionality
const logoutButton = document.getElementById('logout');
if (logoutButton) {
    logoutButton.addEventListener('click', async (e) => {
        e.preventDefault();
        try {
            const response = await axios.get('/logout');
            window.location.href = '/';
        } catch (error) {
            console.error('Logout failed:', error);
            alert('Logout failed. Please try again.');
        }
    });
}

// Error handling function
function handleError(error) {
    console.error('Error:', error);
    if (error.response) {
        alert(`Error: ${error.response.data.error || 'An unexpected error occurred.'}`);
    } else if (error.request) {
        alert('Error: No response received from the server. Please check your internet connection.');
    } else {
        alert('Error: An unexpected error occurred. Please try again.');
    }
}