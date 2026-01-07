// 配置必须在加载 CapJS 之前设置，否则会回退到 CDN
// 使用绝对路径以避免 Web Worker 中的解析问题
window.CAP_CUSTOM_WASM_URL = new URL('/vendor/capjs/cap_wasm.min.js', window.location.href).href;

// 使用动态导入确保配置已生效
const { default: Cap } = await import('/vendor/capjs/cap.js');

const urlParams = new URLSearchParams(window.location.search);
if (urlParams.has('e')) {
    document.getElementById('error-message').style.display = 'block';
}

if (urlParams.has('r')) {
    document.getElementById('redirect').value = urlParams.get('r');
}

const form = document.querySelector('.login-form');
const submitBtn = form.querySelector('button[type="submit"]');
const usernameInput = form.querySelector('input[name="username"]');

// Load saved username
const savedUsername = localStorage.getItem('arkauthn_username');
if (savedUsername) {
    usernameInput.value = savedUsername;
}

// Duration selector logic
const durationInputs = document.querySelectorAll('input[name="duration-option"]');
const durationInput = document.getElementById('duration-input');

durationInputs.forEach(input => {
    input.addEventListener('change', (e) => {
        if (e.target.checked) {
            durationInput.value = e.target.value;
        }
    });
});

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    // Save username
    localStorage.setItem('arkauthn_username', usernameInput.value);
    
    if (submitBtn.disabled) return;
    
    const originalText = submitBtn.innerText;
    submitBtn.disabled = true;
    submitBtn.innerText = '安全验证中...';

    try {
        const cap = new Cap({
            apiEndpoint: '/api/cap/',
        });
        const solution = await cap.solve();
        
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'cap_token';
        input.value = solution.token;
        form.appendChild(input);
        
        form.submit();
    } catch (err) {
        console.error(err);
        alert('验证失败，请重试');
        submitBtn.disabled = false;
        submitBtn.innerText = originalText;
    }
});
