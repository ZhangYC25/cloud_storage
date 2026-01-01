// auth.js - 登录与注册页面脚本

let countdown = 60; // 验证码倒计时秒数
let countdownInterval = null; // 倒计时定时器

/**
 * 切换密码可见性
 */
function togglePasswordVisibility(inputId, iconElement) {
    const input = document.getElementById(inputId);
    const isPassword = input.type === 'password';

    input.type = isPassword ? 'text' : 'password';
    iconElement.classList.toggle('fa-eye');
    iconElement.classList.toggle('fa-eye-slash');
}

/**
 * 显示注册表单
 */
function showRegister() {
    document.getElementById('login-box').style.display = 'none';
    const registerBox = document.getElementById('register-box');
    registerBox.style.display = 'block';
    registerBox.style.animation = 'none';
    setTimeout(() => {
        registerBox.style.animation = 'fadeIn 0.4s cubic-bezier(0.2, 0.8, 0.2, 1) forwards';
    }, 10);
}

/**
 * 显示登录表单
 */
function showLogin() {
    document.getElementById('register-box').style.display = 'none';
    const loginBox = document.getElementById('login-box');
    loginBox.style.display = 'block';
    loginBox.style.animation = 'none';
    setTimeout(() => {
        loginBox.style.animation = 'fadeIn 0.4s cubic-bezier(0.2, 0.8, 0.2, 1) forwards';
    }, 10);
}

/**
 * 用户登录
 */
async function login() {
    const nameInput = document.getElementById('login-name');
    const passInput = document.getElementById('login-password');
    const submitBtn = document.getElementById('login-button');
    const errorDiv = document.getElementById('login-error');

    errorDiv.textContent = '';
    const name = nameInput.value.trim();
    const password = passInput.value;

    if (!name || !password) {
        alert("请输入完整信息！");
        return;
    }

    if (submitBtn.disabled) return;

    submitBtn.disabled = true;
    submitBtn.textContent = '登录中…';

    try {
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, password })
        });

        const data = await res.json();

        if (res.ok && data.message === "login successful") {
            window.location.href = "/updown.html";
        } else {
            errorDiv.textContent = '用户名或密码错误';
            passInput.value = '';
            nameInput.focus();
        }
    } catch (error) {
        console.error("登录异常:", error);
        alert("网络错误，请检查连接后重试");
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = '登录';
    }
}

/**
 * 发送邮箱验证码
 */
async function sendVerificationCode() {
    const emailInput = document.getElementById('reg-email');
    const nameInput = document.getElementById('reg-name');
    const btn = document.getElementById('send-code-btn');
    const errorDiv = document.getElementById('register-error');

    errorDiv.textContent = '';
    errorDiv.style.color = '#e74c3c';

    const email = emailInput.value.trim();
    const name = nameInput.value.trim();

    // 前端快速校验
    if (!email) {
        errorDiv.textContent = '请先填写邮箱';
        emailInput.focus();
        return;
    }
    if (!name) {
        errorDiv.textContent = '用户名不能为空';
        nameInput.focus();
        return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
        errorDiv.textContent = '邮箱格式不正确';
        emailInput.focus();
        return;
    }
    if (name.length < 3 || name.length > 20) {
        errorDiv.textContent = '用户名必须为 3-20 个字符';
        nameInput.focus();
        return;
    }

    if (btn.disabled) return;

    try {
        const res = await fetch('/api/email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, name })
        });

        const data = await res.json();

        if (res.ok) {
            errorDiv.style.color = '#27ae60';
            errorDiv.textContent = '验证码已发送，请查收（包括垃圾邮件）';

            // 开始倒计时
            countdown = 60;
            btn.disabled = true;
            btn.textContent = `${countdown}s 后重试`;

            if (countdownInterval) clearInterval(countdownInterval);
            countdownInterval = setInterval(() => {
                countdown--;
                if (countdown <= 0) {
                    clearInterval(countdownInterval);
                    btn.disabled = false;
                    btn.textContent = '重新获取';
                } else {
                    btn.textContent = `${countdown}s 后重试`;
                }
            }, 1000);
        } else {
            let msg = data.error || '未知错误，请稍后重试';
            if (msg.includes('name has existed')) msg = '该用户名已被注册';
            else if (msg.includes('email has existed')) msg = '该邮箱已被注册';
            else if (msg.includes('valid email')) msg = '请输入有效的邮箱地址';
            else if (msg.includes('send verify failed')) msg = '验证码发送失败，请稍后重试';

            errorDiv.textContent = msg;
        }
    } catch (err) {
        console.error("网络请求失败:", err);
        errorDiv.textContent = '网络错误，请检查连接后重试';
    }
}

/**
 * 用户注册
 */
async function registerUser() {
    const nameInput = document.getElementById('reg-name');
    const emailInput = document.getElementById('reg-email');
    const passwordInput = document.getElementById('reg-password');
    const errorDiv = document.getElementById('register-error');
    const btn = document.getElementById('register-button');

    errorDiv.textContent = '';
    errorDiv.style.color = '#e74c3c';

    const name = nameInput.value.trim();
    const email = emailInput.value.trim();
    const password = passwordInput.value;

    // 前端校验
    if (!name) {
        errorDiv.textContent = '请输入用户名';
        nameInput.focus();
        return;
    }
    if (name.length < 3 || name.length > 20) {
        errorDiv.textContent = '用户名需为 3-20 个字符';
        nameInput.focus();
        return;
    }
    if (!email) {
        errorDiv.textContent = '请输入邮箱';
        emailInput.focus();
        return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
        errorDiv.textContent = '邮箱格式不正确';
        emailInput.focus();
        return;
    }
    if (!password) {
        errorDiv.textContent = '请输入密码';
        passwordInput.focus();
        return;
    }

    btn.disabled = true;
    btn.textContent = '注册中…';

    try {
        const res = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, password, email })
        });

        const data = await res.json();

        if (res.ok) {
            errorDiv.style.color = '#27ae60';
            errorDiv.textContent = '注册成功！2秒后返回登录…';
            setTimeout(() => {
                showLogin();
                nameInput.value = '';
                emailInput.value = '';
                passwordInput.value = '';
                errorDiv.textContent = '';
            }, 2000);
        } else {
            let msg = data.error || data.message || '注册失败，请稍后重试';
            if (msg.includes('name has existed') || msg.includes('name already taken')) msg = '该用户名已被占用';
            else if (msg.includes('email has existed') || msg.includes('email already registered')) msg = '该邮箱已被注册';
            else if (msg.includes('password is too weak')) msg = '密码过于简单，请换一个';
            else if (msg.includes('password must be at least 8')) msg = '密码需>= 8 位，并包含字母、数字或符号';
            else if (msg.includes('valid email') || msg.includes('invalid email')) msg = '邮箱格式不正确';

            errorDiv.textContent = msg;
        }
    } catch (error) {
        console.error("注册异常:", error);
        alert("网络错误，请稍后重试");
    } finally {
        btn.disabled = false;
        btn.textContent = '注册';
    }
}
