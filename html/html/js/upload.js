// script.js

/*
 * ===============================================
 * UI 辅助函数（仅用于显示）
 * ===============================================
 */
function updateFileNameDisplay(input) {
    const display = document.getElementById('fileInputDisplay');
    if (input.files && input.files.length > 0) {
        display.innerHTML = `<i class="fa-solid fa-file"></i> 已选择: ${input.files[0].name}`;
        document.getElementById('uploadResult').classList.add('hidden');
    } else {
        display.innerHTML = `<i class="fa-solid fa-file-upload"></i> 点击此处选择文件 或 拖放文件`;
    }
}

function displayResult(success, message, url) {
    const resultDiv = document.getElementById('uploadResult');
    resultDiv.classList.remove('hidden');
    resultDiv.style.backgroundColor = '';
    resultDiv.style.color = '';

    if (success === true) {
        resultDiv.style.backgroundColor = '#e8f5e9';
        resultDiv.style.color = '#2e7d32';
        resultDiv.innerHTML = `
            <h4>上传成功！</h4>
            <p>${message}</p>
            <p>文件 URL (请保存):</p>
            <span class="url-box">${url}</span>
        `;
    } else if (success === false) {
        resultDiv.style.backgroundColor = '#ffebee';
        resultDiv.style.color = '#c62828';
        resultDiv.innerHTML = `
            <h4>上传失败</h4>
            <p>${message}</p>
        `;
    } else {
        resultDiv.style.backgroundColor = '#fff3e0';
        resultDiv.style.color = '#ef6c00';
        resultDiv.innerHTML = `
            <h4>提示</h4>
            <p>${message}</p>
        `;
    }
}

/*
 * ===============================================
 * 页面初始化与导航
 * ===============================================
 */
document.addEventListener('DOMContentLoaded', () => {
    switchPage('uploadPage');
});

function switchPage(pageId) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById(pageId).classList.add('active');

    document.querySelectorAll('.nav-link-item').forEach(link => link.classList.remove('current'));
    document.getElementById(pageId.replace('Page', 'Link')).classList.add('current');
}

/*
 * ===============================================
 * 文件 MD5 计算（需要引入 SparkMD5 库）
 * ===============================================
 */
async function calcFileMD5(file) {
    console.log("MD5() 被调用了");
    return new Promise((resolve, reject) => {
        if (file.size === 0) {
            return resolve(SparkMD5.hash(''));
        }

        const chunkSize = 2 * 1024 * 1024; // 2MB
        const chunks = Math.ceil(file.size / chunkSize);
        let currentChunk = 0;
        const spark = new SparkMD5.ArrayBuffer();

        function loadNext() {
            const start = currentChunk * chunkSize;
            const end = Math.min(start + chunkSize, file.size);
            const chunk = file.slice(start, end);
            const reader = new FileReader();

            reader.onload = (e) => {
                spark.append(e.target.result);
                currentChunk++;
                if (currentChunk < chunks) {
                    loadNext();
                } else {
                    resolve(spark.end());
                }
            };

            reader.onerror = () => reject(new Error("MD5 计算失败"));
            reader.readAsArrayBuffer(chunk);
        }

        loadNext();
    });
}

function getFileExtension(file) {
    if (!file || !file.name) return '';
    const dotIndex = file.name.lastIndexOf('.');
    if (dotIndex === -1 || dotIndex === file.name.length - 1) return '';
    return file.name.slice(dotIndex + 1).toLowerCase();
}

/*
 * ===============================================
 * 大文件分块上传
 * ===============================================
 */
const LARGE_FILE_THRESHOLD = 1024 * 1024; // 1MB
const CHUNK_SIZE = 256 * 1024; // 256KB
const MAX_CONCURRENT = 4;

async function uploadLargeFile(file, md5) {
    const uploadBtn = document.getElementById('uploadBtn');
    const ext = getFileExtension(file);
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

    // 初始化
    const initRes = await fetch("/api/upload/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename: file.name, size: totalChunks, md5, ext })
    });
    if (!initRes.ok) throw new Error((await initRes.json().catch(() => ({}))).message || "初始化上传失败");
    const { upload_id } = await initRes.json();

    let uploadedCount = 0;
    const uploadChunk = async (i) => {
        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, file.size);
        const chunk = file.slice(start, end);

        const res = await fetch("/api/upload/chunk", {
            method: "POST",
            headers: {
                "X-Upload-ID": upload_id,
                "X-Chunk-Index": i.toString(),
		"X-File-MD5": md5,
                "Content-Type": "application/octet-stream"
            },
            body: chunk
        });
        if (!res.ok) throw new Error(`Chunk ${i} failed`);
        uploadedCount++;
        uploadBtn.textContent = `上传中... (${uploadedCount}/${totalChunks})`;
    };

    // 分批并发上传
    const chunks = Array.from({ length: totalChunks }, (_, i) => i);
    for (let i = 0; i < chunks.length; i += MAX_CONCURRENT) {
        const batch = chunks.slice(i, i + MAX_CONCURRENT);
        await Promise.all(batch.map(uploadChunk));
    }

    // 完成合并
    uploadBtn.textContent = "合并文件...";
    const finishRes = await fetch("/api/upload/finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({md5, upload_id })
    });
    const finishData = await finishRes.json().catch(() => ({}));
    if (!finishRes.ok || finishData.success === false) {
        throw new Error(finishData.message || finishData.error || "合并失败");
    }
    if (finishData.status === "finish" && finishData.url) {
        return finishData;
    }

    // 轮询获取最终 URL
    const MAX_RETRIES = 20;
    const RETRY_INTERVAL = 1000;
    let retries = 0;
    while (retries < MAX_RETRIES) {
        try {
            const queryRes = await fetch("/api/upload/query", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ md5, upload_id })
            });
            if (queryRes.ok) {
                const data = await queryRes.json();
                if (data.url) return data;
                if (data.error) throw new Error(data.error);
            }
        } catch (err) {
            console.warn("Query failed, retrying...", err);
        }
        retries++;
        if (retries < MAX_RETRIES) await new Promise(r => setTimeout(r, RETRY_INTERVAL));
    }
    throw new Error("文件合并超时，请稍后重试或联系管理员");
}

/*
 * ===============================================
 * 主上传函数
 * ===============================================
 */
async function uploadFile() {
    console.log("uploadFile() 被调用了");
    const fileInput = document.getElementById('fileInput');
    const uploadBtn = document.getElementById('uploadBtn');
    const file = fileInput.files[0];

    document.getElementById('uploadResult').classList.add('hidden');
    if (!file) return alert("请先选择文件！");

    uploadBtn.disabled = true;
    uploadBtn.textContent = "上传中...";

    try {
        const md5 = await calcFileMD5(file);

        const checkRes = await fetch("/api/upload/check", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ filename: file.name, md5 })
        });
        const checkData = await checkRes.json();

        if (checkData.status === "already_owned") {
            displayResult(null, "文件已存在，无需上传！", null);
            return;
        }
        if (checkData.status === "instant_upload") {
            displayResult(null, "秒传成功！文件已添加到您的网盘。", null);
            return;
        }
        if (checkData.status !== "need_upload") throw new Error(checkData.message || "预检失败");

        let uploadData;
        if (file.size < LARGE_FILE_THRESHOLD) {
            const uploadRes = await fetch("/api/upload/file", {
                method: "POST",
        	    headers: {
            		"Content-Type": "application/octet-stream",
            		"X-Filename": encodeURIComponent(file.name),  
            		"X-File-MD5": md5,
        		},
       			body: file
    			});
	    uploadData = await uploadRes.json();
            if (!uploadRes.ok || !uploadData.success) throw new Error(uploadData.message || "上传失败");
            displayResult(true, "文件上传成功！", uploadData.url);
        } else {
            uploadData = await uploadLargeFile(file, md5);
            displayResult(true, "文件上传成功！", uploadData.url);
        }
    } catch (err) {
        console.error("上传出错:", err);
        displayResult(false, err.message || "未知错误", null);
    } finally {
        uploadBtn.disabled = false;
        uploadBtn.textContent = "上传";
        fileInput.value = "";
        updateFileNameDisplay(fileInput);
    }
}

/*
 * ===============================================
 * 文件列表与删除
 * ===============================================
 */
function escapeHtml(text) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };
    return text.replace(/[&<>"']/g, m => map[m]);
}

function loadFiles() {
    fetch(`/api/files`)
        .then(res => {
            if (!res.ok) throw new Error("加载失败");
            return res.json();
        })
        .then(data => {
            const tbody = document.querySelector("#filesTable tbody");
            tbody.innerHTML = "";
            data.forEach(f => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td>${escapeHtml(f.filename)}</td>
                    <td><a href="${f.url}" target="_blank">查看</a></td>
                    <td><a href="${f.url}" download>下载</a></td>
                    <td><button onclick="deleteFile('${f.id}')">删除</button></td>
                `;
                tbody.appendChild(tr);
            });
        })
        .catch(err => console.error(err));
}

function deleteFile(id) {
    fetch(`/api/delete?id=${encodeURIComponent(id)}`, { method: "DELETE" })
        .then(res => {
            if (!res.ok) throw new Error(`请求失败，状态码：${res.status}`);
            return res.json();
        })
        .then(data => {
            if (data.success) {
                alert("删除成功");
                loadFiles();
            } else {
                alert(`删除失败：${data.message}`);
            }
        })
        .catch(error => alert(`操作失败：${error.message || "服务器异常"}`));
}
