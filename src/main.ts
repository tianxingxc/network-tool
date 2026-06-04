import './ui/styles.css';
import {
  aesEncrypt, aesDecrypt, desEncrypt, desDecrypt, tripleDesEncrypt, tripleDesDecrypt,
  generateRSAKeyPair, rsaEncrypt, rsaDecrypt,
  type RSAPadding,
  md5, sha1, sha256, sha512, hmacSHA256,
  base64Encode, base64Decode, urlEncode, urlDecode, htmlEncode, htmlDecode,
  unicodeEncode, unicodeDecode, hexEncode, hexDecode,
  convertBase, getBaseNames, textToAscii, asciiToText,
} from './crypto';

// ========== Utility ==========
function $(sel: string): HTMLElement | null {
  return document.querySelector(sel);
}

function $$(sel: string): NodeListOf<HTMLElement> {
  return document.querySelectorAll(sel);
}

function showToast(msg: string, type: 'success' | 'error' | 'info' = 'success') {
  const old = document.querySelector('.toast');
  if (old) old.remove();
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2500);
}

function copyText(text: string) {
  navigator.clipboard.writeText(text).then(
    () => showToast('已复制到剪贴板'),
    () => showToast('复制失败', 'error')
  );
}

function getVal(id: string): string {
  return (($('#' + id)) as HTMLInputElement | HTMLTextAreaElement | null)?.value || '';
}

function setVal(id: string, val: string) {
  const el = $('#' + id) as HTMLInputElement | HTMLTextAreaElement | null;
  if (el) el.value = val;
}

const hashAlgorithms: Record<string, (input: string) => string> = {
  MD5: md5,
  'SHA-1': sha1,
  'SHA-256': sha256,
  'SHA-512': sha512,
};

// ========== Render App ==========
function renderApp() {
  const app = $('#app')!;
  app.innerHTML = `
    <div class="header">
      <h1>CryptoKit</h1>
      <p class="subtitle">加密解密工具箱 | 纯浏览器端运行，数据不离开本机</p>
    </div>

    <nav class="tab-nav">
      <button class="tab-btn active" data-tab="hash"><span class="icon">#</span> 哈希</button>
      <button class="tab-btn" data-tab="symmetric"><span class="icon">⊞</span> 对称加密</button>
      <button class="tab-btn" data-tab="rsa"><span class="icon">⚷</span> RSA</button>
      <button class="tab-btn" data-tab="encoding"><span class="icon">≂</span> 编解码</button>
      <button class="tab-btn" data-tab="convert"><span class="icon">⇄</span> 进制转换</button>
    </nav>

    <!-- Hash Tab -->
    <div class="tab-content active" id="tab-hash">
      <div class="card">
        <div class="card-title">哈希计算</div>
        <div class="form-group">
          <label>哈希算法</label>
          <select id="hash-algo">
            <option value="MD5">MD5</option>
            <option value="SHA-1">SHA-1</option>
            <option value="SHA-256" selected>SHA-256</option>
            <option value="SHA-512">SHA-512</option>
          </select>
        </div>
        <div class="form-group">
          <label>输入文本</label>
          <textarea id="hash-input" placeholder="输入要计算哈希的文本..."></textarea>
        </div>
        <div class="btn-row">
          <button class="btn btn-primary" id="hash-calc">计算哈希</button>
          <button class="btn btn-outline" id="hash-clear">清空</button>
        </div>
        <div class="hash-results" id="hash-results"></div>
      </div>

      <div class="card">
        <div class="card-title">HMAC-SHA256 <span class="badge">签名</span></div>
        <div class="form-group">
          <label>消息</label>
          <textarea id="hmac-msg" class="small" placeholder="输入消息..."></textarea>
        </div>
        <div class="form-group">
          <label>密钥</label>
          <input type="text" id="hmac-key" placeholder="输入密钥..." />
        </div>
        <div class="btn-row">
          <button class="btn btn-primary" id="hmac-calc">计算 HMAC</button>
        </div>
        <div id="hmac-result"></div>
      </div>
    </div>

    <!-- Symmetric Encryption Tab -->
    <div class="tab-content" id="tab-symmetric">
      <div class="card">
        <div class="card-title">AES 加密解密</div>
        <div class="form-group">
          <label>密钥 (Key)</label>
          <input type="text" id="aes-key" placeholder="输入AES密钥 (自动填充至16/24/32字节)" />
        </div>
        <div class="form-group">
          <label>模式</label>
          <select id="aes-mode">
            <option value="CBC">CBC (默认)</option>
            <option value="ECB">ECB</option>
            <option value="CFB">CFB</option>
            <option value="OFB">OFB</option>
            <option value="CTR">CTR</option>
          </select>
        </div>
        <div class="grid-2">
          <div class="form-group">
            <label>明文</label>
            <textarea id="aes-plain" placeholder="输入要加密的明文..."></textarea>
          </div>
          <div class="form-group">
            <label>密文 (Base64)</label>
            <textarea id="aes-cipher" placeholder="输入要解密的密文..."></textarea>
          </div>
        </div>
        <div class="btn-row">
          <button class="btn btn-primary" id="aes-enc">加密 →</button>
          <button class="btn btn-success" id="aes-dec">← 解密</button>
        </div>
      </div>

      <div class="card">
        <div class="card-title">DES / 3DES 加密解密</div>
        <div class="form-group">
          <label>密钥</label>
          <input type="text" id="des-key" placeholder="DES: 8字节 | 3DES: 24字节" />
        </div>
        <div class="grid-2">
          <div class="form-group">
            <label>明文</label>
            <textarea id="des-plain" class="small" placeholder="输入明文..."></textarea>
          </div>
          <div class="form-group">
            <label>密文 (Base64)</label>
            <textarea id="des-cipher" class="small" placeholder="输入密文..."></textarea>
          </div>
        </div>
        <div class="btn-row">
          <button class="btn btn-primary" id="des-enc">DES 加密</button>
          <button class="btn btn-success" id="des-dec">DES 解密</button>
          <button class="btn btn-primary" id="tdes-enc">3DES 加密</button>
          <button class="btn btn-success" id="tdes-dec">3DES 解密</button>
        </div>
      </div>
    </div>

    <!-- RSA Tab -->
    <div class="tab-content" id="tab-rsa">
      <div class="card">
        <div class="card-title">RSA 密钥对生成</div>
        <div class="form-group">
          <label>密钥长度</label>
          <select id="rsa-keysize">
            <option value="512">512 bit</option>
            <option value="1024">1024 bit</option>
            <option value="2048" selected>2048 bit</option>
            <option value="3072">3072 bit</option>
            <option value="4096">4096 bit</option>
          </select>
        </div>
        <div class="btn-row">
          <button class="btn btn-primary" id="rsa-gen">生成密钥对</button>
        </div>
        <div class="grid-2">
          <div class="form-group">
            <label>公钥 (PEM)</label>
            <div class="result-area">
              <button class="copy-btn" id="rsa-pubkey-copy">复制</button>
              <div class="key-display" id="rsa-pubkey">点击"生成密钥对"开始</div>
            </div>
          </div>
          <div class="form-group">
            <label>私钥 (PEM)</label>
            <div class="result-area">
              <button class="copy-btn" id="rsa-privkey-copy">复制</button>
              <div class="key-display" id="rsa-privkey"></div>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">RSA 加密解密</div>
        <div class="form-group">
          <label>填充方式</label>
          <select id="rsa-padding">
            <option value="PKCS1_V1_5">PKCS#1 v1.5</option>
            <option value="OAEP">OAEP (SHA-256)</option>
          </select>
        </div>
        <div class="form-group">
          <label>公钥 (PEM)</label>
          <textarea id="rsa-enc-pubkey" placeholder="粘贴公钥PEM..." style="min-height:120px;"></textarea>
        </div>
        <div class="form-group">
          <label>私钥 (PEM)</label>
          <textarea id="rsa-enc-privkey" placeholder="粘贴私钥PEM..." style="min-height:120px;"></textarea>
        </div>
        <div class="grid-2">
          <div class="form-group">
            <label>明文</label>
            <textarea id="rsa-plain" class="small" placeholder="输入要加密的明文..."></textarea>
          </div>
          <div class="form-group">
            <label>密文 (Base64)</label>
            <textarea id="rsa-cipher" class="small" placeholder="输入要解密的密文..."></textarea>
          </div>
        </div>
        <div class="btn-row">
          <button class="btn btn-primary" id="rsa-enc">加密 →</button>
          <button class="btn btn-success" id="rsa-dec">← 解密</button>
        </div>
      </div>
    </div>

    <!-- Encoding Tab -->
    <div class="tab-content" id="tab-encoding">
      <div class="card">
        <div class="card-title">Base64 编解码</div>
        <div class="grid-2">
          <div class="form-group">
            <label>原文</label>
            <textarea id="b64-input" class="small" placeholder="输入文本..."></textarea>
          </div>
          <div class="form-group">
            <label>Base64</label>
            <textarea id="b64-output" class="small" placeholder="Base64结果..."></textarea>
          </div>
        </div>
        <div class="btn-row">
          <button class="btn btn-primary" id="b64-enc">编码 →</button>
          <button class="btn btn-success" id="b64-dec">← 解码</button>
        </div>
      </div>

      <div class="card">
        <div class="card-title">URL 编解码</div>
        <div class="grid-2">
          <div class="form-group">
            <label>原文</label>
            <textarea id="url-input" class="small" placeholder="输入文本..."></textarea>
          </div>
          <div class="form-group">
            <label>URL编码</label>
            <textarea id="url-output" class="small" placeholder="编码结果..."></textarea>
          </div>
        </div>
        <div class="btn-row">
          <button class="btn btn-primary" id="url-enc">编码 →</button>
          <button class="btn btn-success" id="url-dec">← 解码</button>
        </div>
      </div>

      <div class="card">
        <div class="card-title">HTML / Unicode / Hex 编解码</div>
        <div class="form-group">
          <label>原文</label>
          <textarea id="enc-input" class="small" placeholder="输入文本..."></textarea>
        </div>
        <div class="btn-row">
          <button class="btn btn-primary btn-sm" id="html-enc">HTML 编码</button>
          <button class="btn btn-success btn-sm" id="html-dec">HTML 解码</button>
          <button class="btn btn-primary btn-sm" id="unicode-enc">Unicode 编码</button>
          <button class="btn btn-success btn-sm" id="unicode-dec">Unicode 解码</button>
          <button class="btn btn-primary btn-sm" id="hex-enc">Hex 编码</button>
          <button class="btn btn-success btn-sm" id="hex-dec">Hex 解码</button>
        </div>
        <div class="form-group">
          <label>结果</label>
          <div class="result-area">
            <button class="copy-btn" id="enc-result-copy">复制</button>
            <textarea id="enc-result" class="small" readonly placeholder="结果将显示在这里..."></textarea>
          </div>
        </div>
      </div>
    </div>

    <!-- Convert Tab -->
    <div class="tab-content" id="tab-convert">
      <div class="card">
        <div class="card-title">进制转换</div>
        <div class="form-group">
          <label>输入数值 (十进制)</label>
          <input type="text" id="conv-input" placeholder="输入十进制数值..." />
        </div>
        <div class="btn-row">
          <button class="btn btn-primary" id="conv-convert">转换</button>
        </div>
        <div class="convert-grid" id="conv-results"></div>
      </div>

      <div class="card">
        <div class="card-title">ASCII 转换</div>
        <div class="grid-2">
          <div class="form-group">
            <label>文本</label>
            <textarea id="ascii-text" class="small" placeholder="输入文本..."></textarea>
          </div>
          <div class="form-group">
            <label>ASCII 码</label>
            <textarea id="ascii-codes" class="small" placeholder="如: 72 101 108 108 111"></textarea>
          </div>
        </div>
        <div class="btn-row">
          <button class="btn btn-primary" id="ascii-enc">文本 → ASCII</button>
          <button class="btn btn-success" id="ascii-dec">ASCII → 文本</button>
        </div>
      </div>
    </div>

    <div class="footer">
      CryptoKit — 纯浏览器端加密工具箱，所有数据仅在本地处理
    </div>
  `;
}

// ========== Bind Events ==========
function bindEvents() {
  // Tab switching
  $$('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('.tab-btn').forEach(b => b.classList.remove('active'));
      $$('.tab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      const tab = btn.getAttribute('data-tab');
      if (tab) $(`#tab-${tab}`)?.classList.add('active');
    });
  });

  // ---- Hash ----
  $('#hash-calc')?.addEventListener('click', () => {
    const input = getVal('hash-input');
    const algo = getVal('hash-algo');
    if (!input) { showToast('请输入文本', 'error'); return; }
    const fn = hashAlgorithms[algo];
    if (!fn) { showToast('未知算法', 'error'); return; }
    const value = fn(input);
    const container = $('#hash-results')!;
    container.innerHTML = `
      <div class="hash-item">
        <span class="hash-label">${algo}</span>
        <span class="hash-value">${value}</span>
        <button class="hash-copy" data-copy="${value}">复制</button>
      </div>
    `;
    container.querySelector('.hash-copy')?.addEventListener('click', function() {
      copyText((this as HTMLElement).dataset.copy!);
    });
  });

  $('#hash-clear')?.addEventListener('click', () => {
    setVal('hash-input', '');
    ($('#hash-results') as HTMLElement).innerHTML = '';
  });

  $('#hmac-calc')?.addEventListener('click', () => {
    const msg = getVal('hmac-msg');
    const key = getVal('hmac-key');
    if (!msg || !key) { showToast('请输入消息和密钥', 'error'); return; }
    const result = hmacSHA256(msg, key);
    const container = $('#hmac-result')!;
    container.innerHTML = `
      <div class="hash-item">
        <span class="hash-label">HMAC-SHA256</span>
        <span class="hash-value">${result}</span>
        <button class="hash-copy" data-copy="${result}">复制</button>
      </div>
    `;
    container.querySelector('.hash-copy')?.addEventListener('click', () => copyText(result));
  });

  // ---- AES ----
  $('#aes-enc')?.addEventListener('click', () => {
    const plain = getVal('aes-plain');
    const key = getVal('aes-key');
    const mode = getVal('aes-mode') as 'CBC' | 'ECB' | 'CFB' | 'OFB' | 'CTR';
    if (!plain || !key) { showToast('请输入明文和密钥', 'error'); return; }
    try {
      setVal('aes-cipher', aesEncrypt(plain, key, mode));
      showToast('AES加密成功');
    } catch (e: any) { showToast('加密失败: ' + e.message, 'error'); }
  });

  $('#aes-dec')?.addEventListener('click', () => {
    const cipher = getVal('aes-cipher');
    const key = getVal('aes-key');
    const mode = getVal('aes-mode') as 'CBC' | 'ECB' | 'CFB' | 'OFB' | 'CTR';
    if (!cipher || !key) { showToast('请输入密文和密钥', 'error'); return; }
    try {
      setVal('aes-plain', aesDecrypt(cipher, key, mode));
      showToast('AES解密成功');
    } catch (e: any) { showToast('解密失败: ' + e.message, 'error'); }
  });

  // ---- DES ----
  $('#des-enc')?.addEventListener('click', () => {
    const plain = getVal('des-plain');
    const key = getVal('des-key');
    if (!plain || !key) { showToast('请输入明文和密钥', 'error'); return; }
    try {
      setVal('des-cipher', desEncrypt(plain, key));
      showToast('DES加密成功');
    } catch (e: any) { showToast('加密失败: ' + e.message, 'error'); }
  });

  $('#des-dec')?.addEventListener('click', () => {
    const cipher = getVal('des-cipher');
    const key = getVal('des-key');
    if (!cipher || !key) { showToast('请输入密文和密钥', 'error'); return; }
    try {
      setVal('des-plain', desDecrypt(cipher, key));
      showToast('DES解密成功');
    } catch (e: any) { showToast('解密失败: ' + e.message, 'error'); }
  });

  $('#tdes-enc')?.addEventListener('click', () => {
    const plain = getVal('des-plain');
    const key = getVal('des-key');
    if (!plain || !key) { showToast('请输入明文和密钥', 'error'); return; }
    try {
      setVal('des-cipher', tripleDesEncrypt(plain, key));
      showToast('3DES加密成功');
    } catch (e: any) { showToast('加密失败: ' + e.message, 'error'); }
  });

  $('#tdes-dec')?.addEventListener('click', () => {
    const cipher = getVal('des-cipher');
    const key = getVal('des-key');
    if (!cipher || !key) { showToast('请输入密文和密钥', 'error'); return; }
    try {
      setVal('des-plain', tripleDesDecrypt(cipher, key));
      showToast('3DES解密成功');
    } catch (e: any) { showToast('解密失败: ' + e.message, 'error'); }
  });

  // ---- RSA ----
  let rsaPubKeyText = '';
  let rsaPrivKeyText = '';

  $('#rsa-gen')?.addEventListener('click', async () => {
    const keySize = parseInt(getVal('rsa-keysize'));
    const btn = $('#rsa-gen')!;
    const origText = btn.textContent;
    btn.innerHTML = '<span class="spinner"></span> 生成中...';
    (btn as HTMLButtonElement).disabled = true;
    try {
      const pair = await generateRSAKeyPair(keySize);
      rsaPubKeyText = pair.publicKey;
      rsaPrivKeyText = pair.privateKey;
      ($('#rsa-pubkey') as HTMLElement).textContent = pair.publicKey;
      ($('#rsa-privkey') as HTMLElement).textContent = pair.privateKey;
      setVal('rsa-enc-pubkey', pair.publicKey);
      setVal('rsa-enc-privkey', pair.privateKey);
      showToast(`RSA ${keySize}bit 密钥对生成成功`);
    } catch (e: any) {
      showToast('生成失败: ' + (e?.message || String(e)), 'error');
      console.error('RSA keygen error:', e);
    } finally {
      btn.textContent = origText;
      (btn as HTMLButtonElement).disabled = false;
    }
  });

  $('#rsa-pubkey-copy')?.addEventListener('click', () => {
    if (rsaPubKeyText) copyText(rsaPubKeyText);
  });
  $('#rsa-privkey-copy')?.addEventListener('click', () => {
    if (rsaPrivKeyText) copyText(rsaPrivKeyText);
  });

  $('#rsa-enc')?.addEventListener('click', () => {
    const plain = getVal('rsa-plain');
    const pubkey = getVal('rsa-enc-pubkey');
    const padding = getVal('rsa-padding') as RSAPadding;
    if (!plain || !pubkey) { showToast('请输入明文和公钥', 'error'); return; }
    try {
      const cipher = rsaEncrypt(plain, pubkey, padding);
      setVal('rsa-cipher', cipher);
      showToast('RSA加密成功');
    } catch (e: any) { showToast('加密失败: ' + e.message, 'error'); }
  });

  $('#rsa-dec')?.addEventListener('click', () => {
    const cipher = getVal('rsa-cipher');
    const privkey = getVal('rsa-enc-privkey');
    const padding = getVal('rsa-padding') as RSAPadding;
    if (!cipher || !privkey) { showToast('请输入密文和私钥', 'error'); return; }
    try {
      const plain = rsaDecrypt(cipher, privkey, padding);
      setVal('rsa-plain', plain);
      showToast('RSA解密成功');
    } catch (e: any) { showToast('解密失败: ' + e.message, 'error'); }
  });

  // ---- Base64 ----
  $('#b64-enc')?.addEventListener('click', () => {
    const input = getVal('b64-input');
    if (!input) { showToast('请输入文本', 'error'); return; }
    try { setVal('b64-output', base64Encode(input)); showToast('Base64编码成功'); }
    catch (e: any) { showToast('编码失败', 'error'); }
  });

  $('#b64-dec')?.addEventListener('click', () => {
    const input = getVal('b64-output');
    if (!input) { showToast('请输入Base64', 'error'); return; }
    try { setVal('b64-input', base64Decode(input)); showToast('Base64解码成功'); }
    catch (e: any) { showToast('解码失败，请检查输入', 'error'); }
  });

  // ---- URL ----
  $('#url-enc')?.addEventListener('click', () => {
    const input = getVal('url-input');
    if (!input) return;
    setVal('url-output', urlEncode(input));
    showToast('URL编码成功');
  });

  $('#url-dec')?.addEventListener('click', () => {
    const input = getVal('url-output');
    if (!input) return;
    try { setVal('url-input', urlDecode(input)); showToast('URL解码成功'); }
    catch (e: any) { showToast('解码失败', 'error'); }
  });

  // ---- HTML/Unicode/Hex ----
  $('#html-enc')?.addEventListener('click', () => {
    const input = getVal('enc-input');
    if (!input) return;
    setVal('enc-result', htmlEncode(input));
  });
  $('#html-dec')?.addEventListener('click', () => {
    const input = getVal('enc-input');
    if (!input) return;
    setVal('enc-result', htmlDecode(input));
  });
  $('#unicode-enc')?.addEventListener('click', () => {
    const input = getVal('enc-input');
    if (!input) return;
    setVal('enc-result', unicodeEncode(input));
  });
  $('#unicode-dec')?.addEventListener('click', () => {
    const input = getVal('enc-input');
    if (!input) return;
    try { setVal('enc-result', unicodeDecode(input)); }
    catch (e: any) { showToast('解码失败', 'error'); }
  });
  $('#hex-enc')?.addEventListener('click', () => {
    const input = getVal('enc-input');
    if (!input) return;
    setVal('enc-result', hexEncode(input));
  });
  $('#hex-dec')?.addEventListener('click', () => {
    const input = getVal('enc-input');
    if (!input) return;
    try { setVal('enc-result', hexDecode(input)); }
    catch (e: any) { showToast('解码失败', 'error'); }
  });

  $('#enc-result-copy')?.addEventListener('click', () => {
    const text = getVal('enc-result');
    if (text) copyText(text);
  });

  // ---- Base Conversion ----
  const baseIds: Record<string, string> = { '2': 'BIN', '8': 'OCT', '10': 'DEC', '16': 'HEX', '32': 'B32', '36': 'B36', '62': 'B62' };

  $('#conv-convert')?.addEventListener('click', () => {
    const input = getVal('conv-input').trim();
    if (!input) { showToast('请输入数值', 'error'); return; }

    if (!/^[0-9]+$/.test(input)) {
      showToast('请输入有效的十进制数', 'error');
      return;
    }

    const container = $('#conv-results')!;
    const names = getBaseNames();
    const baseDescriptions: Record<number, string> = {
      2: '0-1',
      8: '0-7',
      10: '0-9',
      16: '0-9, A-F',
      32: '0-9, A-V',
      36: '0-9, A-Z',
      62: '0-9, A-Z, a-z',
    };
    const html = Object.entries(names).map(([base, name]) => {
      const b = parseInt(base) as 2 | 8 | 10 | 16 | 32 | 36 | 62;
      const val = convertBase(input, 10, b);
      const desc = baseDescriptions[b] || '';
      return `
        <div class="convert-item">
          <label>${name} <span style="font-weight:400;color:var(--text-muted);font-size:0.75rem;">字符集: ${desc}</span></label>
          <input type="text" value="${val}" readonly id="conv-${baseIds[base]}" />
        </div>
      `;
    }).join('');
    container.innerHTML = html;
    container.querySelectorAll('input').forEach(inp => {
      (inp as HTMLElement).style.cursor = 'pointer';
      inp.addEventListener('click', () => copyText((inp as HTMLInputElement).value));
    });
  });

  // ---- ASCII ----
  $('#ascii-enc')?.addEventListener('click', () => {
    const text = getVal('ascii-text');
    if (!text) return;
    setVal('ascii-codes', textToAscii(text));
  });

  $('#ascii-dec')?.addEventListener('click', () => {
    const codes = getVal('ascii-codes');
    if (!codes) return;
    try { setVal('ascii-text', asciiToText(codes)); }
    catch (e: any) { showToast('转换失败', 'error'); }
  });
}

// ========== Init ==========
renderApp();
bindEvents();
