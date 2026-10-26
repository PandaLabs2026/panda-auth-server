(() => {
  const root = document.getElementById('mfa');
  if (!root) return;

  const token = root.querySelector('input[name="__RequestVerificationToken"]').value;
  const message = document.getElementById('mfa-message');
  const show = text => { message.hidden = false; message.textContent = text; };
  const post = async (url, body) => {
    const response = await fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', RequestVerificationToken: token },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) throw new Error((await response.json().catch(() => ({}))).error || '操作未完成，请重试。');
    return response.json();
  };

  let totpFactorId;
  document.getElementById('begin-totp')?.addEventListener('click', async () => {
    try {
      const enrollment = await post(root.dataset.totpOptionsUrl);
      totpFactorId = enrollment.factorId;
      document.getElementById('totp-secret').textContent = enrollment.secret;
      document.getElementById('totp-setup').hidden = false;
    } catch (error) { show(error.message); }
  });
  document.getElementById('confirm-totp')?.addEventListener('click', async () => {
    try {
      await post(root.dataset.totpConfirmUrl, { factorId: totpFactorId, code: document.getElementById('totp-code').value });
      location.assign(root.dataset.returnUrl);
    } catch (error) { show(error.message); }
  });
  document.getElementById('assert-totp')?.addEventListener('click', async () => {
    try {
      await post(root.dataset.totpAssertUrl, { code: document.getElementById('totp-assert-code').value });
      location.assign(root.dataset.returnUrl);
    } catch (error) { show(error.message); }
  });
})();
