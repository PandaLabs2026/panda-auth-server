(() => {
  const root = document.getElementById('mfa');
  if (!root || !window.PublicKeyCredential) return;

  const token = root.querySelector('input[name="__RequestVerificationToken"]').value;
  const message = document.getElementById('mfa-message');
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0));
  const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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
  const creationOptions = options => ({
    ...options,
    challenge: decode(options.challenge),
    user: { ...options.user, id: decode(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map(item => ({ ...item, id: decode(item.id) })),
  });
  const assertionOptions = options => ({
    ...options,
    challenge: decode(options.challenge),
    allowCredentials: (options.allowCredentials || []).map(item => ({ ...item, id: decode(item.id) })),
  });
  const responseJson = credential => ({
    id: credential.id, rawId: encode(credential.rawId), type: credential.type,
    response: (() => {
      const response = credential.response;
      const encoded = { clientDataJSON: encode(response.clientDataJSON) };
      if (response.attestationObject) encoded.attestationObject = encode(response.attestationObject);
      if (response.authenticatorData) encoded.authenticatorData = encode(response.authenticatorData);
      if (response.signature) encoded.signature = encode(response.signature);
      if (response.userHandle) encoded.userHandle = encode(response.userHandle);
      return encoded;
    })(),
    clientExtensionResults: credential.getClientExtensionResults(),
  });

  document.getElementById('enroll-passkey')?.addEventListener('click', async () => {
    try {
      const ceremony = await post(root.dataset.optionsUrl);
      const credential = await navigator.credentials.create({ publicKey: creationOptions(ceremony.publicKey) });
      if (!credential) throw new Error('未能创建 Passkey。');
      await post(root.dataset.enrollUrl, { ceremonyId: ceremony.ceremonyId, response: responseJson(credential) });
      location.reload();
    } catch (error) { show(error.message); }
  });
  document.getElementById('assert-passkey')?.addEventListener('click', async () => {
    try {
      const ceremony = await post(root.dataset.assertionOptionsUrl);
      const credential = await navigator.credentials.get({ publicKey: assertionOptions(ceremony.publicKey) });
      if (!credential) throw new Error('未能验证 Passkey。');
      await post(root.dataset.assertionUrl, { ceremonyId: ceremony.ceremonyId, response: responseJson(credential) });
      location.assign(root.dataset.returnUrl);
    } catch (error) { show(error.message); }
  });
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
      show('TOTP 备用验证已确认。');
    } catch (error) { show(error.message); }
  });
  document.getElementById('assert-totp')?.addEventListener('click', async () => {
    try {
      await post(root.dataset.totpAssertUrl, { code: document.getElementById('totp-assert-code').value });
      location.assign(root.dataset.returnUrl);
    } catch (error) { show(error.message); }
  });
})();
