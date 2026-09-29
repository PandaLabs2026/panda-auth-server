(() => {
  const root = document.getElementById('login-mfa-challenge');
  if (!root || !window.PublicKeyCredential) return;

  const form = root.querySelector('form');
  const tokenInput = form && form.querySelector('input[name="__RequestVerificationToken"]');
  const message = document.getElementById('login-mfa-message');
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0));
  const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const show = text => { message.hidden = false; message.textContent = text; };

  const post = async (url, body) => {
    const response = await fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', RequestVerificationToken: tokenInput ? tokenInput.value : '' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) throw new Error((await response.json().catch(() => ({}))).error || '操作未完成，请重试。');
    return response.json();
  };

  const assertionOptions = options => ({
    ...options,
    challenge: decode(options.challenge),
    allowCredentials: (options.allowCredentials || []).map(item => ({ ...item, id: decode(item.id) })),
  });
  const responseJson = credential => ({
    id: credential.id, rawId: encode(credential.rawId), type: credential.type,
    response: {
      clientDataJson: encode(credential.response.clientDataJSON),
      authenticatorData: encode(credential.response.authenticatorData),
      signature: encode(credential.response.signature),
      userHandle: credential.response.userHandle ? encode(credential.response.userHandle) : undefined,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  });

  document.getElementById('challenge-passkey')?.addEventListener('click', async () => {
    try {
      const ceremony = await post(root.dataset.assertionOptionsUrl);
      const credential = await navigator.credentials.get({ publicKey: assertionOptions(ceremony.publicKey) });
      if (!credential) throw new Error('未能验证 Passkey。');
      await post(root.dataset.assertionUrl, { ceremonyId: ceremony.ceremonyId, response: responseJson(credential) });
      location.assign(root.dataset.returnUrl);
    } catch (error) { show(error.message); }
  });
})();
