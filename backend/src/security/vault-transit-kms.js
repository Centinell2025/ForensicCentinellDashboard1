class VaultTransitKms {
  constructor({ address, token, mount = 'transit', keyName }) {
    if (!address || !token || !keyName) throw new Error('Vault address, token, and key name are required');
    this.address = address.replace(/\/$/, ''); this.token = token; this.mount = mount; this.keyName = keyName;
  }
  async request(operation, body) {
    const response = await fetch(`${this.address}/v1/${this.mount}/${operation}/${this.keyName}`, {
      method:'POST', headers:{ 'content-type':'application/json', 'x-vault-token':this.token }, body:JSON.stringify(body), signal:AbortSignal.timeout(8000)
    });
    if (!response.ok) throw new Error(`Vault Transit ${operation} failed with ${response.status}`);
    return (await response.json()).data;
  }
  async encryptDataKey(dataKey, context = {}) {
    const data = await this.request('encrypt', { plaintext:dataKey.toString('base64'), context:Buffer.from(JSON.stringify(context)).toString('base64') });
    return { keyId:`vault://${this.mount}/${this.keyName}`, ciphertext:Buffer.from(data.ciphertext) };
  }
  async decryptDataKey(wrapped, _keyId, context = {}) {
    const data = await this.request('decrypt', { ciphertext:wrapped.toString(), context:Buffer.from(JSON.stringify(context)).toString('base64') });
    return Buffer.from(data.plaintext,'base64');
  }
}
module.exports = { VaultTransitKms };
