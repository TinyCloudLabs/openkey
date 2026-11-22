// TC-3800: the web half of the API's `OPENKEY_NETWORK_DECRYPT_CAP`. Set both to `enabled` together: the API holds a
// whole network's `decrypt` to 7 days outside a signed approval request, and with this the popup, frame and
// command-line screens stop their expiry choices there too. The server's flag is the one that counts; this one only
// keeps the screen from offering a time the server would bring back to 7 days.
export const NETWORK_DECRYPT_CAP = import.meta.env.VITE_OPENKEY_NETWORK_DECRYPT_CAP === 'enabled';
