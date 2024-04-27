const CIPHER_KEY_HEX = "1c9d8104a784a227b4a4ec4f4e6d1d6e19d6e8f6ebbe9d69e7b9eb7196aa8b6c";
const CIPHER_IV_HEX = "65a951eae0a9e8df0d3e42a50c3706b7";

const appKey = hexToBytes(CIPHER_KEY_HEX);
const appIv = hexToBytes(CIPHER_IV_HEX);

$(document).ready(() => {
    handle()
})

function handle() {
    const plaintextSelector = $('#plaintext')

    $('#encrypt-btn').click(async () => {
        const encryptedText = await encrypt(plaintextSelector.val())

        $('#result').val(encryptedText)
    })

    $('#decrypt-btn').click(async () => {
        const decryptedText = await decrypt(plaintextSelector.val())

        $('#result').val(decryptedText)
    })

    $('#hash-btn').click(async () => {
        const plaintext = await hash(plaintextSelector.val())

        $('#result').val(plaintext)
    })
}

function hexToBytes(hexString) {
    const bytes = [];

    for (let i = 0; i < hexString.length; i += 2) {
        bytes.push(parseInt(hexString.substr(i, 2), 16));
    }

    return new Uint8Array(bytes);
}

async function encrypt(plaintext) {
    const key = await crypto.subtle.importKey("raw", appKey, {name: "AES-CBC"}, false, ["encrypt"]);
    const ciphertext = await crypto.subtle.encrypt({
        name: "AES-CBC",
        iv: appIv
    }, key, new TextEncoder().encode(plaintext));
    const ciphertextBytes = new Uint8Array(ciphertext);

    return Array.from(ciphertextBytes).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

async function decrypt(encryptedText) {
    const ciphertextBytes = new Uint8Array(encryptedText.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const key = await crypto.subtle.importKey("raw", appKey, {name: "AES-CBC"}, false, ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt({name: "AES-CBC", iv: appIv}, key, ciphertextBytes);

    return new TextDecoder().decode(plaintext);
}

function hash(plaintext) {
    return sha3_512(plaintext);
}
