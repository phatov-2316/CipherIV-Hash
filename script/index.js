let CIPHER_KEY_HEX = "1c9d8104a784a227b4a4ec4f4e6d1d6e19d6e8f6ebbe9d69e7b9eb7196aa8b6c";
let CIPHER_IV_HEX = "65a951eae0a9e8df0d3e42a50c3706b7";

let appKey = hexToBytes(CIPHER_KEY_HEX);
let appIv = hexToBytes(CIPHER_IV_HEX);

$('#cipher-key-input').on('change', function () {
    CIPHER_KEY_HEX = $(this).val();

    if (!CIPHER_KEY_HEX) {
        CIPHER_KEY_HEX = "1c9d8104a784a227b4a4ec4f4e6d1d6e19d6e8f6ebbe9d69e7b9eb7196aa8b6c"
    }

    appKey = hexToBytes(CIPHER_KEY_HEX);
})

$('#cipher-iv-input').on('change', function () {
    CIPHER_IV_HEX = $(this).val();

    if (!CIPHER_IV_HEX) {
        CIPHER_IV_HEX = "65a951eae0a9e8df0d3e42a50c3706b7"
    }

    appIv = hexToBytes(CIPHER_IV_HEX);
})

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

    $('#gen-cipher-key-btn').click(async () => {
        const plaintext = await genCipherKey()

        $('#result-secret-key').val(plaintext)
    })

    $('#gen-cipher-iv-btn').click(async () => {
        const plaintext = await genCipherIV()

        $('#result-secret-key').val(plaintext)
    })
}

function hexToBytes(hexString) {
    const bytes = [];

    for (let i = 0; i < hexString.length; i += 2) {
        bytes.push(parseInt(hexString.substr(i, 2), 16));
    }

    return new Uint8Array(bytes);
}

function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
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
    try {
        const ciphertextBytes = new Uint8Array(encryptedText.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const key = await crypto.subtle.importKey("raw", appKey, {name: "AES-CBC"}, false, ["decrypt"]);
        const plaintext = await crypto.subtle.decrypt({name: "AES-CBC", iv: appIv}, key, ciphertextBytes);

        return new TextDecoder().decode(plaintext);
    } catch (e) {
        alert(`Error decrypt`);
    }
}

function hash(plaintext) {
    return sha3_512(plaintext);
}

async function genCipherKey() {
    const cipherKey = await window.crypto.getRandomValues(new Uint8Array(32));

    return bufferToHex(cipherKey)
}

async function genCipherIV() {
    const cipherIV = await window.crypto.getRandomValues(new Uint8Array(16));

    return bufferToHex(cipherIV);
}

